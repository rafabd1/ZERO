package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type StaleResult struct {
	Subdomains   int
	HTTPServices int
	Technologies int
}

type CleanupOptions struct {
	DeleteInactiveInventory   bool
	DeleteDNSOnlySubdomains   bool
	DNSOnlyRetentionHours     int
	InactiveRetentionHours    int
	InactiveRetentionScans    int
	ChangeEventRetentionHours int
	ScanRequestRetentionHours int
	ScanRunRetentionHours     int
	BatchSize                 int
}

type cleanupDB interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (r *Repository) MarkStaleEntities(ctx context.Context, programID string, staleAfterHours int) (StaleResult, error) {
	if programID == "" || staleAfterHours <= 0 {
		return StaleResult{}, nil
	}
	var result StaleResult
	if err := r.pool.QueryRow(ctx, `
		WITH stale AS (
			UPDATE zero_subdomains
			SET active = false,
				metadata = metadata || jsonb_build_object('stale_marked_at', now(), 'stale_after_hours', $2)
			WHERE program_id = $1::uuid
			  AND active = true
			  AND last_seen_at < now() - make_interval(hours => $2)
			RETURNING id, program_id, fqdn, last_seen_at
		)
		SELECT count(*) FROM stale
	`, programID, staleAfterHours).Scan(&result.Subdomains); err != nil {
		return result, fmt.Errorf("mark stale subdomains: %w", err)
	}
	if err := r.pool.QueryRow(ctx, `
		WITH stale AS (
			UPDATE zero_http_services
			SET active = false,
				raw = raw || jsonb_build_object('stale_marked_at', now(), 'stale_after_hours', $2)
			WHERE program_id = $1::uuid
			  AND active = true
			  AND last_seen_at < now() - make_interval(hours => $2)
			RETURNING id, program_id, url, last_seen_at
		)
		SELECT count(*) FROM stale
	`, programID, staleAfterHours).Scan(&result.HTTPServices); err != nil {
		return result, fmt.Errorf("mark stale http services: %w", err)
	}
	if err := r.pool.QueryRow(ctx, `
		WITH stale AS (
			UPDATE zero_technology_observations
			SET active = false,
				evidence = evidence || jsonb_build_object('stale_marked_at', now(), 'stale_after_hours', $2)
			WHERE program_id = $1::uuid
			  AND active = true
			  AND last_seen_at < now() - make_interval(hours => $2)
			RETURNING id, program_id, name, version, source, last_seen_at
		)
		SELECT count(*) FROM stale
	`, programID, staleAfterHours).Scan(&result.Technologies); err != nil {
		return result, fmt.Errorf("mark stale technologies: %w", err)
	}
	return result, nil
}

func (r *Repository) CleanupInactiveEntities(ctx context.Context, retentionHours, retentionScans int) (CleanupResult, error) {
	return r.CleanupOperationalData(ctx, CleanupOptions{
		DeleteInactiveInventory: true,
		InactiveRetentionHours:  retentionHours,
		InactiveRetentionScans:  retentionScans,
	})
}

func (r *Repository) CleanupOperationalData(ctx context.Context, opts CleanupOptions) (CleanupResult, error) {
	var result CleanupResult
	conn, err := r.pool.Acquire(ctx)
	if err != nil {
		return result, fmt.Errorf("acquire cleanup connection: %w", err)
	}
	defer conn.Release()
	locked, err := tryCleanupLock(ctx, conn)
	if err != nil {
		return result, err
	}
	if !locked {
		return result, nil
	}
	defer unlockCleanup(ctx, conn)
	batchSize := cleanupBatchSize(opts.BatchSize)
	if err := r.pruneDisallowedChangeEvents(ctx, conn, batchSize, &result); err != nil {
		return result, err
	}
	if opts.ChangeEventRetentionHours > 0 {
		if err := r.pruneOldChangeEvents(ctx, conn, opts.ChangeEventRetentionHours, batchSize, &result); err != nil {
			return result, err
		}
	}
	if opts.ScanRequestRetentionHours > 0 {
		if err := r.pruneOldScanRequests(ctx, conn, opts.ScanRequestRetentionHours, batchSize, &result); err != nil {
			return result, err
		}
	}
	if opts.ScanRunRetentionHours > 0 {
		if err := r.pruneOldScanRuns(ctx, conn, opts.ScanRunRetentionHours, batchSize, &result); err != nil {
			return result, err
		}
	}
	if opts.DeleteDNSOnlySubdomains {
		if err := r.pruneDNSOnlySubdomains(ctx, conn, opts.DNSOnlyRetentionHours, batchSize, &result); err != nil {
			return result, err
		}
	}
	if !opts.DeleteInactiveInventory {
		return result, nil
	}
	retentionHours := opts.InactiveRetentionHours
	retentionScans := opts.InactiveRetentionScans
	deleted, err := runBatchedCount(ctx, conn, "cleanup inactive technology vulnerability matches", batchSize, `
		WITH retained_runs AS (
			SELECT id
			FROM (
				SELECT id, program_id,
					row_number() OVER (PARTITION BY program_id ORDER BY COALESCE(finished_at, started_at) DESC, started_at DESC) AS rn
				FROM zero_scan_runs
				WHERE status = 'succeeded'
				  AND run_type = 'full'
				  AND program_id IS NOT NULL
			) ranked
			WHERE $2 > 0 AND rn <= $2
		), candidates AS (
			SELECT m.id
			FROM zero_technology_vulnerability_matches m
			JOIN zero_http_services s ON m.http_service_id = s.id
			WHERE s.active = false
			  AND (
				($3::boolean)
				OR ($1 > 0 AND s.last_seen_at < now() - make_interval(hours => $1))
				OR ($2 > 0 AND s.last_scan_run_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM retained_runs rr WHERE rr.id = s.last_scan_run_id))
			  )
			LIMIT $4
		), stale_matches AS (
			DELETE FROM zero_technology_vulnerability_matches m
			WHERE m.id IN (SELECT id FROM candidates)
			RETURNING m.id
		)
		SELECT count(*) FROM stale_matches
	`, retentionHours, retentionScans, immediateRetention(retentionHours, retentionScans))
	if err != nil {
		return result, err
	}
	result.TechnologyVulnerabilityRows += deleted
	deleted, err = runBatchedCount(ctx, conn, "cleanup inactive technology observations", batchSize, `
		WITH retained_runs AS (
			SELECT id
			FROM (
				SELECT id, program_id,
					row_number() OVER (PARTITION BY program_id ORDER BY COALESCE(finished_at, started_at) DESC, started_at DESC) AS rn
				FROM zero_scan_runs
				WHERE status = 'succeeded'
				  AND run_type = 'full'
				  AND program_id IS NOT NULL
			) ranked
			WHERE $2 > 0 AND rn <= $2
		), candidates AS (
			SELECT t.id
			FROM zero_technology_observations t
			WHERE t.active = false
			  AND (
				($3::boolean)
				OR ($1 > 0 AND t.last_seen_at < now() - make_interval(hours => $1))
				OR ($2 > 0 AND t.last_scan_run_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM retained_runs rr WHERE rr.id = t.last_scan_run_id))
			  )
			LIMIT $4
		), stale_tech AS (
			DELETE FROM zero_technology_observations t
			WHERE t.id IN (SELECT id FROM candidates)
			RETURNING t.id
		)
		SELECT count(*) FROM stale_tech
	`, retentionHours, retentionScans, immediateRetention(retentionHours, retentionScans))
	if err != nil {
		return result, err
	}
	result.TechnologyObservations += deleted
	deleted, err = runBatchedCount(ctx, conn, "cleanup inactive http services", batchSize, `
		WITH retained_runs AS (
			SELECT id
			FROM (
				SELECT id, program_id,
					row_number() OVER (PARTITION BY program_id ORDER BY COALESCE(finished_at, started_at) DESC, started_at DESC) AS rn
				FROM zero_scan_runs
				WHERE status = 'succeeded'
				  AND run_type = 'full'
				  AND program_id IS NOT NULL
			) ranked
			WHERE $2 > 0 AND rn <= $2
		), candidates AS (
			SELECT s.id
			FROM zero_http_services s
			WHERE s.active = false
			  AND NOT EXISTS (SELECT 1 FROM zero_nuclei_results n WHERE n.http_service_id = s.id)
			  AND NOT EXISTS (SELECT 1 FROM zero_candidate_findings f WHERE f.http_service_id = s.id)
			  AND (
				($3::boolean)
				OR ($1 > 0 AND s.last_seen_at < now() - make_interval(hours => $1))
				OR ($2 > 0 AND s.last_scan_run_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM retained_runs rr WHERE rr.id = s.last_scan_run_id))
			  )
			LIMIT $4
		), stale_services AS (
			DELETE FROM zero_http_services s
			WHERE s.id IN (SELECT id FROM candidates)
			RETURNING s.id
		)
		SELECT count(*) FROM stale_services
	`, retentionHours, retentionScans, immediateRetention(retentionHours, retentionScans))
	if err != nil {
		return result, err
	}
	result.HTTPServices += deleted
	deleted, err = runBatchedCount(ctx, conn, "cleanup inactive subdomains", batchSize, `
		WITH retained_runs AS (
			SELECT id
			FROM (
				SELECT id, program_id,
					row_number() OVER (PARTITION BY program_id ORDER BY COALESCE(finished_at, started_at) DESC, started_at DESC) AS rn
				FROM zero_scan_runs
				WHERE status = 'succeeded'
				  AND run_type = 'full'
				  AND program_id IS NOT NULL
			) ranked
			WHERE $2 > 0 AND rn <= $2
		), candidates AS (
			SELECT s.id
			FROM zero_subdomains s
			WHERE s.active = false
			  AND (
				($3::boolean)
				OR ($1 > 0 AND s.last_seen_at < now() - make_interval(hours => $1))
				OR ($2 > 0 AND s.last_scan_run_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM retained_runs rr WHERE rr.id = s.last_scan_run_id))
			  )
			LIMIT $4
		), stale_subdomains AS (
			DELETE FROM zero_subdomains s
			WHERE s.id IN (SELECT id FROM candidates)
			RETURNING s.id
		)
		SELECT count(*) FROM stale_subdomains
	`, retentionHours, retentionScans, immediateRetention(retentionHours, retentionScans))
	if err != nil {
		return result, err
	}
	result.Subdomains += deleted
	deleted, err = runBatchedCount(ctx, conn, "cleanup inactive scope assets", batchSize, `
		WITH retained_runs AS (
			SELECT id
			FROM (
				SELECT id, program_id,
					row_number() OVER (PARTITION BY program_id ORDER BY COALESCE(finished_at, started_at) DESC, started_at DESC) AS rn
				FROM zero_scan_runs
				WHERE status = 'succeeded'
				  AND run_type = 'full'
				  AND program_id IS NOT NULL
			) ranked
			WHERE $2 > 0 AND rn <= $2
		), candidates AS (
			SELECT a.id
			FROM zero_scope_assets a
			WHERE a.active = false
			  AND (
				($3::boolean)
				OR ($1 > 0 AND a.last_seen_at < now() - make_interval(hours => $1))
				OR ($2 > 0 AND a.last_scan_run_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM retained_runs rr WHERE rr.id = a.last_scan_run_id))
			  )
			LIMIT $4
		), stale_assets AS (
			DELETE FROM zero_scope_assets a
			WHERE a.id IN (SELECT id FROM candidates)
			RETURNING a.id
		)
		SELECT count(*) FROM stale_assets
	`, retentionHours, retentionScans, immediateRetention(retentionHours, retentionScans))
	if err != nil {
		return result, err
	}
	result.ScopeAssets += deleted
	return result, nil
}

func (r *Repository) pruneDisallowedChangeEvents(ctx context.Context, q cleanupDB, batchSize int, result *CleanupResult) error {
	deleted, err := runBatchedCount(ctx, q, "cleanup disallowed change events", batchSize, `
		WITH candidates AS (
			SELECT id
			FROM zero_change_events
			WHERE entity_type <> ALL($1::text[])
			LIMIT $2
		), deleted AS (
			DELETE FROM zero_change_events
			WHERE id IN (SELECT id FROM candidates)
			RETURNING id
		)
		SELECT count(*) FROM deleted
	`, r.allowedChangeEventEntities())
	if err != nil {
		return err
	}
	result.ChangeEvents += deleted
	return nil
}

func (r *Repository) pruneDNSOnlySubdomains(ctx context.Context, q cleanupDB, retentionHours, batchSize int, result *CleanupResult) error {
	deleted, err := runBatchedCount(ctx, q, "cleanup dns-only subdomains", batchSize, `
		WITH candidates AS (
			SELECT s.id
			FROM zero_subdomains s
			WHERE s.active = true
			  AND ($1 <= 0 OR s.last_seen_at < now() - make_interval(hours => $1))
			  AND NOT EXISTS (
				SELECT 1
				FROM zero_http_services h
				WHERE h.subdomain_id = s.id
				  AND h.active = true
			  )
			  AND NOT EXISTS (
				SELECT 1
				FROM zero_nuclei_results n
				WHERE n.target_source = 'subdomains'
				  AND n.target_id = s.id
			  )
			ORDER BY s.last_seen_at ASC
			LIMIT $2
		), deleted AS (
			DELETE FROM zero_subdomains s
			WHERE s.id IN (SELECT id FROM candidates)
			RETURNING s.id
		)
		SELECT count(*) FROM deleted
	`, retentionHours)
	if err != nil {
		return err
	}
	result.DNSOnlySubdomains += deleted
	result.Subdomains += deleted
	return nil
}

func (r *Repository) pruneOldChangeEvents(ctx context.Context, q cleanupDB, retentionHours, batchSize int, result *CleanupResult) error {
	deleted, err := runBatchedCount(ctx, q, "cleanup old change events", batchSize, `
		WITH candidates AS (
			SELECT id
			FROM zero_change_events
			WHERE occurred_at < now() - make_interval(hours => $1)
			  AND entity_type <> ALL($2::text[])
			LIMIT $3
		), deleted AS (
			DELETE FROM zero_change_events
			WHERE id IN (SELECT id FROM candidates)
			RETURNING id
		)
		SELECT count(*) FROM deleted
	`, retentionHours, []string{"candidate_finding", "nuclei_result"})
	if err != nil {
		return err
	}
	result.ChangeEvents += deleted
	return nil
}

func (r *Repository) pruneOldScanRequests(ctx context.Context, q cleanupDB, retentionHours, batchSize int, result *CleanupResult) error {
	deleted, err := runBatchedCount(ctx, q, "cleanup old scan requests", batchSize, `
		WITH candidates AS (
			SELECT id
			FROM zero_scan_requests
			WHERE status IN ('succeeded', 'failed', 'canceled')
			  AND COALESCE(finished_at, updated_at, created_at) < now() - make_interval(hours => $1)
			LIMIT $2
		), deleted AS (
			DELETE FROM zero_scan_requests
			WHERE id IN (SELECT id FROM candidates)
			RETURNING id
		)
		SELECT count(*) FROM deleted
	`, retentionHours)
	if err != nil {
		return err
	}
	result.ScanRequests += deleted
	return nil
}

func (r *Repository) pruneOldScanRuns(ctx context.Context, q cleanupDB, retentionHours, batchSize int, result *CleanupResult) error {
	for _, runType := range []string{"scope", "enum", "probe", "intel", "nuclei"} {
		deleted, err := runBatchedCount(ctx, q, "cleanup old "+runType+" scan runs", batchSize, `
			WITH candidates AS (
				SELECT id
				FROM zero_scan_runs
				WHERE status IN ('succeeded','failed','canceled','incomplete')
				  AND run_type = $2
				  AND started_at < now() - make_interval(hours => $1)
				ORDER BY started_at ASC
				LIMIT $3
			), deleted AS (
				DELETE FROM zero_scan_runs
				WHERE id IN (SELECT id FROM candidates)
				RETURNING id
			)
			SELECT count(*) FROM deleted
		`, retentionHours, runType)
		if err != nil {
			return err
		}
		result.ScanRuns += deleted
	}
	deleted, err := runBatchedCount(ctx, q, "cleanup old full scan runs", batchSize, `
		WITH candidates AS (
			SELECT sr.id
			FROM zero_scan_runs sr
			WHERE sr.status IN ('succeeded','failed','canceled','incomplete')
			  AND sr.run_type = 'full'
			  AND sr.program_id IS NOT NULL
			  AND sr.started_at < now() - make_interval(hours => $1)
			  AND EXISTS (
				SELECT 1
				FROM zero_scan_runs newer
				WHERE newer.program_id = sr.program_id
				  AND newer.run_type = 'full'
				  AND newer.status IN ('succeeded','failed','canceled','incomplete')
				  AND (
					newer.started_at > sr.started_at
					OR (
						newer.started_at = sr.started_at
						AND newer.id > sr.id
					)
				  )
			  )
			ORDER BY sr.started_at ASC
			LIMIT $2
		), deleted AS (
			DELETE FROM zero_scan_runs
			WHERE id IN (SELECT id FROM candidates)
			RETURNING id
		)
		SELECT count(*) FROM deleted
	`, retentionHours)
	if err != nil {
		return err
	}
	result.ScanRuns += deleted
	return nil
}

func tryCleanupLock(ctx context.Context, q cleanupDB) (bool, error) {
	var locked bool
	if err := q.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended('zero_cleanup_operational_data', 0))`).Scan(&locked); err != nil {
		return false, fmt.Errorf("acquire cleanup lock: %w", err)
	}
	return locked, nil
}

func unlockCleanup(ctx context.Context, q cleanupDB) {
	_, _ = q.Exec(ctx, `SELECT pg_advisory_unlock(hashtextextended('zero_cleanup_operational_data', 0))`)
}

func runBatchedCount(ctx context.Context, q cleanupDB, label string, batchSize int, query string, args ...any) (int, error) {
	batchSize = cleanupBatchSize(batchSize)
	total := 0
	for {
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		default:
		}
		callArgs := append([]any{}, args...)
		callArgs = append(callArgs, batchSize)
		var count int
		if err := q.QueryRow(ctx, query, callArgs...).Scan(&count); err != nil {
			return total, fmt.Errorf("%s: %w", label, err)
		}
		total += count
		if count < batchSize {
			return total, nil
		}
	}
}

func cleanupBatchSize(value int) int {
	if value <= 0 {
		return 5000
	}
	if value < 100 {
		return 100
	}
	if value > 50000 {
		return 50000
	}
	return value
}

func immediateRetention(retentionHours, retentionScans int) bool {
	return retentionHours <= 0 && retentionScans <= 0
}

func (r *Repository) CompactChangeEvents(ctx context.Context) (int, error) {
	allowed := r.allowedChangeEventEntities()
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin compact change events: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('zero_compact_change_events', 0))`); err != nil {
		return 0, fmt.Errorf("acquire change event compact lock: %w", err)
	}
	var before int
	if err := tx.QueryRow(ctx, `SELECT count(*)::int FROM zero_change_events`).Scan(&before); err != nil {
		return 0, fmt.Errorf("count change events before compact: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		CREATE TEMP TABLE zero_change_events_keep
		ON COMMIT DROP
		AS SELECT *
		FROM zero_change_events
		WHERE entity_type = ANY($1::text[])
	`, allowed); err != nil {
		return 0, fmt.Errorf("copy kept change events: %w", err)
	}
	var kept int
	if err := tx.QueryRow(ctx, `SELECT count(*)::int FROM zero_change_events_keep`).Scan(&kept); err != nil {
		return 0, fmt.Errorf("count kept change events: %w", err)
	}
	if _, err := tx.Exec(ctx, `TRUNCATE zero_change_events`); err != nil {
		return 0, fmt.Errorf("truncate change events: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO zero_change_events SELECT * FROM zero_change_events_keep ON CONFLICT(evidence_hash) DO NOTHING`); err != nil {
		return 0, fmt.Errorf("restore kept change events: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit compact change events: %w", err)
	}
	return before - kept, nil
}

func (r *Repository) CompactOperationalStorage(ctx context.Context) error {
	for _, table := range []string{
		"zero_subdomains",
		"zero_http_services",
		"zero_technology_observations",
		"zero_scan_runs",
		"zero_scan_requests",
		"zero_scope_assets",
		"zero_change_events",
	} {
		if _, err := r.pool.Exec(ctx, fmt.Sprintf("VACUUM (FULL, ANALYZE) %s", table)); err != nil {
			return fmt.Errorf("compact %s: %w", table, err)
		}
	}
	return nil
}
