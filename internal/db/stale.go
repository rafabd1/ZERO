package db

import (
	"context"
	"fmt"
)

type StaleResult struct {
	Subdomains   int
	HTTPServices int
	Technologies int
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
		), events AS (
			INSERT INTO zero_change_events(program_id, entity_type, entity_id, entity_key, change_type, old_value, new_value, evidence_hash)
			SELECT program_id, 'subdomain', id, fqdn, 'removed',
				jsonb_build_object('active', true, 'last_seen_at', last_seen_at),
				jsonb_build_object('active', false, 'stale_after_hours', $2),
				encode(digest('stale:subdomain:' || id::text || ':' || $2::text, 'sha256'), 'hex')
			FROM stale
			ON CONFLICT(evidence_hash) DO NOTHING
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
		), events AS (
			INSERT INTO zero_change_events(program_id, entity_type, entity_id, entity_key, change_type, old_value, new_value, evidence_hash)
			SELECT program_id, 'http_service', id, url, 'removed',
				jsonb_build_object('active', true, 'last_seen_at', last_seen_at),
				jsonb_build_object('active', false, 'stale_after_hours', $2),
				encode(digest('stale:http_service:' || id::text || ':' || $2::text, 'sha256'), 'hex')
			FROM stale
			ON CONFLICT(evidence_hash) DO NOTHING
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
		), events AS (
			INSERT INTO zero_change_events(program_id, entity_type, entity_id, entity_key, change_type, old_value, new_value, evidence_hash)
			SELECT program_id, 'technology', id, name || ':' || version || ':' || source, 'removed',
				jsonb_build_object('last_seen_at', last_seen_at),
				jsonb_build_object('active', false, 'stale_after_hours', $2),
				encode(digest('stale:technology:' || id::text || ':' || $2::text, 'sha256'), 'hex')
			FROM stale
			ON CONFLICT(evidence_hash) DO NOTHING
		)
		SELECT count(*) FROM stale
	`, programID, staleAfterHours).Scan(&result.Technologies); err != nil {
		return result, fmt.Errorf("mark stale technologies: %w", err)
	}
	return result, nil
}

func (r *Repository) CleanupInactiveEntities(ctx context.Context, retentionHours, retentionScans int) (CleanupResult, error) {
	if retentionHours <= 0 && retentionScans <= 0 {
		return CleanupResult{}, nil
	}
	var result CleanupResult
	if err := r.pool.QueryRow(ctx, `
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
		), stale_matches AS (
			DELETE FROM zero_technology_vulnerability_matches m
			USING zero_http_services s
			WHERE m.http_service_id = s.id
			  AND s.active = false
			  AND (
				($1 > 0 AND s.last_seen_at < now() - make_interval(hours => $1))
				OR ($2 > 0 AND s.last_scan_run_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM retained_runs rr WHERE rr.id = s.last_scan_run_id))
			  )
			RETURNING m.id
		)
		SELECT count(*) FROM stale_matches
	`, retentionHours, retentionScans).Scan(&result.TechnologyVulnerabilityRows); err != nil {
		return result, fmt.Errorf("cleanup inactive technology vulnerability matches: %w", err)
	}
	if err := r.pool.QueryRow(ctx, `
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
		), stale_tech AS (
			DELETE FROM zero_technology_observations t
			WHERE t.active = false
			  AND (
				($1 > 0 AND t.last_seen_at < now() - make_interval(hours => $1))
				OR ($2 > 0 AND t.last_scan_run_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM retained_runs rr WHERE rr.id = t.last_scan_run_id))
			  )
			RETURNING t.id
		)
		SELECT count(*) FROM stale_tech
	`, retentionHours, retentionScans).Scan(&result.TechnologyObservations); err != nil {
		return result, fmt.Errorf("cleanup inactive technology observations: %w", err)
	}
	if err := r.pool.QueryRow(ctx, `
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
		), stale_services AS (
			DELETE FROM zero_http_services s
			WHERE s.active = false
			  AND NOT EXISTS (SELECT 1 FROM zero_nuclei_results n WHERE n.http_service_id = s.id)
			  AND NOT EXISTS (SELECT 1 FROM zero_candidate_findings f WHERE f.http_service_id = s.id)
			  AND (
				($1 > 0 AND s.last_seen_at < now() - make_interval(hours => $1))
				OR ($2 > 0 AND s.last_scan_run_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM retained_runs rr WHERE rr.id = s.last_scan_run_id))
			  )
			RETURNING s.id
		)
		SELECT count(*) FROM stale_services
	`, retentionHours, retentionScans).Scan(&result.HTTPServices); err != nil {
		return result, fmt.Errorf("cleanup inactive http services: %w", err)
	}
	if err := r.pool.QueryRow(ctx, `
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
		), stale_subdomains AS (
			DELETE FROM zero_subdomains s
			WHERE s.active = false
			  AND (
				($1 > 0 AND s.last_seen_at < now() - make_interval(hours => $1))
				OR ($2 > 0 AND s.last_scan_run_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM retained_runs rr WHERE rr.id = s.last_scan_run_id))
			  )
			RETURNING s.id
		)
		SELECT count(*) FROM stale_subdomains
	`, retentionHours, retentionScans).Scan(&result.Subdomains); err != nil {
		return result, fmt.Errorf("cleanup inactive subdomains: %w", err)
	}
	if err := r.pool.QueryRow(ctx, `
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
		), stale_assets AS (
			DELETE FROM zero_scope_assets a
			WHERE a.active = false
			  AND (
				($1 > 0 AND a.last_seen_at < now() - make_interval(hours => $1))
				OR ($2 > 0 AND a.last_scan_run_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM retained_runs rr WHERE rr.id = a.last_scan_run_id))
			  )
			RETURNING a.id
		)
		SELECT count(*) FROM stale_assets
	`, retentionHours, retentionScans).Scan(&result.ScopeAssets); err != nil {
		return result, fmt.Errorf("cleanup inactive scope assets: %w", err)
	}
	return result, nil
}
