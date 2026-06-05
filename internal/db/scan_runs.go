package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type ScanRunOptions struct {
	DefaultScanCycleID string
	ParentScanRunID    string
	ScanRequestID      string
	ScanCampaignID     string
}

func (r *Repository) StartScanRun(ctx context.Context, runType, workerID, programID string) (string, error) {
	return r.StartScanRunWithOptions(ctx, runType, workerID, programID, ScanRunOptions{})
}

func (r *Repository) StartScanRunWithOptions(ctx context.Context, runType, workerID, programID string, opts ScanRunOptions) (string, error) {
	if workerID == "" {
		workerID = "cli"
	}
	programID = strings.TrimSpace(programID)
	opts.DefaultScanCycleID = strings.TrimSpace(opts.DefaultScanCycleID)
	opts.ParentScanRunID = strings.TrimSpace(opts.ParentScanRunID)
	opts.ScanRequestID = strings.TrimSpace(opts.ScanRequestID)
	opts.ScanCampaignID = strings.TrimSpace(opts.ScanCampaignID)
	var id string
	err := r.pool.QueryRow(ctx, `
		INSERT INTO zero_scan_runs(
			run_type, worker_id, program_id, default_scan_cycle_id, parent_scan_run_id, scan_request_id, scan_campaign_id
		)
		VALUES (
			$1,$2,NULLIF($3, '')::uuid,NULLIF($4, '')::uuid,NULLIF($5, '')::uuid,NULLIF($6, '')::uuid,NULLIF($7, '')::uuid
		)
		RETURNING id::text
	`, runType, workerID, programID, opts.DefaultScanCycleID, opts.ParentScanRunID, opts.ScanRequestID, opts.ScanCampaignID).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("start scan run: %w", err)
	}
	return id, nil
}

func (r *Repository) FinishScanRun(ctx context.Context, id, status string, inputCount, insertedCount int, stats map[string]any, runErr error) error {
	if len(stats) == 0 {
		stats = map[string]any{}
	}
	errorText := ""
	if runErr != nil {
		errorText = runErr.Error()
	}
	rawStats, _ := json.Marshal(stats)
	err := withRetryableDB(ctx, 5, 150*time.Millisecond, func() error {
		_, err := r.pool.Exec(ctx, `
		UPDATE zero_scan_runs
		SET status = $2,
			finished_at = now(),
			input_count = $3,
			inserted_count = $4,
			error = $5,
			stats = $6::jsonb
		WHERE id = $1::uuid
	`, id, status, inputCount, insertedCount, errorText, string(rawStats))
		return err
	})
	if err != nil {
		return fmt.Errorf("finish scan run: %w", err)
	}
	return nil
}

func (r *Repository) StartDefaultScanCycle(ctx context.Context, parallelism, totalPrograms int) (string, error) {
	if parallelism < 1 {
		parallelism = 1
	}
	if parallelism > 64 {
		parallelism = 64
	}
	if totalPrograms < 0 {
		totalPrograms = 0
	}
	var id string
	err := r.pool.QueryRow(ctx, `
		INSERT INTO zero_default_scan_cycles(parallelism, total_programs, running_programs, metadata)
		VALUES ($1,$2,0,jsonb_build_object('source', 'run due'))
		RETURNING id::text
	`, parallelism, totalPrograms).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("start default scan cycle: %w", err)
	}
	return id, nil
}

func (r *Repository) RefreshDefaultScanCycle(ctx context.Context, id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil
	}
	err := withRetryableDB(ctx, 5, 150*time.Millisecond, func() error {
		_, err := r.pool.Exec(ctx, `
		WITH counts AS (
			SELECT
				count(*) FILTER (WHERE status = 'running')::int AS running,
				count(*) FILTER (WHERE status = 'succeeded')::int AS succeeded,
				count(*) FILTER (WHERE status = 'failed')::int AS failed,
				count(*) FILTER (WHERE status = 'canceled')::int AS canceled,
				count(*)::int AS total
			FROM zero_scan_runs
			WHERE default_scan_cycle_id = $1::uuid
			  AND run_type = 'full'
		)
		UPDATE zero_default_scan_cycles c
		SET running_programs = counts.running,
			succeeded_programs = counts.succeeded,
			failed_programs = counts.failed,
			canceled_programs = counts.canceled,
			total_programs = GREATEST(c.total_programs, counts.total),
			status = CASE
				WHEN counts.running > 0 THEN 'running'
				WHEN counts.failed > 0 AND counts.succeeded > 0 THEN 'partial'
				WHEN counts.failed > 0 THEN 'failed'
				WHEN counts.canceled > 0 AND counts.succeeded = 0 THEN 'canceled'
				ELSE 'succeeded'
			END,
			finished_at = CASE
				WHEN counts.running = 0 THEN COALESCE(c.finished_at, now())
				ELSE NULL
			END,
			error = CASE
				WHEN counts.failed > 0 AND counts.succeeded > 0 THEN counts.failed::text || ' default program scan(s) failed; completed partially'
				WHEN counts.failed > 0 THEN 'all default program scans failed'
				ELSE ''
			END,
			updated_at = now()
		FROM counts
		WHERE c.id = $1::uuid
	`, id)
		return err
	})
	if err != nil {
		return fmt.Errorf("refresh default scan cycle: %w", err)
	}
	return nil
}

func (r *Repository) RefreshRunningDefaultScanCycles(ctx context.Context) (int, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id::text
		FROM zero_default_scan_cycles
		WHERE status = 'running'
		ORDER BY started_at ASC
	`)
	if err != nil {
		return 0, fmt.Errorf("list running default scan cycles: %w", err)
	}
	defer rows.Close()

	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return 0, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, id := range ids {
		if err := r.RefreshDefaultScanCycle(ctx, id); err != nil {
			return 0, err
		}
	}
	return len(ids), nil
}

func (r *Repository) RecoverRunningScanRuns(ctx context.Context) (int, error) {
	tag, err := r.pool.Exec(ctx, `
		UPDATE zero_scan_runs
		SET status = 'failed',
			finished_at = now(),
			error = CASE
				WHEN error = '' THEN 'recovered on worker startup after interrupted execution'
				ELSE error
			END,
			stats = stats || jsonb_build_object('recovered_on_startup', true)
		WHERE status = 'running'
	`)
	if err != nil {
		return 0, fmt.Errorf("recover running scan runs: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

func (r *Repository) LastSuccessfulScopeSync(ctx context.Context) (*time.Time, error) {
	var last *time.Time
	err := r.pool.QueryRow(ctx, `
		SELECT max(finished_at)
		FROM zero_scan_runs
		WHERE run_type = 'scope'
		  AND status = 'succeeded'
		  AND finished_at IS NOT NULL
	`).Scan(&last)
	if err != nil {
		return nil, fmt.Errorf("last successful scope sync: %w", err)
	}
	return last, nil
}
