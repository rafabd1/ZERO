package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

func (r *Repository) StartScanRun(ctx context.Context, runType, workerID, programID string) (string, error) {
	if workerID == "" {
		workerID = "cli"
	}
	var id string
	err := r.pool.QueryRow(ctx, `
		INSERT INTO zero_scan_runs(run_type, worker_id, program_id)
		VALUES ($1,$2,NULLIF($3, '')::uuid)
		RETURNING id::text
	`, runType, workerID, programID).Scan(&id)
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
	if err != nil {
		return fmt.Errorf("finish scan run: %w", err)
	}
	return nil
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
