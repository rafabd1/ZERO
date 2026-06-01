package db

import (
	"context"
	"encoding/json"
	"fmt"
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
