package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

func (r *Repository) CreateScanRequest(ctx context.Context, programID, name, requestedBy string, runAfter time.Time, params any) (string, error) {
	if requestedBy == "" {
		requestedBy = "cli"
	}
	if runAfter.IsZero() {
		runAfter = time.Now().UTC()
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return "", fmt.Errorf("marshal scan request params: %w", err)
	}
	var id string
	err = r.pool.QueryRow(ctx, `
		INSERT INTO zero_scan_requests(program_id, name, requested_by, run_after, params)
		VALUES (NULLIF($1, '')::uuid,$2,$3,$4,$5::jsonb)
		RETURNING id::text
	`, programID, name, requestedBy, runAfter, string(raw)).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create scan request: %w", err)
	}
	return id, nil
}

func (r *Repository) ClaimDueScanRequests(ctx context.Context, limit int) ([]ScanRequest, error) {
	if limit <= 0 {
		limit = 5
	}
	rows, err := r.pool.Query(ctx, `
		WITH due AS (
			SELECT id
			FROM zero_scan_requests
			WHERE status = 'queued'
			  AND run_after <= now()
			ORDER BY run_after, created_at
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		)
		UPDATE zero_scan_requests r
		SET status = 'running',
			attempt_count = attempt_count + 1,
			started_at = now(),
			locked_at = now(),
			updated_at = now(),
			error = ''
		FROM due
		WHERE r.id = due.id
		RETURNING r.id::text, COALESCE(r.program_id::text, ''), r.name, r.params
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("claim scan requests: %w", err)
	}
	defer rows.Close()
	requests := []ScanRequest{}
	for rows.Next() {
		var req ScanRequest
		if err := rows.Scan(&req.ID, &req.ProgramID, &req.Name, &req.Params); err != nil {
			return nil, err
		}
		requests = append(requests, req)
	}
	return requests, rows.Err()
}

func (r *Repository) FinishScanRequest(ctx context.Context, id string, runErr error) error {
	status := "succeeded"
	errorText := ""
	if runErr != nil {
		status = "failed"
		errorText = runErr.Error()
	}
	_, err := r.pool.Exec(ctx, `
		UPDATE zero_scan_requests
		SET status = $2,
			finished_at = now(),
			locked_at = NULL,
			error = $3,
			updated_at = now()
		WHERE id = $1::uuid
	`, id, status, errorText)
	if err != nil {
		return fmt.Errorf("finish scan request: %w", err)
	}
	return nil
}
