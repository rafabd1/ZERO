package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
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

func (r *Repository) CreateScanCampaign(ctx context.Context, name, requestedBy string, runAfter time.Time, params any, dueOnly bool, limit, parallelism int) (ScanCampaignCreateResult, error) {
	if requestedBy == "" {
		requestedBy = "cli"
	}
	if runAfter.IsZero() {
		runAfter = time.Now().UTC()
	}
	if parallelism <= 0 {
		parallelism = 1
	}
	if parallelism > 32 {
		parallelism = 32
	}
	programs, err := r.ListProgramsForCampaign(ctx, dueOnly, limit)
	if err != nil {
		return ScanCampaignCreateResult{}, err
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return ScanCampaignCreateResult{}, fmt.Errorf("marshal scan campaign params: %w", err)
	}
	filterRaw, err := json.Marshal(map[string]any{
		"due_only": dueOnly,
		"limit":    limit,
	})
	if err != nil {
		return ScanCampaignCreateResult{}, fmt.Errorf("marshal scan campaign filter: %w", err)
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return ScanCampaignCreateResult{}, fmt.Errorf("begin scan campaign: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var id string
	err = tx.QueryRow(ctx, `
		INSERT INTO zero_scan_campaigns(
			name, requested_by, run_after, parallelism, params, program_filter, total_requests, queued_requests
		)
		VALUES ($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7,$7)
		RETURNING id::text
	`, name, requestedBy, runAfter, parallelism, string(raw), string(filterRaw), len(programs)).Scan(&id)
	if err != nil {
		return ScanCampaignCreateResult{}, fmt.Errorf("create scan campaign: %w", err)
	}

	for _, program := range programs {
		childParams, err := scanCampaignChildParams(raw, program.ID)
		if err != nil {
			return ScanCampaignCreateResult{}, err
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO zero_scan_requests(program_id, campaign_id, name, requested_by, run_after, params)
			VALUES ($1::uuid,$2::uuid,$3,$4,$5,$6::jsonb)
		`, program.ID, id, name, requestedBy, runAfter, string(childParams))
		if err != nil {
			return ScanCampaignCreateResult{}, fmt.Errorf("create scan campaign child request: %w", err)
		}
	}

	if len(programs) == 0 {
		_, err = tx.Exec(ctx, `
			UPDATE zero_scan_campaigns
			SET status = 'succeeded',
				finished_at = now(),
				updated_at = now()
			WHERE id = $1::uuid
		`, id)
		if err != nil {
			return ScanCampaignCreateResult{}, fmt.Errorf("finish empty scan campaign: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return ScanCampaignCreateResult{}, fmt.Errorf("commit scan campaign: %w", err)
	}
	return ScanCampaignCreateResult{
		ID:       id,
		Total:    len(programs),
		Queued:   len(programs),
		DueOnly:  dueOnly,
		Limit:    limit,
		Parallel: parallelism,
	}, nil
}

func scanCampaignChildParams(raw []byte, programID string) ([]byte, error) {
	params := map[string]any{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &params); err != nil {
			return nil, fmt.Errorf("decode scan campaign params: %w", err)
		}
	}
	params["ProgramID"] = programID
	params["SkipSync"] = true
	return json.Marshal(params)
}

func (r *Repository) ClaimDueScanRequests(ctx context.Context, limit int) ([]ScanRequest, error) {
	if limit <= 0 {
		limit = 5
	}
	rows, err := r.pool.Query(ctx, `
		WITH campaign_counts AS (
			SELECT campaign_id, count(*) FILTER (WHERE status = 'running') AS running_count
			FROM zero_scan_requests
			WHERE campaign_id IS NOT NULL
			GROUP BY campaign_id
		),
		eligible AS (
			SELECT
				r.id,
				r.campaign_id,
				r.run_after,
				r.created_at,
				COALESCE(c.parallelism, 1) - COALESCE(cc.running_count, 0) AS campaign_slots,
				row_number() OVER (PARTITION BY r.campaign_id ORDER BY r.run_after, r.created_at) AS campaign_rank
			FROM zero_scan_requests r
			LEFT JOIN zero_scan_campaigns c ON c.id = r.campaign_id
			LEFT JOIN campaign_counts cc ON cc.campaign_id = r.campaign_id
			WHERE r.status = 'queued'
			  AND r.run_after <= now()
			  AND (
				r.campaign_id IS NULL
				OR (
					c.status IN ('queued', 'running')
					AND c.run_after <= now()
				)
			  )
		),
		due AS (
			SELECT id
			FROM eligible
			WHERE campaign_id IS NULL
			   OR (campaign_slots > 0 AND campaign_rank <= campaign_slots)
			ORDER BY run_after, created_at
			LIMIT $1
		),
		claimed AS (
			UPDATE zero_scan_requests r
			SET status = 'running',
				attempt_count = attempt_count + 1,
				started_at = now(),
				locked_at = now(),
				updated_at = now(),
				error = ''
			FROM due
			WHERE r.id = due.id
			RETURNING r.id, r.program_id, r.campaign_id, r.name, r.params
		),
		affected_campaigns AS (
			SELECT DISTINCT campaign_id
			FROM claimed
			WHERE campaign_id IS NOT NULL
		),
		counts AS (
			SELECT
				r.campaign_id,
				count(*) FILTER (WHERE r.status = 'queued') AS queued,
				count(*) FILTER (WHERE r.status = 'running') AS running,
				count(*) FILTER (WHERE r.status = 'succeeded') AS succeeded,
				count(*) FILTER (WHERE r.status = 'failed') AS failed,
				count(*) FILTER (WHERE r.status = 'canceled') AS canceled
			FROM zero_scan_requests r
			JOIN affected_campaigns ac ON ac.campaign_id = r.campaign_id
			GROUP BY r.campaign_id
		),
		refreshed_campaigns AS (
			UPDATE zero_scan_campaigns c
			SET queued_requests = counts.queued::int,
				running_requests = counts.running::int,
				succeeded_requests = counts.succeeded::int,
				failed_requests = counts.failed::int,
				status = CASE
					WHEN c.status = 'canceled' THEN 'canceled'
					WHEN counts.running > 0 THEN 'running'
					WHEN counts.queued > 0 THEN 'queued'
					WHEN counts.failed > 0 THEN 'failed'
					WHEN counts.canceled > 0 THEN 'canceled'
					ELSE 'succeeded'
				END,
				started_at = COALESCE(c.started_at, now()),
				finished_at = CASE
					WHEN counts.running = 0 AND counts.queued = 0 THEN COALESCE(c.finished_at, now())
					ELSE NULL
				END,
				updated_at = now(),
				error = CASE
					WHEN counts.failed > 0 THEN 'one or more campaign scan requests failed'
					ELSE ''
				END
			FROM counts
			WHERE c.id = counts.campaign_id
			RETURNING c.id
		)
		SELECT
			id::text,
			COALESCE(program_id::text, ''),
			COALESCE(campaign_id::text, ''),
			name,
			params
		FROM claimed
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("claim scan requests: %w", err)
	}
	defer rows.Close()
	requests := []ScanRequest{}
	campaignIDs := map[string]struct{}{}
	for rows.Next() {
		var req ScanRequest
		if err := rows.Scan(&req.ID, &req.ProgramID, &req.CampaignID, &req.Name, &req.Params); err != nil {
			return nil, err
		}
		requests = append(requests, req)
		if req.CampaignID != "" {
			campaignIDs[req.CampaignID] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for campaignID := range campaignIDs {
		_ = r.RefreshScanCampaign(ctx, campaignID)
	}
	return requests, nil
}

func (r *Repository) RecoverRunningScanRequests(ctx context.Context) (int, error) {
	tag, err := r.pool.Exec(ctx, `
		UPDATE zero_scan_requests
		SET status = 'queued',
			run_after = now(),
			locked_at = NULL,
			error = CASE
				WHEN error = '' THEN 'requeued on worker startup after interrupted execution'
				ELSE error
			END,
			updated_at = now()
		WHERE status = 'running'
	`)
	if err != nil {
		return 0, fmt.Errorf("recover running scan requests: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

func (r *Repository) CancelScanRequest(ctx context.Context, requestID string) (CancelScanResult, error) {
	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		return CancelScanResult{}, fmt.Errorf("request id is required")
	}
	var result CancelScanResult
	var campaignID string
	err := r.pool.QueryRow(ctx, `
		WITH before AS (
			SELECT id, status, COALESCE(campaign_id::text, '') AS campaign_id
			FROM zero_scan_requests
			WHERE id = $1::uuid
		), updated AS (
			UPDATE zero_scan_requests r
			SET status = 'canceled',
				finished_at = now(),
				locked_at = NULL,
				error = CASE
					WHEN r.error = '' THEN 'canceled by operator'
					ELSE r.error
				END,
				updated_at = now()
			FROM before b
			WHERE r.id = b.id
			  AND r.status IN ('queued', 'running')
			RETURNING b.status
		)
		SELECT
			COALESCE((SELECT id::text FROM before), ''),
			COALESCE((SELECT status FROM before), ''),
			COALESCE((SELECT campaign_id FROM before), ''),
			(SELECT count(*)::int FROM updated),
			(SELECT count(*)::int FROM updated WHERE status = 'queued'),
			(SELECT count(*)::int FROM updated WHERE status = 'running')
	`, requestID).Scan(&result.ID, &result.Status, &campaignID, &result.RequestsCanceled, &result.QueuedCanceled, &result.RunningCanceled)
	if err != nil {
		return CancelScanResult{}, fmt.Errorf("cancel scan request: %w", err)
	}
	if result.ID == "" {
		return CancelScanResult{}, fmt.Errorf("scan request not found")
	}
	result.Type = "scan_request"
	if campaignID != "" {
		if err := r.RefreshScanCampaign(ctx, campaignID); err != nil {
			return result, err
		}
	}
	if result.RequestsCanceled > 0 {
		result.Status = "canceled"
	}
	return result, nil
}

func (r *Repository) CancelScanCampaign(ctx context.Context, campaignID string) (CancelScanResult, error) {
	campaignID = strings.TrimSpace(campaignID)
	if campaignID == "" {
		return CancelScanResult{}, fmt.Errorf("campaign id is required")
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return CancelScanResult{}, fmt.Errorf("begin cancel scan campaign: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM zero_scan_campaigns WHERE id = $1::uuid)`, campaignID).Scan(&exists); err != nil {
		return CancelScanResult{}, fmt.Errorf("lookup scan campaign: %w", err)
	}
	if !exists {
		return CancelScanResult{}, fmt.Errorf("scan campaign not found")
	}

	var queuedCanceled, runningCanceled int
	if err := tx.QueryRow(ctx, `
		WITH candidates AS (
			SELECT id, status
			FROM zero_scan_requests
			WHERE campaign_id = $1::uuid
			  AND status IN ('queued', 'running')
		), updated AS (
			UPDATE zero_scan_requests
			SET status = 'canceled',
				finished_at = now(),
				locked_at = NULL,
				error = CASE
					WHEN error = '' THEN 'canceled by operator'
					ELSE error
				END,
				updated_at = now()
			FROM candidates c
			WHERE zero_scan_requests.id = c.id
			RETURNING c.status
		)
		SELECT
			count(*) FILTER (WHERE status = 'queued')::int,
			count(*) FILTER (WHERE status = 'running')::int
		FROM updated
	`, campaignID).Scan(&queuedCanceled, &runningCanceled); err != nil {
		return CancelScanResult{}, fmt.Errorf("cancel scan campaign requests: %w", err)
	}

	_, err = tx.Exec(ctx, `
		WITH counts AS (
			SELECT
				count(*) FILTER (WHERE status = 'queued') AS queued,
				count(*) FILTER (WHERE status = 'running') AS running,
				count(*) FILTER (WHERE status = 'succeeded') AS succeeded,
				count(*) FILTER (WHERE status = 'failed') AS failed,
				count(*) FILTER (WHERE status = 'canceled') AS canceled
			FROM zero_scan_requests
			WHERE campaign_id = $1::uuid
		)
		UPDATE zero_scan_campaigns c
		SET status = 'canceled',
			queued_requests = counts.queued::int,
			running_requests = counts.running::int,
			succeeded_requests = counts.succeeded::int,
			failed_requests = counts.failed::int,
			finished_at = now(),
			updated_at = now(),
			error = 'canceled by operator'
		FROM counts
		WHERE c.id = $1::uuid
	`, campaignID)
	if err != nil {
		return CancelScanResult{}, fmt.Errorf("update scan campaign: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return CancelScanResult{}, fmt.Errorf("commit cancel scan campaign: %w", err)
	}
	return CancelScanResult{
		ID:               campaignID,
		Type:             "scan_campaign",
		Status:           "canceled",
		QueuedCanceled:   queuedCanceled,
		RunningCanceled:  runningCanceled,
		RequestsCanceled: queuedCanceled + runningCanceled,
	}, nil
}

func (r *Repository) RecoverRunningScanCampaigns(ctx context.Context) (int, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id::text
		FROM zero_scan_campaigns
		WHERE status = 'running'
	`)
	if err != nil {
		return 0, fmt.Errorf("list running scan campaigns: %w", err)
	}
	defer rows.Close()

	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return len(ids), err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return len(ids), err
	}
	rows.Close()

	count := 0
	for _, id := range ids {
		if err := r.RefreshScanCampaign(ctx, id); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
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
		  AND status <> 'canceled'
	`, id, status, errorText)
	if err != nil {
		return fmt.Errorf("finish scan request: %w", err)
	}
	return r.RefreshScanCampaignForRequest(ctx, id)
}

func (r *Repository) RefreshScanCampaignForRequest(ctx context.Context, requestID string) error {
	var campaignID string
	err := r.pool.QueryRow(ctx, `
		SELECT COALESCE(campaign_id::text, '')
		FROM zero_scan_requests
		WHERE id = $1::uuid
	`, requestID).Scan(&campaignID)
	if err != nil {
		return fmt.Errorf("lookup scan request campaign: %w", err)
	}
	if strings.TrimSpace(campaignID) == "" {
		return nil
	}
	return r.RefreshScanCampaign(ctx, campaignID)
}

func (r *Repository) RefreshScanCampaign(ctx context.Context, campaignID string) error {
	_, err := r.pool.Exec(ctx, `
		WITH counts AS (
			SELECT
				count(*) FILTER (WHERE status = 'queued') AS queued,
				count(*) FILTER (WHERE status = 'running') AS running,
				count(*) FILTER (WHERE status = 'succeeded') AS succeeded,
				count(*) FILTER (WHERE status = 'failed') AS failed,
				count(*) FILTER (WHERE status = 'canceled') AS canceled
			FROM zero_scan_requests
			WHERE campaign_id = $1::uuid
		)
		UPDATE zero_scan_campaigns c
		SET queued_requests = counts.queued::int,
			running_requests = counts.running::int,
			succeeded_requests = counts.succeeded::int,
			failed_requests = counts.failed::int,
			status = CASE
				WHEN c.status = 'canceled' THEN 'canceled'
				WHEN counts.running > 0 THEN 'running'
				WHEN counts.queued > 0 THEN 'queued'
				WHEN counts.failed > 0 THEN 'failed'
				WHEN counts.canceled > 0 THEN 'canceled'
				ELSE 'succeeded'
			END,
			finished_at = CASE
				WHEN counts.running = 0 AND counts.queued = 0 THEN COALESCE(c.finished_at, now())
				ELSE NULL
			END,
			updated_at = now(),
			error = CASE
				WHEN counts.failed > 0 THEN 'one or more campaign scan requests failed'
				ELSE ''
			END
		FROM counts
		WHERE c.id = $1::uuid
	`, campaignID)
	if err != nil {
		return fmt.Errorf("refresh scan campaign: %w", err)
	}
	return nil
}
