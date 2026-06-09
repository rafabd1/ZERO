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
	queryLimit := limit
	if queryLimit <= 0 {
		queryLimit = 100000
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

	var id string
	var total, queued int
	err = r.pool.QueryRow(ctx, `
		WITH selected_programs AS MATERIALIZED (
			SELECT id
			FROM zero_programs
			WHERE active = true
			  AND (
				$7 = false
				OR last_scan_finished_at IS NULL
				OR last_scan_finished_at <= now() - make_interval(hours => scan_interval_hours)
			  )
			  AND NOT EXISTS (
				SELECT 1
				FROM zero_scan_runs sr
				WHERE sr.program_id = zero_programs.id
				  AND sr.run_type = 'full'
				  AND sr.status = 'running'
			  )
			ORDER BY last_scan_finished_at NULLS FIRST, last_seen_at DESC, platform, handle
			LIMIT $8
		), program_count AS (
			SELECT count(*)::int AS total
			FROM selected_programs
		), created_campaign AS (
			INSERT INTO zero_scan_campaigns(
				name, requested_by, run_after, parallelism, params, program_filter, total_requests, queued_requests
			)
			SELECT $1, $2, $3, $4, $5::jsonb, $6::jsonb, program_count.total, program_count.total
			FROM program_count
			RETURNING id
		), inserted_requests AS (
			INSERT INTO zero_scan_requests(program_id, campaign_id, name, requested_by, run_after, params)
			SELECT
				selected_programs.id,
				created_campaign.id,
				$1,
				$2,
				$3,
				jsonb_set(
					COALESCE($5::jsonb, '{}'::jsonb) || '{"SkipSync":true}'::jsonb,
					'{ProgramID}',
					to_jsonb(selected_programs.id::text),
					true
				)
			FROM selected_programs
			CROSS JOIN created_campaign
			RETURNING id
		), finished_empty_campaign AS (
			UPDATE zero_scan_campaigns
			SET status = 'succeeded',
				finished_at = now(),
				updated_at = now()
			WHERE id = (SELECT id FROM created_campaign)
			  AND NOT EXISTS (SELECT 1 FROM inserted_requests)
			RETURNING id
		)
		SELECT
			(SELECT id::text FROM created_campaign),
			(SELECT total FROM program_count),
			(SELECT count(*)::int FROM inserted_requests)
	`, name, requestedBy, runAfter, parallelism, string(raw), string(filterRaw), dueOnly, queryLimit).Scan(&id, &total, &queued)
	if err != nil {
		return ScanCampaignCreateResult{}, fmt.Errorf("create scan campaign: %w", err)
	}
	return ScanCampaignCreateResult{
		ID:       id,
		Status:   "queued",
		Total:    total,
		Queued:   queued,
		DueOnly:  dueOnly,
		Limit:    limit,
		Parallel: parallelism,
	}, nil
}

func (r *Repository) CreateStagedScanCampaign(ctx context.Context, name, requestedBy string, runAfter time.Time, params any, dueOnly bool, limit, parallelism int) (ScanCampaignCreateResult, error) {
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

	var id string
	err = r.pool.QueryRow(ctx, `
		INSERT INTO zero_scan_campaigns(
			name, status, requested_by, run_after, parallelism, params, program_filter, total_requests, queued_requests
		)
		VALUES ($1,'staging',$2,$3,$4,$5::jsonb,$6::jsonb,0,0)
		RETURNING id::text
	`, name, requestedBy, runAfter, parallelism, string(raw), string(filterRaw)).Scan(&id)
	if err != nil {
		return ScanCampaignCreateResult{}, fmt.Errorf("create staged scan campaign: %w", err)
	}
	return ScanCampaignCreateResult{
		ID:       id,
		Status:   "staging",
		Total:    0,
		Queued:   0,
		DueOnly:  dueOnly,
		Limit:    limit,
		Parallel: parallelism,
	}, nil
}

func (r *Repository) StageScanCampaignRequests(ctx context.Context, campaignID string) (ScanCampaignCreateResult, error) {
	campaignID = strings.TrimSpace(campaignID)
	if campaignID == "" {
		return ScanCampaignCreateResult{}, fmt.Errorf("campaign id is required")
	}
	var result ScanCampaignCreateResult
	err := r.pool.QueryRow(ctx, `
		WITH campaign AS MATERIALIZED (
			SELECT
				id,
				name,
				requested_by,
				run_after,
				parallelism,
				params,
				COALESCE((program_filter->>'due_only')::boolean, false) AS due_only,
				COALESCE((program_filter->>'limit')::integer, 0) AS requested_limit
			FROM zero_scan_campaigns
			WHERE id = $1::uuid
			  AND status = 'staging'
			FOR UPDATE
		), selected_programs AS MATERIALIZED (
			SELECT zp.id
			FROM zero_programs zp
			CROSS JOIN campaign c
			WHERE zp.active = true
			  AND (
				c.due_only = false
				OR zp.last_scan_finished_at IS NULL
				OR zp.last_scan_finished_at <= now() - make_interval(hours => zp.scan_interval_hours)
			  )
			  AND NOT EXISTS (
				SELECT 1
				FROM zero_scan_runs sr
				WHERE sr.program_id = zp.id
				  AND sr.run_type = 'full'
				  AND sr.status = 'running'
			  )
			ORDER BY zp.last_scan_finished_at NULLS FIRST, zp.last_seen_at DESC, zp.platform, zp.handle
			LIMIT (SELECT CASE WHEN requested_limit <= 0 THEN 100000 ELSE requested_limit END FROM campaign)
		), program_count AS (
			SELECT count(*)::int AS total
			FROM selected_programs
		), inserted_requests AS (
			INSERT INTO zero_scan_requests(program_id, campaign_id, name, requested_by, run_after, params)
			SELECT
				selected_programs.id,
				campaign.id,
				campaign.name,
				campaign.requested_by,
				campaign.run_after,
				jsonb_set(
					COALESCE(campaign.params, '{}'::jsonb) || '{"SkipSync":true}'::jsonb,
					'{ProgramID}',
					to_jsonb(selected_programs.id::text),
					true
				)
			FROM selected_programs
			CROSS JOIN campaign
			RETURNING id
		), updated_campaign AS (
			UPDATE zero_scan_campaigns c
			SET status = CASE WHEN program_count.total = 0 THEN 'succeeded' ELSE 'queued' END,
				total_requests = program_count.total,
				queued_requests = (SELECT count(*)::int FROM inserted_requests),
				finished_at = CASE WHEN program_count.total = 0 THEN now() ELSE NULL END,
				updated_at = now()
			FROM campaign
			CROSS JOIN program_count
			WHERE c.id = campaign.id
			  AND c.status = 'staging'
			RETURNING c.id, c.status, c.total_requests, c.queued_requests, campaign.due_only, campaign.requested_limit, c.parallelism
		)
		SELECT
			COALESCE((SELECT id::text FROM updated_campaign), ''),
			COALESCE((SELECT status FROM updated_campaign), ''),
			COALESCE((SELECT total_requests FROM updated_campaign), 0),
			COALESCE((SELECT queued_requests FROM updated_campaign), 0),
			COALESCE((SELECT due_only FROM updated_campaign), false),
			COALESCE((SELECT requested_limit FROM updated_campaign), 0),
			COALESCE((SELECT parallelism FROM updated_campaign), 0)
	`, campaignID).Scan(&result.ID, &result.Status, &result.Total, &result.Queued, &result.DueOnly, &result.Limit, &result.Parallel)
	if err != nil {
		return ScanCampaignCreateResult{}, fmt.Errorf("stage scan campaign requests: %w", err)
	}
	if result.ID == "" {
		return ScanCampaignCreateResult{}, nil
	}
	return result, nil
}

func (r *Repository) FailStagingScanCampaign(ctx context.Context, campaignID string, stageErr error) error {
	campaignID = strings.TrimSpace(campaignID)
	if campaignID == "" {
		return nil
	}
	msg := "scan campaign staging failed"
	if stageErr != nil {
		msg = msg + ": " + stageErr.Error()
	}
	_, err := r.pool.Exec(ctx, `
		UPDATE zero_scan_campaigns
		SET status = 'failed',
			error = $2,
			finished_at = now(),
			updated_at = now()
		WHERE id = $1::uuid
		  AND status = 'staging'
	`, campaignID, msg)
	if err != nil {
		return fmt.Errorf("fail staged scan campaign: %w", err)
	}
	return nil
}

func (r *Repository) ListStagingScanCampaigns(ctx context.Context, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id::text
		FROM zero_scan_campaigns
		WHERE status = 'staging'
		ORDER BY created_at
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("list staged scan campaigns: %w", err)
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return ids, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
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
				error = '',
				progress_stage = '',
				progress_current = 0,
				progress_total = 0,
				progress_message = '',
				progress_meta = '{}'::jsonb,
				progress_updated_at = NULL
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
					WHEN counts.failed > 0 AND counts.succeeded > 0 THEN 'partial'
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
					WHEN counts.failed > 0 AND counts.succeeded > 0 THEN counts.failed::text || ' campaign scan request(s) failed; completed partially'
					WHEN counts.failed > 0 THEN 'all campaign scan requests failed'
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

func (r *Repository) ScanRequestWorkerCapacity(ctx context.Context) (int, error) {
	var capacity int
	err := r.pool.QueryRow(ctx, `
		WITH campaign_capacity AS (
			SELECT COALESCE(sum(c.parallelism), 0)::int AS capacity
			FROM zero_scan_campaigns c
			WHERE c.status IN ('queued', 'running')
			  AND c.run_after <= now()
			  AND EXISTS (
				SELECT 1
				FROM zero_scan_requests r
				WHERE r.campaign_id = c.id
				  AND (
					r.status = 'running'
					OR (r.status = 'queued' AND r.run_after <= now())
				  )
			  )
		), standalone_capacity AS (
			SELECT count(*)::int AS capacity
			FROM zero_scan_requests r
			WHERE r.campaign_id IS NULL
			  AND (
				r.status = 'running'
				OR (r.status = 'queued' AND r.run_after <= now())
			  )
		)
		SELECT GREATEST(1, campaign_capacity.capacity + standalone_capacity.capacity)
		FROM campaign_capacity, standalone_capacity
	`).Scan(&capacity)
	if err != nil {
		return 0, fmt.Errorf("scan request worker capacity: %w", err)
	}
	return capacity, nil
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

func (r *Repository) RecoverStaleScanRequests(ctx context.Context, staleAfter time.Duration) (int, error) {
	if staleAfter <= 0 {
		staleAfter = 30 * time.Minute
	}
	staleSeconds := int64(staleAfter.Seconds())
	if staleSeconds < 60 {
		staleSeconds = 60
	}
	tag, err := r.pool.Exec(ctx, `
		WITH stale AS (
			SELECT id
			FROM zero_scan_requests
			WHERE status = 'running'
			  AND started_at < now() - make_interval(secs => $1)
			  AND (
				locked_at IS NULL
				OR locked_at < now() - make_interval(secs => $1)
			  )
		)
		UPDATE zero_scan_requests r
		SET status = 'queued',
			run_after = now(),
			locked_at = NULL,
			error = CASE
				WHEN r.error = '' THEN 'requeued after stale scan request heartbeat'
				ELSE r.error
			END,
			updated_at = now()
		WHERE r.id IN (SELECT id FROM stale)
	`, staleSeconds)
	if err != nil {
		return 0, fmt.Errorf("recover stale scan requests: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

func (r *Repository) TouchScanRequest(ctx context.Context, id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil
	}
	_, err := r.pool.Exec(ctx, `
		UPDATE zero_scan_requests
		SET locked_at = now(),
			updated_at = now()
		WHERE id = $1::uuid
		  AND status = 'running'
	`, id)
	if err != nil {
		return fmt.Errorf("touch scan request: %w", err)
	}
	return nil
}

func (r *Repository) UpdateScanRequestProgress(ctx context.Context, id string, progress ScanRequestProgress) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil
	}
	if progress.Current < 0 {
		progress.Current = 0
	}
	if progress.Total < 0 {
		progress.Total = 0
	}
	if progress.Total > 0 && progress.Current > progress.Total {
		progress.Current = progress.Total
	}
	if progress.Meta == nil {
		progress.Meta = map[string]any{}
	}
	rawMeta, err := json.Marshal(progress.Meta)
	if err != nil {
		return fmt.Errorf("marshal scan request progress metadata: %w", err)
	}
	_, err = r.pool.Exec(ctx, `
		UPDATE zero_scan_requests
		SET locked_at = now(),
			updated_at = now(),
			progress_stage = $2,
			progress_current = $3,
			progress_total = $4,
			progress_message = $5,
			progress_meta = $6::jsonb,
			progress_updated_at = now()
		WHERE id = $1::uuid
		  AND status = 'running'
	`, id, strings.TrimSpace(progress.Stage), progress.Current, progress.Total, strings.TrimSpace(progress.Message), string(rawMeta))
	if err != nil {
		return fmt.Errorf("update scan request progress: %w", err)
	}
	return nil
}

func (r *Repository) RecoverRetryableFailedScanRequests(ctx context.Context, retryPolicy ScanRequestRetryPolicy) (int, error) {
	if retryPolicy.MaxAttempts <= 0 {
		retryPolicy.MaxAttempts = 4
	}
	if retryPolicy.BaseDelay <= 0 {
		retryPolicy.BaseDelay = 2 * time.Minute
	}
	delaySeconds := int64(retryPolicy.BaseDelay.Seconds())
	if delaySeconds < 1 {
		delaySeconds = 60
	}
	tag, err := r.pool.Exec(ctx, `
		WITH retryable AS (
			SELECT r.id
			FROM zero_scan_requests r
			JOIN zero_scan_campaigns c ON c.id = r.campaign_id
			WHERE r.status = 'failed'
			  AND c.status IN ('queued', 'running')
			  AND r.attempt_count < $1
			  AND EXISTS (
				SELECT 1
				FROM unnest($3::text[]) AS needle
				WHERE lower(r.error) LIKE '%' || needle || '%'
			  )
		)
		UPDATE zero_scan_requests r
		SET status = 'queued',
			run_after = now() + make_interval(secs => LEAST($2::double precision * power(2, GREATEST(r.attempt_count - 1, 0)), 3600)),
			finished_at = NULL,
			locked_at = NULL,
			error = s.retry_error,
			updated_at = now()
		FROM (
			SELECT id, 'transient failure recovered; retry scheduled: ' || error AS retry_error
			FROM zero_scan_requests
			WHERE id IN (SELECT id FROM retryable)
		) s
		WHERE r.id = s.id
	`, retryPolicy.MaxAttempts, delaySeconds, retryableScanRequestNeedles())
	if err != nil {
		return 0, fmt.Errorf("recover retryable failed scan requests: %w", err)
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

func (r *Repository) FinishScanRequest(ctx context.Context, id string, runErr error, retryPolicy ScanRequestRetryPolicy) error {
	status := "succeeded"
	errorText := ""
	if runErr != nil {
		status = "failed"
		errorText = runErr.Error()
	}
	if runErr != nil && retryableScanRequestError(runErr) {
		if retryPolicy.MaxAttempts <= 0 {
			retryPolicy.MaxAttempts = 4
		}
		if retryPolicy.BaseDelay <= 0 {
			retryPolicy.BaseDelay = 2 * time.Minute
		}
		delaySeconds := int64(retryPolicy.BaseDelay.Seconds())
		if delaySeconds < 1 {
			delaySeconds = 60
		}
		var requeued bool
		err := r.pool.QueryRow(ctx, `
			WITH current AS (
				SELECT attempt_count
				FROM zero_scan_requests
				WHERE id = $1::uuid
				  AND status <> 'canceled'
			), updated AS (
				UPDATE zero_scan_requests r
				SET status = 'queued',
					run_after = now() + make_interval(secs => LEAST($3::double precision * power(2, GREATEST(current.attempt_count - 1, 0)), 3600)),
					locked_at = NULL,
					error = $4,
					updated_at = now()
				FROM current
				WHERE r.id = $1::uuid
				  AND current.attempt_count < $2
				RETURNING r.id
			)
			SELECT EXISTS (SELECT 1 FROM updated)
		`, id, retryPolicy.MaxAttempts, delaySeconds, retryErrorText(errorText)).Scan(&requeued)
		if err != nil {
			return fmt.Errorf("retry scan request: %w", err)
		}
		if requeued {
			return r.RefreshScanCampaignForRequest(ctx, id)
		}
	}
	_, err := r.pool.Exec(ctx, `
		UPDATE zero_scan_requests
		SET status = $2,
			finished_at = now(),
			locked_at = NULL,
			error = $3,
			updated_at = now(),
			progress_stage = CASE WHEN $2 = 'succeeded' THEN 'finished' ELSE progress_stage END,
			progress_current = CASE WHEN $2 = 'succeeded' AND progress_total > 0 THEN progress_total ELSE progress_current END,
			progress_message = CASE WHEN $2 = 'succeeded' THEN 'finished' ELSE progress_message END,
			progress_updated_at = now()
		WHERE id = $1::uuid
		  AND status <> 'canceled'
	`, id, status, errorText)
	if err != nil {
		return fmt.Errorf("finish scan request: %w", err)
	}
	return r.RefreshScanCampaignForRequest(ctx, id)
}

func retryErrorText(err string) string {
	err = strings.TrimSpace(err)
	if err == "" {
		return "transient failure; retry scheduled"
	}
	return "transient failure; retry scheduled: " + err
}

func retryableScanRequestError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, needle := range retryableScanRequestNeedles() {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}

func retryableScanRequestNeedles() []string {
	return []string{
		"emaxconnsession",
		"max clients reached",
		"failed to connect",
		"connection refused",
		"connection reset",
		"connection timed out",
		"server closed",
		"temporary failure",
		"timeout",
		"deadline exceeded",
		"status 429",
		"too many requests",
		"status 500",
		"status 502",
		"status 503",
		"status 504",
	}
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
				WHEN c.status = 'staging'
					AND counts.queued = 0
					AND counts.running = 0
					AND counts.succeeded = 0
					AND counts.failed = 0
					AND counts.canceled = 0 THEN 'staging'
				WHEN counts.running > 0 THEN 'running'
				WHEN counts.queued > 0 THEN 'queued'
				WHEN counts.failed > 0 AND counts.succeeded > 0 THEN 'partial'
				WHEN counts.failed > 0 THEN 'failed'
				WHEN counts.canceled > 0 THEN 'canceled'
				ELSE 'succeeded'
			END,
			finished_at = CASE
				WHEN c.status = 'staging'
					AND counts.queued = 0
					AND counts.running = 0
					AND counts.succeeded = 0
					AND counts.failed = 0
					AND counts.canceled = 0 THEN NULL
				WHEN counts.running = 0 AND counts.queued = 0 THEN COALESCE(c.finished_at, now())
				ELSE NULL
			END,
			updated_at = now(),
			error = CASE
				WHEN counts.failed > 0 AND counts.succeeded > 0 THEN counts.failed::text || ' campaign scan request(s) failed; completed partially'
				WHEN counts.failed > 0 THEN 'all campaign scan requests failed'
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
