package db

import (
	"context"
	"encoding/json"
	"fmt"
)

func (r *Repository) ListUnreportedFindings(ctx context.Context, limit int) ([]ReportFinding, error) {
	if limit <= 0 {
		limit = 500
	}
	rows, err := r.pool.Query(ctx, `
		SELECT
			f.id::text,
			f.program_id::text,
			p.handle,
			p.program_url,
			COALESCE(s.url, ''),
			COALESCE(s.host, ''),
			f.severity,
			f.confidence,
			f.evidence,
			f.first_seen_at::text
		FROM zero_candidate_findings f
		JOIN zero_programs p ON p.id = f.program_id
		LEFT JOIN zero_http_services s ON s.id = f.http_service_id
		WHERE f.status = 'new'
		  AND f.report_id IS NULL
		ORDER BY
			CASE f.severity
				WHEN 'critical' THEN 1
				WHEN 'high' THEN 2
				WHEN 'medium' THEN 3
				WHEN 'low' THEN 4
				ELSE 5
			END,
			f.confidence DESC,
			f.first_seen_at ASC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	findings := []ReportFinding{}
	for rows.Next() {
		var finding ReportFinding
		if err := rows.Scan(
			&finding.ID,
			&finding.ProgramID,
			&finding.ProgramHandle,
			&finding.ProgramURL,
			&finding.ServiceURL,
			&finding.ServiceHost,
			&finding.Severity,
			&finding.Confidence,
			&finding.Evidence,
			&finding.FirstSeenAt,
		); err != nil {
			return nil, err
		}
		findings = append(findings, finding)
	}
	return findings, rows.Err()
}

func (r *Repository) CreateReport(ctx context.Context, draft ReportDraft) (string, bool, error) {
	meta, _ := json.Marshal(draft.Metadata)
	var id string
	var inserted bool
	err := r.pool.QueryRow(ctx, `
		INSERT INTO zero_reports(
			program_id, report_key, title, severity, confidence, body_markdown, finding_ids, metadata
		)
		VALUES ($1::uuid,$2,$3,$4,$5,$6,$7::text[]::uuid[],$8::jsonb)
		ON CONFLICT(report_key) DO UPDATE SET
			metadata = zero_reports.metadata || excluded.metadata
		RETURNING id::text, (xmax = 0) AS inserted
	`, draft.ProgramID, draft.ReportKey, draft.Title, draft.Severity, draft.Confidence, draft.Body, draft.FindingIDs, string(meta)).Scan(&id, &inserted)
	if err != nil {
		return "", false, fmt.Errorf("create report: %w", err)
	}

	_, err = r.pool.Exec(ctx, `
		UPDATE zero_candidate_findings
		SET report_id = $1::uuid
		WHERE id = ANY($2::text[]::uuid[])
		  AND report_id IS NULL
	`, id, draft.FindingIDs)
	if err != nil {
		return "", false, fmt.Errorf("attach findings to report: %w", err)
	}
	return id, inserted, nil
}
