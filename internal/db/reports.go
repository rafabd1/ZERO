package db

import (
	"context"
	"encoding/json"
	"fmt"
)

func (r *Repository) ListUnreportedFindings(ctx context.Context, programID string, limit int) ([]ReportFinding, error) {
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
		  AND ($1 = '' OR f.program_id::text = $1)
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
		LIMIT $2
	`, programID, limit)
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
			program_id, scan_run_id, report_key, title, severity, confidence, body_markdown, finding_ids, metadata
		)
		VALUES ($1::uuid,NULLIF($2, '')::uuid,$3,$4,$5,$6,$7,$8::text[]::uuid[],$9::jsonb)
		ON CONFLICT(report_key) DO UPDATE SET
			metadata = zero_reports.metadata || excluded.metadata
		RETURNING id::text, (xmax = 0) AS inserted
	`, draft.ProgramID, draft.ScanRunID, draft.ReportKey, draft.Title, draft.Severity, draft.Confidence, draft.Body, draft.FindingIDs, string(meta)).Scan(&id, &inserted)
	if err != nil {
		return "", false, fmt.Errorf("create report: %w", err)
	}

	_, err = r.pool.Exec(ctx, `
		UPDATE zero_candidate_findings
		SET report_id = $1::uuid,
			status = 'reported'
		WHERE id = ANY($2::text[]::uuid[])
		  AND report_id IS NULL
	`, id, draft.FindingIDs)
	if err != nil {
		return "", false, fmt.Errorf("attach findings to report: %w", err)
	}
	return id, inserted, nil
}

func (r *Repository) ListTriageBundles(ctx context.Context, programID, status string, limit int) ([]json.RawMessage, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := r.pool.Query(ctx, `
		SELECT jsonb_build_object(
			'finding', jsonb_build_object(
				'id', f.id,
				'program_id', f.program_id,
				'http_service_id', f.http_service_id,
				'nuclei_result_id', f.nuclei_result_id,
				'severity', f.severity,
				'confidence', f.confidence,
				'status', f.status,
				'evidence', f.evidence,
				'first_seen_at', f.first_seen_at,
				'last_seen_at', f.last_seen_at
			),
			'program', jsonb_build_object(
				'id', p.id,
				'platform', p.platform,
				'handle', p.handle,
				'program_url', p.program_url
			),
			'service', CASE WHEN s.id IS NULL THEN NULL ELSE jsonb_build_object(
				'id', s.id,
				'url', s.url,
				'host', s.host,
				'status_code', s.status_code,
				'title', s.title,
				'webserver', s.webserver,
				'technologies', s.technologies,
				'favicon_hash', s.favicon_hash,
				'tls', s.tls
			) END,
			'nuclei_result', CASE WHEN n.id IS NULL THEN NULL ELSE jsonb_build_object(
				'id', n.id,
				'template_id', n.template_id,
				'template_path', n.template_path,
				'matched_at', n.matched_at,
				'severity', n.severity,
				'cves', n.cves,
				'tags', n.tags,
				'type', n.type,
				'extractor_name', n.extractor_name,
				'raw', n.raw
			) END,
			'technology_observations', COALESCE((
				SELECT jsonb_agg(jsonb_build_object(
					'id', t.id,
					'name', t.name,
					'version', t.version,
					'source', t.source,
					'confidence', t.confidence,
					'evidence', t.evidence,
					'last_seen_at', t.last_seen_at
				) ORDER BY t.confidence DESC, t.last_seen_at DESC)
				FROM zero_technology_observations t
				WHERE t.http_service_id = s.id
				  AND t.active = true
			), '[]'::jsonb),
			'passive_cve_matches', COALESCE((
				SELECT jsonb_agg(jsonb_build_object(
					'vuln_id', v.vuln_id,
					'severity', v.severity,
					'cvss_score', v.cvss_score,
					'summary', v.summary,
					'references', v.references_json,
					'technology_name', m.technology_name,
					'technology_version', m.technology_version,
					'confidence', m.confidence,
					'evidence', m.evidence
				) ORDER BY m.confidence DESC, v.severity)
				FROM zero_technology_vulnerability_matches m
				JOIN zero_vulnerability_records v ON v.id = m.vulnerability_id
				WHERE m.program_id = f.program_id
				  AND (n.id IS NULL OR lower(v.vuln_id) = ANY(n.cves))
			), '[]'::jsonb),
			'report', CASE WHEN rep.id IS NULL THEN NULL ELSE jsonb_build_object(
				'id', rep.id,
				'report_key', rep.report_key,
				'title', rep.title,
				'severity', rep.severity,
				'confidence', rep.confidence,
				'created_at', rep.created_at
			) END,
			'triage', jsonb_build_object(
				'source', 'zero',
				'exported_for', 'proteus',
				'notes', 'Nuclei-backed finding. Passive CVE matches are prioritization context, not proof by themselves.'
			)
		)
		FROM zero_candidate_findings f
		JOIN zero_programs p ON p.id = f.program_id
		LEFT JOIN zero_http_services s ON s.id = f.http_service_id
		LEFT JOIN zero_nuclei_results n ON n.id = f.nuclei_result_id
		LEFT JOIN zero_reports rep ON rep.id = f.report_id
		WHERE ($1 = '' OR f.program_id::text = $1)
		  AND ($2 = '' OR f.status = $2)
		ORDER BY
			CASE f.severity
				WHEN 'critical' THEN 1
				WHEN 'high' THEN 2
				WHEN 'medium' THEN 3
				WHEN 'low' THEN 4
				ELSE 5
			END,
			f.confidence DESC,
			f.first_seen_at DESC
		LIMIT $3
	`, programID, status, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []json.RawMessage{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		out = append(out, append(json.RawMessage(nil), raw...))
	}
	return out, rows.Err()
}
