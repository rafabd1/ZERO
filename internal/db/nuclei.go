package db

import (
	"context"
	"encoding/json"
	"fmt"
)

func (r *Repository) ListNucleiTargets(ctx context.Context, programID string) ([]NucleiTarget, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, program_id, url
		FROM zero_http_services
		WHERE active = true
		  AND ($1 = '' OR program_id::text = $1)
		ORDER BY program_id, url
	`, programID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var targets []NucleiTarget
	for rows.Next() {
		var target NucleiTarget
		if err := rows.Scan(&target.HTTPServiceID, &target.ProgramID, &target.URL); err != nil {
			return nil, err
		}
		targets = append(targets, target)
	}
	return targets, rows.Err()
}

func (r *Repository) UpsertNucleiResult(ctx context.Context, result NucleiResult) (string, bool, error) {
	if len(result.Raw) == 0 {
		result.Raw = json.RawMessage(`{}`)
	}
	var id string
	var inserted bool
	err := r.pool.QueryRow(ctx, `
		INSERT INTO zero_nuclei_results(
			program_id, http_service_id, template_id, template_path, matched_at,
			severity, cves, tags, type, extractor_name, evidence_hash, raw
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb)
		ON CONFLICT(program_id, template_id, matched_at, evidence_hash) DO UPDATE SET
			http_service_id = COALESCE(excluded.http_service_id, zero_nuclei_results.http_service_id),
			severity = excluded.severity,
			cves = excluded.cves,
			tags = excluded.tags,
			type = excluded.type,
			extractor_name = excluded.extractor_name,
			raw = excluded.raw,
			last_seen_at = now()
		RETURNING id, (xmax = 0) AS inserted
	`, result.ProgramID, nullString(result.HTTPServiceID), result.TemplateID, result.TemplatePath, result.MatchedAt,
		result.Severity, result.CVEs, result.Tags, result.Type, result.ExtractorName, result.EvidenceHash, string(result.Raw)).Scan(&id, &inserted)
	if err != nil {
		return "", false, fmt.Errorf("upsert nuclei result: %w", err)
	}
	return id, inserted, nil
}

func (r *Repository) UpsertCandidateFindingFromNuclei(ctx context.Context, nucleiResultID string, result NucleiResult) (string, bool, error) {
	evidence, _ := json.Marshal(map[string]any{
		"source":      "nuclei",
		"template_id": result.TemplateID,
		"matched_at":  result.MatchedAt,
		"severity":    result.Severity,
		"cves":        result.CVEs,
		"tags":        result.Tags,
		"nuclei_hash": result.EvidenceHash,
	})
	confidence := nucleiConfidence(result.Severity)
	evidenceHash := "nuclei:" + result.EvidenceHash

	var id string
	var inserted bool
	err := r.pool.QueryRow(ctx, `
		INSERT INTO zero_candidate_findings(
			program_id, http_service_id, nuclei_result_id, severity, confidence,
			status, evidence_hash, evidence
		)
		VALUES ($1,$2,$3,$4,$5,'new',$6,$7::jsonb)
		ON CONFLICT(evidence_hash) DO UPDATE SET
			last_seen_at = now(),
			severity = excluded.severity,
			confidence = GREATEST(zero_candidate_findings.confidence, excluded.confidence),
			evidence = zero_candidate_findings.evidence || excluded.evidence
		RETURNING id, (xmax = 0) AS inserted
	`, result.ProgramID, nullString(result.HTTPServiceID), nucleiResultID, result.Severity, confidence, evidenceHash, string(evidence)).Scan(&id, &inserted)
	if err != nil {
		return "", false, fmt.Errorf("upsert candidate finding from nuclei: %w", err)
	}
	return id, inserted, nil
}

func nucleiConfidence(severity string) int {
	switch severity {
	case "critical":
		return 92
	case "high":
		return 88
	case "medium":
		return 80
	default:
		return 70
	}
}
