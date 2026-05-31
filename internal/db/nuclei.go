package db

import (
	"context"
	"encoding/json"
	"fmt"
)

func (r *Repository) ListNucleiTargets(ctx context.Context) ([]NucleiTarget, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, program_id, url
		FROM zero_http_services
		WHERE active = true
		ORDER BY program_id, url
	`)
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
