package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	NucleiTargetSourceHTTPServices = "http-services"
	NucleiTargetSourceSubdomains   = "subdomains"
)

func NormalizeNucleiTargetSource(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "http", "http-service", "http-services", "services", "urls":
		return NucleiTargetSourceHTTPServices
	case "subdomain", "subdomains", "dns", "hosts", "hostnames":
		return NucleiTargetSourceSubdomains
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func (r *Repository) ListNucleiTargets(ctx context.Context, programID string, techFilter string, techMaxAgeSeconds int64, targetSource string) ([]NucleiTarget, error) {
	targetSource = NormalizeNucleiTargetSource(targetSource)
	if targetSource == NucleiTargetSourceSubdomains {
		if len(nucleiTechFilters(techFilter)) > 0 {
			return nil, fmt.Errorf("nuclei tech filter is only supported with target source %q", NucleiTargetSourceHTTPServices)
		}
		return r.listNucleiSubdomainTargets(ctx, programID)
	}
	if targetSource != NucleiTargetSourceHTTPServices {
		return nil, fmt.Errorf("unsupported nuclei target source %q", targetSource)
	}
	filters := nucleiTechFilters(techFilter)
	if len(filters) > 0 {
		return r.listNucleiTargetsByTechnology(ctx, programID, filters, techMaxAgeSeconds)
	}
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
		if err := rows.Scan(&target.HTTPServiceID, &target.ProgramID, &target.Input); err != nil {
			return nil, err
		}
		target.TargetID = target.HTTPServiceID
		target.TargetSource = NucleiTargetSourceHTTPServices
		targets = append(targets, target)
	}
	return targets, rows.Err()
}

func (r *Repository) listNucleiTargetsByTechnology(ctx context.Context, programID string, filters []string, techMaxAgeSeconds int64) ([]NucleiTarget, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT DISTINCT s.id, s.program_id, s.url
		FROM zero_http_services s
		WHERE s.active = true
		  AND ($1 = '' OR s.program_id::text = $1)
		  AND (
			(
				($3::bigint <= 0 OR s.last_seen_at >= now() - ($3::bigint * interval '1 second'))
				AND (
					lower(s.title) LIKE ANY($2::text[])
					OR lower(s.webserver) LIKE ANY($2::text[])
					OR EXISTS (
						SELECT 1
						FROM jsonb_array_elements_text(
							CASE
								WHEN jsonb_typeof(s.technologies) = 'array' THEN s.technologies
								ELSE '[]'::jsonb
							END
						) AS tech(name)
						WHERE lower(tech.name) LIKE ANY($2::text[])
					)
				)
			)
			OR EXISTS (
				SELECT 1
				FROM zero_technology_observations o
				WHERE o.http_service_id = s.id
				  AND o.active = true
				  AND ($3::bigint <= 0 OR o.last_seen_at >= now() - ($3::bigint * interval '1 second'))
				  AND lower(o.name) LIKE ANY($2::text[])
			)
		  )
		ORDER BY s.program_id, s.url
	`, programID, filters, techMaxAgeSeconds)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var targets []NucleiTarget
	for rows.Next() {
		var target NucleiTarget
		if err := rows.Scan(&target.HTTPServiceID, &target.ProgramID, &target.Input); err != nil {
			return nil, err
		}
		target.TargetID = target.HTTPServiceID
		target.TargetSource = NucleiTargetSourceHTTPServices
		targets = append(targets, target)
	}
	return targets, rows.Err()
}

func (r *Repository) listNucleiSubdomainTargets(ctx context.Context, programID string) ([]NucleiTarget, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, program_id, fqdn
		FROM zero_subdomains
		WHERE active = true
		  AND ($1 = '' OR program_id::text = $1)
		ORDER BY program_id, fqdn
	`, programID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var targets []NucleiTarget
	for rows.Next() {
		var target NucleiTarget
		if err := rows.Scan(&target.TargetID, &target.ProgramID, &target.Input); err != nil {
			return nil, err
		}
		target.TargetSource = NucleiTargetSourceSubdomains
		targets = append(targets, target)
	}
	return targets, rows.Err()
}

func nucleiTechFilters(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == '|' || r == '\n' || r == '\r'
	})
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		part = strings.ToLower(strings.TrimSpace(part))
		part = strings.Trim(part, "%")
		if part == "" {
			continue
		}
		pattern := "%" + part + "%"
		if _, ok := seen[pattern]; ok {
			continue
		}
		seen[pattern] = struct{}{}
		out = append(out, pattern)
	}
	return out
}

func (r *Repository) UpsertNucleiResult(ctx context.Context, result NucleiResult) (string, bool, error) {
	if len(result.Raw) == 0 {
		result.Raw = json.RawMessage(`{}`)
	}
	if result.CVEs == nil {
		result.CVEs = []string{}
	}
	if result.Tags == nil {
		result.Tags = []string{}
	}
	var id string
	var inserted bool
	err := r.pool.QueryRow(ctx, `
		INSERT INTO zero_nuclei_results(
			program_id, http_service_id, scan_run_id, target_source, target_id, template_id, template_path, matched_at,
			severity, cves, tags, type, extractor_name, evidence_hash, raw
		)
		VALUES ($1,$2,NULLIF($3, '')::uuid,$4,NULLIF($5, '')::uuid,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::jsonb)
		ON CONFLICT(program_id, template_id, matched_at, evidence_hash) DO UPDATE SET
			http_service_id = COALESCE(excluded.http_service_id, zero_nuclei_results.http_service_id),
			scan_run_id = COALESCE(excluded.scan_run_id, zero_nuclei_results.scan_run_id),
			target_source = excluded.target_source,
			target_id = excluded.target_id,
			severity = excluded.severity,
			cves = excluded.cves,
			tags = excluded.tags,
			type = excluded.type,
			extractor_name = excluded.extractor_name,
			raw = excluded.raw,
			last_seen_at = now()
		RETURNING id, (xmax = 0) AS inserted
	`, result.ProgramID, nullString(result.HTTPServiceID), result.ScanRunID, normalizeNucleiResultTargetSource(result.TargetSource), result.TargetID, result.TemplateID, result.TemplatePath, result.MatchedAt,
		result.Severity, result.CVEs, result.Tags, result.Type, result.ExtractorName, result.EvidenceHash, string(result.Raw)).Scan(&id, &inserted)
	if err != nil {
		return "", false, fmt.Errorf("upsert nuclei result: %w", err)
	}
	if inserted {
		if err := r.RecordChangeEvent(ctx, ChangeEvent{
			ProgramID:  result.ProgramID,
			ScanRunID:  result.ScanRunID,
			EntityType: "nuclei_result",
			EntityID:   id,
			EntityKey:  result.TemplateID + ":" + result.MatchedAt + ":" + result.EvidenceHash,
			ChangeType: "added",
			NewValue: map[string]any{
				"template_id": result.TemplateID,
				"matched_at":  result.MatchedAt,
				"severity":    result.Severity,
				"cves":        result.CVEs,
				"tags":        result.Tags,
				"target":      normalizeNucleiResultTargetSource(result.TargetSource),
			},
		}); err != nil {
			return "", false, err
		}
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
		"target": map[string]any{
			"source": normalizeNucleiResultTargetSource(result.TargetSource),
			"id":     result.TargetID,
		},
		"target_source": normalizeNucleiResultTargetSource(result.TargetSource),
		"target_id":     result.TargetID,
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
	if inserted {
		if err := r.RecordChangeEvent(ctx, ChangeEvent{
			ProgramID:  result.ProgramID,
			ScanRunID:  result.ScanRunID,
			EntityType: "candidate_finding",
			EntityID:   id,
			EntityKey:  evidenceHash,
			ChangeType: "added",
			NewValue: map[string]any{
				"nuclei_result_id": nucleiResultID,
				"template_id":      result.TemplateID,
				"matched_at":       result.MatchedAt,
				"severity":         result.Severity,
				"confidence":       confidence,
				"cves":             result.CVEs,
				"target":           normalizeNucleiResultTargetSource(result.TargetSource),
			},
		}); err != nil {
			return "", false, err
		}
	}
	return id, inserted, nil
}

func normalizeNucleiResultTargetSource(value string) string {
	value = NormalizeNucleiTargetSource(value)
	if value == "" {
		return NucleiTargetSourceHTTPServices
	}
	return value
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
