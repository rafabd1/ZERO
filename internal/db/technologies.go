package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func (r *Repository) ListWebTechTargets(ctx context.Context, programID string, limit int) ([]WebTechTarget, error) {
	if limit <= 0 {
		limit = 100000
	}
	rows, err := r.pool.Query(ctx, `
		SELECT
			id::text,
			program_id::text,
			COALESCE(last_scan_run_id::text, ''),
			url,
			host,
			COALESCE(status_code, -1),
			COALESCE(title, ''),
			COALESCE(webserver, ''),
			COALESCE(technologies, '[]'::jsonb)::text,
			COALESCE(favicon_hash, ''),
			COALESCE(raw->>'location', ''),
			COALESCE(raw->>'cname', '')
		FROM zero_http_services
		WHERE active = true
		  AND ($1 = '' OR program_id::text = $1)
		ORDER BY last_seen_at DESC, url
		LIMIT $2
	`, programID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	targets := []WebTechTarget{}
	for rows.Next() {
		var target WebTechTarget
		var technologies string
		if err := rows.Scan(
			&target.HTTPServiceID,
			&target.ProgramID,
			&target.LastScanRunID,
			&target.URL,
			&target.Host,
			&target.StatusCode,
			&target.Title,
			&target.Webserver,
			&technologies,
			&target.FaviconHash,
			&target.RedirectLocation,
			&target.CNAME,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(technologies), &target.Technologies)
		targets = append(targets, target)
	}
	return targets, rows.Err()
}

func (r *Repository) ListVersionedTechnologies(ctx context.Context, programID string, limit int) ([]VersionedTechnology, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := r.pool.Query(ctx, `
		SELECT DISTINCT ON (lower(t.name), t.version)
			t.program_id::text,
			t.http_service_id::text,
			COALESCE(t.last_scan_run_id::text, ''),
			t.name,
			t.version,
			t.source
		FROM zero_technology_observations t
		WHERE t.version <> ''
		  AND t.active = true
		  AND ($1 = '' OR t.program_id::text = $1)
		ORDER BY lower(t.name), t.version, t.last_seen_at DESC
		LIMIT $2
	`, programID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	techs := []VersionedTechnology{}
	for rows.Next() {
		var tech VersionedTechnology
		if err := rows.Scan(&tech.ProgramID, &tech.HTTPServiceID, &tech.LastScanRunID, &tech.Name, &tech.Version, &tech.Source); err != nil {
			return nil, err
		}
		techs = append(techs, tech)
	}
	return techs, rows.Err()
}

func (r *Repository) UpsertVulnerabilityRecord(ctx context.Context, record VulnerabilityRecord) (string, bool, error) {
	if record.VulnID == "" || record.Source == "" {
		return "", false, nil
	}
	if record.Severity == "" {
		record.Severity = "unknown"
	}
	refs, _ := json.Marshal(record.References)
	if len(record.Raw) == 0 {
		record.Raw = json.RawMessage(`{}`)
	}
	var id string
	var inserted bool
	err := r.pool.QueryRow(ctx, `
		INSERT INTO zero_vulnerability_records(
			vuln_id, source, summary, severity, cvss_score, references_json, raw
		)
		VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb)
		ON CONFLICT(vuln_id) DO UPDATE SET
			source = excluded.source,
			summary = excluded.summary,
			severity = excluded.severity,
			cvss_score = excluded.cvss_score,
			references_json = excluded.references_json,
			raw = excluded.raw,
			last_seen_at = now()
		RETURNING id::text, (xmax = 0) AS inserted
	`, record.VulnID, record.Source, record.Summary, record.Severity, record.CVSSScore, string(refs), string(record.Raw)).Scan(&id, &inserted)
	if err != nil {
		return "", false, fmt.Errorf("upsert vulnerability record: %w", err)
	}
	return id, inserted, nil
}

func (r *Repository) UpsertTechnologyVulnerabilityMatch(ctx context.Context, match TechnologyVulnerabilityMatch) (string, bool, error) {
	match.TechnologyName = strings.TrimSpace(match.TechnologyName)
	match.TechnologyVersion = strings.TrimSpace(match.TechnologyVersion)
	match.SourceObservation = strings.TrimSpace(match.SourceObservation)
	match.SourceQuery = strings.TrimSpace(match.SourceQuery)
	if match.ProgramID == "" || match.VulnerabilityID == "" || match.TechnologyName == "" {
		return "", false, nil
	}
	if match.Confidence < 0 {
		match.Confidence = 0
	}
	if match.Confidence > 100 {
		match.Confidence = 100
	}
	evidence, _ := json.Marshal(emptyMap(match.Evidence))
	var id string
	var inserted bool
	err := r.pool.QueryRow(ctx, `
		INSERT INTO zero_technology_vulnerability_matches(
			program_id, http_service_id, vulnerability_id, last_scan_run_id, technology_name, technology_version,
			source_observation, source_query, confidence, evidence
		)
		VALUES ($1,NULLIF($2, '')::uuid,$3,NULLIF($4, '')::uuid,$5,$6,$7,$8,$9,$10::jsonb)
		ON CONFLICT(program_id, http_service_id, vulnerability_id, (lower(technology_name)), technology_version, source_query) DO UPDATE SET
			last_scan_run_id = COALESCE(excluded.last_scan_run_id, zero_technology_vulnerability_matches.last_scan_run_id),
			last_seen_at = now(),
			confidence = GREATEST(zero_technology_vulnerability_matches.confidence, excluded.confidence),
			evidence = zero_technology_vulnerability_matches.evidence || excluded.evidence
		RETURNING id::text, (xmax = 0) AS inserted
	`, match.ProgramID, match.HTTPServiceID, match.VulnerabilityID, match.LastScanRunID, match.TechnologyName, match.TechnologyVersion, match.SourceObservation, match.SourceQuery, match.Confidence, string(evidence)).Scan(&id, &inserted)
	if err != nil {
		return "", false, fmt.Errorf("upsert technology vulnerability match: %w", err)
	}
	return id, inserted, nil
}

func (r *Repository) ListCVETemplateIDsFromMatches(ctx context.Context, programID, severities string, limit, minYear int) ([]string, error) {
	if limit <= 0 {
		limit = 100
	}
	severityList := cleanCSV(severities)
	if len(severityList) == 0 {
		severityList = []string{"medium", "high", "critical"}
	}
	rows, err := r.pool.Query(ctx, `
		SELECT DISTINCT upper(v.vuln_id)
		FROM zero_technology_vulnerability_matches m
		JOIN zero_vulnerability_records v ON v.id = m.vulnerability_id
		WHERE ($1 = '' OR m.program_id::text = $1)
		  AND lower(v.severity) = ANY($2::text[])
		  AND upper(v.vuln_id) LIKE 'CVE-%'
		  AND (
			$4 <= 0
			OR CASE
				WHEN upper(v.vuln_id) ~ '^CVE-[0-9]{4}-' THEN substring(upper(v.vuln_id) from 5 for 4)::int
				ELSE 0
			END >= $4
		  )
		  AND m.confidence >= 80
		  AND m.evidence->>'strategy' = 'nvd-cpe'
		ORDER BY upper(v.vuln_id)
		LIMIT $3
	`, programID, severityList, limit, minYear)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (r *Repository) UpsertTechnologyObservation(ctx context.Context, obs TechnologyObservation) (string, bool, error) {
	obs.Name = strings.TrimSpace(obs.Name)
	obs.Version = strings.TrimSpace(obs.Version)
	obs.Source = strings.TrimSpace(obs.Source)
	if obs.Source == "" {
		obs.Source = "unknown"
	}
	if obs.Confidence <= 0 {
		obs.Confidence = 50
	}
	if obs.Name == "" || obs.ProgramID == "" || obs.HTTPServiceID == "" {
		return "", false, nil
	}
	if shouldSkipTechnologyObservation(obs) {
		return "", false, nil
	}
	evidence, _ := json.Marshal(emptyMap(obs.Evidence))
	var id string
	var inserted bool
	err := withRetryableDB(ctx, 8, 300*time.Millisecond, func() error {
		return r.pool.QueryRow(ctx, `
		INSERT INTO zero_technology_observations(
			program_id, http_service_id, last_scan_run_id, name, version, source, confidence, evidence
		)
		VALUES ($1,$2,NULLIF($3, '')::uuid,$4,$5,$6,$7,$8::jsonb)
		ON CONFLICT(http_service_id, lower(name), version, source) DO UPDATE SET
			last_scan_run_id = COALESCE(excluded.last_scan_run_id, zero_technology_observations.last_scan_run_id),
			active = true,
			last_seen_at = now(),
			confidence = GREATEST(zero_technology_observations.confidence, excluded.confidence),
			evidence = zero_technology_observations.evidence || excluded.evidence
		RETURNING id::text, (xmax = 0) AS inserted
	`, obs.ProgramID, obs.HTTPServiceID, obs.LastScanRunID, obs.Name, obs.Version, obs.Source, obs.Confidence, string(evidence)).Scan(&id, &inserted)
	})
	if err != nil {
		return "", false, fmt.Errorf("upsert technology observation: %w", err)
	}
	if inserted {
		if err := r.RecordChangeEvent(ctx, ChangeEvent{
			ProgramID:  obs.ProgramID,
			ScanRunID:  obs.LastScanRunID,
			EntityType: "technology",
			EntityID:   id,
			EntityKey:  obs.HTTPServiceID + ":" + strings.ToLower(obs.Name) + ":" + obs.Version + ":" + obs.Source,
			ChangeType: "added",
			NewValue: map[string]any{
				"name":            obs.Name,
				"version":         obs.Version,
				"source":          obs.Source,
				"confidence":      obs.Confidence,
				"http_service_id": obs.HTTPServiceID,
			},
		}); err != nil {
			return "", false, err
		}
	}
	return id, inserted, nil
}

func shouldSkipTechnologyObservation(obs TechnologyObservation) bool {
	if strings.TrimSpace(obs.Version) != "" {
		return false
	}
	source := strings.ToLower(strings.TrimSpace(obs.Source))
	if source != "httpx" && source != "webanalyze" {
		return false
	}
	_, skip := genericUnversionedTechnologies()[normalizeTechnologyName(obs.Name)]
	return skip
}

func normalizeTechnologyName(value string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(value))), " ")
}

func genericUnversionedTechnologies() map[string]struct{} {
	return map[string]struct{}{
		"amazon cloudfront":   {},
		"amazon elb":          {},
		"amazon s3":           {},
		"amazon web services": {},
		"cart functionality":  {},
		"cloudflare":          {},
		"google font api":     {},
		"google tag manager":  {},
		"hsts":                {},
		"http/3":              {},
		"jquery cdn":          {},
		"youtube":             {},
	}
}

func (r *Repository) MarkMissingTechnologyObservationsInactive(ctx context.Context, programID, scanRunID, source string, httpServiceIDs []string) (int, error) {
	scanRunID = strings.TrimSpace(scanRunID)
	source = strings.TrimSpace(source)
	if scanRunID == "" || source == "" || len(httpServiceIDs) == 0 {
		return 0, nil
	}
	cleanIDs := make([]string, 0, len(httpServiceIDs))
	seen := map[string]struct{}{}
	for _, id := range httpServiceIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		cleanIDs = append(cleanIDs, id)
	}
	if len(cleanIDs) == 0 {
		return 0, nil
	}
	var count int
	if err := r.pool.QueryRow(ctx, `
		WITH stale AS (
			UPDATE zero_technology_observations o
			SET active = false,
				evidence = o.evidence || jsonb_build_object(
					'deactivated_at', now(),
					'deactivation_reason', 'missing_from_authoritative_fingerprint',
					'superseded_by_scan_run_id', $2::text
				)
			WHERE ($1 = '' OR o.program_id::text = $1)
			  AND o.source = $3
			  AND o.active = true
			  AND o.http_service_id::text = ANY($4::text[])
			  AND COALESCE(o.last_scan_run_id::text, '') <> $2
			RETURNING o.id, o.program_id, o.http_service_id, o.name, o.version, o.source
		)
		SELECT count(*) FROM stale
	`, strings.TrimSpace(programID), scanRunID, source, cleanIDs).Scan(&count); err != nil {
		return 0, fmt.Errorf("mark missing technology observations inactive: %w", err)
	}
	return count, nil
}

func cleanCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		part = strings.TrimSpace(strings.ToLower(part))
		if part == "" {
			continue
		}
		if _, ok := seen[part]; ok {
			continue
		}
		seen[part] = struct{}{}
		out = append(out, part)
	}
	return out
}
