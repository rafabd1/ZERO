package db

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/rafabd1/ZERO/internal/sanitize"
)

func NormalizeTarget(input string) string {
	s := strings.TrimSpace(strings.ToLower(input))
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimSuffix(s, ".")
	s = strings.TrimSuffix(s, "/")
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.Host != "" {
			host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
			if u.Path == "" || u.Path == "/" {
				return host
			}
			return host + strings.TrimRight(u.EscapedPath(), "/")
		}
	}
	return s
}

func (r *Repository) UpsertProgram(ctx context.Context, platform, handle, programURL string, metadata map[string]any) (string, error) {
	meta, _ := json.Marshal(metadata)
	var id string
	err := r.pool.QueryRow(ctx, `
		INSERT INTO zero_programs(platform, handle, program_url, metadata)
		VALUES ($1, $2, $3, $4::jsonb)
		ON CONFLICT(program_url) DO UPDATE SET
			platform = excluded.platform,
			handle = excluded.handle,
			active = true,
			last_seen_at = now(),
			metadata = zero_programs.metadata || excluded.metadata
		RETURNING id
	`, platform, handle, programURL, string(meta)).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("upsert program: %w", err)
	}
	return id, nil
}

func (r *Repository) ListDuePrograms(ctx context.Context, limit int) ([]Program, error) {
	if limit <= 0 {
		limit = 1000
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id::text, platform, handle, program_url, scan_interval_hours
		FROM zero_programs
		WHERE active = true
		  AND (
			last_scan_finished_at IS NULL
			OR last_scan_finished_at <= now() - make_interval(hours => scan_interval_hours)
		  )
		ORDER BY last_scan_finished_at NULLS FIRST, last_seen_at DESC, platform, handle
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	programs := []Program{}
	for rows.Next() {
		var program Program
		if err := rows.Scan(&program.ID, &program.Platform, &program.Handle, &program.ProgramURL, &program.ScanIntervalHours); err != nil {
			return nil, err
		}
		programs = append(programs, program)
	}
	return programs, rows.Err()
}

func (r *Repository) ListProgramsForCampaign(ctx context.Context, dueOnly bool, limit int) ([]Program, error) {
	if limit <= 0 {
		limit = 100000
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id::text, platform, handle, program_url, scan_interval_hours
		FROM zero_programs
		WHERE active = true
		  AND (
			$1 = false
			OR last_scan_finished_at IS NULL
			OR last_scan_finished_at <= now() - make_interval(hours => scan_interval_hours)
		  )
		ORDER BY last_scan_finished_at NULLS FIRST, last_seen_at DESC, platform, handle
		LIMIT $2
	`, dueOnly, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	programs := []Program{}
	for rows.Next() {
		var program Program
		if err := rows.Scan(&program.ID, &program.Platform, &program.Handle, &program.ProgramURL, &program.ScanIntervalHours); err != nil {
			return nil, err
		}
		programs = append(programs, program)
	}
	return programs, rows.Err()
}

func (r *Repository) MarkProgramScanStarted(ctx context.Context, programID string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE zero_programs
		SET last_scan_started_at = now()
		WHERE id = $1::uuid
	`, programID)
	if err != nil {
		return fmt.Errorf("mark program scan started: %w", err)
	}
	return nil
}

func (r *Repository) MarkProgramScanFinished(ctx context.Context, programID string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE zero_programs
		SET last_scan_finished_at = now()
		WHERE id = $1::uuid
	`, programID)
	if err != nil {
		return fmt.Errorf("mark program scan finished: %w", err)
	}
	return nil
}

func (r *Repository) UpsertScopeAsset(ctx context.Context, asset ScopeAsset) (string, error) {
	if asset.Source == "" {
		asset.Source = "bbscope"
	}
	meta, _ := json.Marshal(asset.Metadata)
	var id string
	var inserted bool
	err := r.pool.QueryRow(ctx, `
		INSERT INTO zero_scope_assets(
			program_id, last_scan_run_id, platform, handle, asset_type, target_raw, target_normalized,
			description, in_scope, eligible_for_bounty, source, metadata
		)
		VALUES ($1,NULLIF($2, '')::uuid,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb)
		ON CONFLICT(program_id, asset_type, target_normalized, in_scope) DO UPDATE SET
			last_scan_run_id = COALESCE(excluded.last_scan_run_id, zero_scope_assets.last_scan_run_id),
			target_raw = excluded.target_raw,
			description = excluded.description,
			eligible_for_bounty = excluded.eligible_for_bounty,
			active = true,
			last_seen_at = now(),
			metadata = zero_scope_assets.metadata || excluded.metadata
		RETURNING id, (xmax = 0) AS inserted
	`, asset.ProgramID, asset.LastScanRunID, asset.Platform, asset.Handle, asset.AssetType, asset.TargetRaw, asset.TargetNormalized,
		asset.Description, asset.InScope, asset.EligibleForBounty, asset.Source, string(meta)).Scan(&id, &inserted)
	if err != nil {
		return "", fmt.Errorf("upsert scope asset: %w", err)
	}
	if inserted {
		if err := r.RecordChangeEvent(ctx, ChangeEvent{
			ProgramID:  asset.ProgramID,
			ScanRunID:  asset.LastScanRunID,
			EntityType: "scope_asset",
			EntityID:   id,
			EntityKey:  asset.AssetType + ":" + asset.TargetNormalized + ":" + fmt.Sprint(asset.InScope),
			ChangeType: "added",
			NewValue: map[string]any{
				"asset_type":          asset.AssetType,
				"target_normalized":   asset.TargetNormalized,
				"in_scope":            asset.InScope,
				"eligible_for_bounty": asset.EligibleForBounty,
				"source":              asset.Source,
			},
		}); err != nil {
			return "", err
		}
	}
	return id, nil
}

func (r *Repository) UpsertScopeAssets(ctx context.Context, assets []ScopeAsset) (int, error) {
	if len(assets) == 0 {
		return 0, nil
	}

	batch := &pgx.Batch{}
	for _, asset := range assets {
		if asset.Source == "" {
			asset.Source = "bbscope"
		}
		meta, _ := json.Marshal(asset.Metadata)
		batch.Queue(`
			INSERT INTO zero_scope_assets(
				program_id, last_scan_run_id, platform, handle, asset_type, target_raw, target_normalized,
				description, in_scope, eligible_for_bounty, source, metadata
			)
			VALUES ($1,NULLIF($2, '')::uuid,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb)
			ON CONFLICT(program_id, asset_type, target_normalized, in_scope) DO UPDATE SET
				last_scan_run_id = COALESCE(excluded.last_scan_run_id, zero_scope_assets.last_scan_run_id),
				target_raw = excluded.target_raw,
				description = excluded.description,
				eligible_for_bounty = excluded.eligible_for_bounty,
				active = true,
				last_seen_at = now(),
				metadata = zero_scope_assets.metadata || excluded.metadata
			RETURNING id::text, (xmax = 0) AS inserted
		`, asset.ProgramID, asset.LastScanRunID, asset.Platform, asset.Handle, asset.AssetType, asset.TargetRaw, asset.TargetNormalized,
			asset.Description, asset.InScope, asset.EligibleForBounty, asset.Source, string(meta))
	}

	results := r.pool.SendBatch(ctx, batch)

	events := make([]ChangeEvent, 0)
	for i, asset := range assets {
		var id string
		var inserted bool
		if err := results.QueryRow().Scan(&id, &inserted); err != nil {
			return 0, fmt.Errorf("batch upsert scope assets: %w", err)
		}
		if inserted {
			events = append(events, ChangeEvent{
				ProgramID:  asset.ProgramID,
				ScanRunID:  asset.LastScanRunID,
				EntityType: "scope_asset",
				EntityID:   id,
				EntityKey:  asset.AssetType + ":" + asset.TargetNormalized + ":" + fmt.Sprint(asset.InScope),
				ChangeType: "added",
				NewValue: map[string]any{
					"asset_type":          asset.AssetType,
					"target_normalized":   asset.TargetNormalized,
					"in_scope":            asset.InScope,
					"eligible_for_bounty": asset.EligibleForBounty,
					"source":              asset.Source,
					"batch_index":         i,
				},
			})
		}
	}
	if err := results.Close(); err != nil {
		return 0, fmt.Errorf("batch upsert scope assets: %w", err)
	}
	if err := r.RecordChangeEvents(ctx, events); err != nil {
		return 0, err
	}
	return len(assets), nil
}

func (r *Repository) MarkScopeAssetsOutsideCategoriesInactive(ctx context.Context, programID string, allowedCategories []string) (int, error) {
	if len(allowedCategories) == 0 {
		return 0, nil
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE zero_scope_assets
		SET active = false,
		    metadata = metadata || jsonb_build_object('deactivated_at', now(), 'deactivated_reason', 'category_filter')
		WHERE program_id = $1::uuid
		  AND active = true
		  AND NOT (asset_type = ANY($2::text[]))
	`, programID, allowedCategories)
	if err != nil {
		return 0, fmt.Errorf("mark scope assets outside categories inactive: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

func (r *Repository) ListDomainRoots(ctx context.Context, programID string) ([]DomainRoot, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, program_id, asset_type, target_raw, target_normalized
		FROM zero_scope_assets
		WHERE active = true
		  AND in_scope = true
		  AND eligible_for_bounty = true
		  AND asset_type IN ('domain', 'url', 'wildcard')
		  AND ($1 = '' OR program_id::text = $1)
		ORDER BY program_id, target_normalized
	`, programID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var assets []domainRootAsset
	for rows.Next() {
		var asset domainRootAsset
		if err := rows.Scan(&asset.ScopeAssetID, &asset.ProgramID, &asset.AssetType, &asset.TargetRaw, &asset.TargetNormalized); err != nil {
			return nil, err
		}
		assets = append(assets, asset)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return buildDomainRootsFromAssets(assets), nil
}

type domainRootAsset struct {
	ScopeAssetID     string
	ProgramID        string
	AssetType        string
	TargetRaw        string
	TargetNormalized string
}

func buildDomainRootsFromAssets(assets []domainRootAsset) []DomainRoot {
	authorizedRoots := map[string]bool{}
	type wildcardCandidate struct {
		scopeAssetID string
		programID    string
		scopeRoot    string
		queryRoot    string
	}
	candidates := []wildcardCandidate{}

	for _, asset := range assets {
		switch asset.AssetType {
		case "wildcard":
			scopeRoot, ok := wildcardRootFromAsset(asset)
			if !ok {
				continue
			}
			queryRoot, ok := sanitize.RegisteredDomain(scopeRoot)
			if !ok {
				continue
			}
			if scopeRoot == queryRoot {
				authorizedRoots[rootAuthKey(asset.ProgramID, queryRoot)] = true
			}
			candidates = append(candidates, wildcardCandidate{
				scopeAssetID: asset.ScopeAssetID,
				programID:    asset.ProgramID,
				scopeRoot:    scopeRoot,
				queryRoot:    queryRoot,
			})
		case "domain", "url":
			host, ok := sanitize.DomainFromScopeTarget(firstNonEmpty(asset.TargetRaw, asset.TargetNormalized))
			if !ok {
				continue
			}
			queryRoot, ok := sanitize.RegisteredDomain(host)
			if ok && host == queryRoot {
				authorizedRoots[rootAuthKey(asset.ProgramID, queryRoot)] = true
			}
		}
	}

	roots := []DomainRoot{}
	seen := map[string]bool{}
	for _, candidate := range candidates {
		if !authorizedRoots[rootAuthKey(candidate.programID, candidate.queryRoot)] {
			continue
		}
		if _, ok := sanitize.WildcardRegex(candidate.scopeRoot); !ok {
			continue
		}
		key := candidate.programID + "\x00" + candidate.scopeRoot + "\x00" + candidate.queryRoot
		if seen[key] {
			continue
		}
		seen[key] = true
		roots = append(roots, DomainRoot{
			ScopeAssetID: candidate.scopeAssetID,
			ProgramID:    candidate.programID,
			RootDomain:   candidate.scopeRoot,
			QueryDomain:  candidate.queryRoot,
		})
	}
	return roots
}

func wildcardRootFromAsset(asset domainRootAsset) (string, bool) {
	root, ok := sanitize.WildcardRootFromScopeTarget(asset.TargetRaw)
	if !ok {
		root, ok = sanitize.WildcardRootFromScopeTarget(asset.TargetNormalized)
	}
	return root, ok
}

func rootAuthKey(programID, root string) string {
	return programID + "\x00" + root
}

func (r *Repository) UpsertSubdomain(ctx context.Context, sub Subdomain) (string, error) {
	var id string
	var inserted bool
	err := r.pool.QueryRow(ctx, `
		INSERT INTO zero_subdomains(program_id, scope_asset_id, last_scan_run_id, root_domain, fqdn, source)
		VALUES ($1,$2,NULLIF($3, '')::uuid,$4,$5,$6)
		ON CONFLICT(program_id, fqdn) DO UPDATE SET
			scope_asset_id = COALESCE(excluded.scope_asset_id, zero_subdomains.scope_asset_id),
			last_scan_run_id = COALESCE(excluded.last_scan_run_id, zero_subdomains.last_scan_run_id),
			root_domain = excluded.root_domain,
			source = excluded.source,
			active = true,
			last_seen_at = now()
		RETURNING id, (xmax = 0) AS inserted
	`, sub.ProgramID, nullString(sub.ScopeAssetID), sub.LastScanRunID, sub.RootDomain, sub.FQDN, sub.Source).Scan(&id, &inserted)
	if err != nil {
		return "", fmt.Errorf("upsert subdomain: %w", err)
	}
	if inserted {
		if err := r.RecordChangeEvent(ctx, ChangeEvent{
			ProgramID:  sub.ProgramID,
			ScanRunID:  sub.LastScanRunID,
			EntityType: "subdomain",
			EntityID:   id,
			EntityKey:  sub.FQDN,
			ChangeType: "added",
			NewValue: map[string]any{
				"root_domain": sub.RootDomain,
				"fqdn":        sub.FQDN,
				"source":      sub.Source,
			},
		}); err != nil {
			return "", err
		}
	}
	return id, nil
}

func (r *Repository) UpsertSubdomains(ctx context.Context, subs []Subdomain) (int, error) {
	if len(subs) == 0 {
		return 0, nil
	}
	batch := &pgx.Batch{}
	for _, sub := range subs {
		batch.Queue(`
			INSERT INTO zero_subdomains(program_id, scope_asset_id, last_scan_run_id, root_domain, fqdn, source)
			VALUES ($1,$2,NULLIF($3, '')::uuid,$4,$5,$6)
			ON CONFLICT(program_id, fqdn) DO UPDATE SET
				scope_asset_id = COALESCE(excluded.scope_asset_id, zero_subdomains.scope_asset_id),
				last_scan_run_id = COALESCE(excluded.last_scan_run_id, zero_subdomains.last_scan_run_id),
				root_domain = excluded.root_domain,
				source = excluded.source,
				active = true,
				last_seen_at = now()
			RETURNING id::text, (xmax = 0) AS inserted
		`, sub.ProgramID, nullString(sub.ScopeAssetID), sub.LastScanRunID, sub.RootDomain, sub.FQDN, sub.Source)
	}
	results := r.pool.SendBatch(ctx, batch)
	events := make([]ChangeEvent, 0)
	for _, sub := range subs {
		var id string
		var inserted bool
		if err := results.QueryRow().Scan(&id, &inserted); err != nil {
			return 0, fmt.Errorf("batch upsert subdomains: %w", err)
		}
		if inserted {
			events = append(events, ChangeEvent{
				ProgramID:  sub.ProgramID,
				ScanRunID:  sub.LastScanRunID,
				EntityType: "subdomain",
				EntityID:   id,
				EntityKey:  sub.FQDN,
				ChangeType: "added",
				NewValue: map[string]any{
					"root_domain": sub.RootDomain,
					"fqdn":        sub.FQDN,
					"source":      sub.Source,
				},
			})
		}
	}
	if err := results.Close(); err != nil {
		return 0, fmt.Errorf("batch upsert subdomains: %w", err)
	}
	if err := r.RecordChangeEvents(ctx, events); err != nil {
		return 0, err
	}
	return len(subs), nil
}

func (r *Repository) ListInScopeSubdomainAssets(ctx context.Context, programID string) ([]Subdomain, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, program_id, asset_type, target_raw, target_normalized
		FROM zero_scope_assets
		WHERE active = true
		  AND in_scope = true
		  AND eligible_for_bounty = true
		  AND asset_type IN ('domain', 'url')
		  AND ($1 = '' OR program_id::text = $1)
		ORDER BY program_id, target_normalized
	`, programID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	subs := []Subdomain{}
	seen := map[string]bool{}
	for rows.Next() {
		var assetID, programID, assetType, raw, normalized string
		if err := rows.Scan(&assetID, &programID, &assetType, &raw, &normalized); err != nil {
			return nil, err
		}
		host, root, ok := scopedSubdomainFromTarget(firstNonEmpty(raw, normalized))
		if !ok {
			continue
		}
		key := programID + "\x00" + host
		if seen[key] {
			continue
		}
		seen[key] = true
		subs = append(subs, Subdomain{
			ProgramID:    programID,
			ScopeAssetID: assetID,
			RootDomain:   root,
			FQDN:         host,
			Source:       "scope:" + assetType,
		})
	}
	return subs, rows.Err()
}

func scopedSubdomainFromTarget(raw string) (string, string, bool) {
	host, ok := scopedSubdomainHost(raw)
	if !ok {
		return "", "", false
	}
	root, ok := sanitize.RegisteredDomain(host)
	if !ok {
		return "", "", false
	}
	return host, root, true
}

func scopedSubdomainHost(raw string) (string, bool) {
	host, ok := sanitize.DomainFromScopeTarget(raw)
	if !ok {
		return "", false
	}
	root, ok := sanitize.RegisteredDomain(host)
	if !ok || host == root {
		return "", false
	}
	return host, true
}

func (r *Repository) ListDNSValidationTargets(ctx context.Context, programID string, limit int) ([]Subdomain, error) {
	if limit <= 0 {
		limit = 100000
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id::text, program_id::text, COALESCE(scope_asset_id::text, ''), root_domain, fqdn, source
		FROM zero_subdomains
		WHERE active = true
		  AND ($1 = '' OR program_id::text = $1)
		ORDER BY last_seen_at DESC, fqdn
		LIMIT $2
	`, programID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	targets := []Subdomain{}
	for rows.Next() {
		var target Subdomain
		if err := rows.Scan(&target.ID, &target.ProgramID, &target.ScopeAssetID, &target.RootDomain, &target.FQDN, &target.Source); err != nil {
			return nil, err
		}
		targets = append(targets, target)
	}
	return targets, rows.Err()
}

func (r *Repository) UpdateSubdomainResolution(ctx context.Context, programID string, resolved map[string]bool, scanRunID string) (int, error) {
	if len(resolved) == 0 {
		return 0, nil
	}
	batch := &pgx.Batch{}
	for fqdn, ok := range resolved {
		batch.Queue(`
			UPDATE zero_subdomains
			SET resolves = $3,
				last_scan_run_id = COALESCE(NULLIF($4, '')::uuid, last_scan_run_id),
				last_seen_at = CASE WHEN $3 THEN now() ELSE last_seen_at END,
				metadata = metadata || jsonb_build_object('last_dns_validation_at', now())
			WHERE program_id = $1::uuid
			  AND fqdn = $2
		`, programID, fqdn, ok, scanRunID)
	}
	results := r.pool.SendBatch(ctx, batch)
	updated := 0
	for range resolved {
		tag, err := results.Exec()
		if err != nil {
			return updated, fmt.Errorf("update subdomain resolution: %w", err)
		}
		updated += int(tag.RowsAffected())
	}
	if err := results.Close(); err != nil {
		return updated, fmt.Errorf("update subdomain resolution: %w", err)
	}
	return updated, nil
}

func (r *Repository) ListSubdomains(ctx context.Context) ([]Subdomain, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, program_id, COALESCE(scope_asset_id::text, ''), root_domain, fqdn, source
		FROM zero_subdomains
		WHERE active = true
		ORDER BY fqdn
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var subs []Subdomain
	for rows.Next() {
		var sub Subdomain
		if err := rows.Scan(&sub.ID, &sub.ProgramID, &sub.ScopeAssetID, &sub.RootDomain, &sub.FQDN, &sub.Source); err != nil {
			return nil, err
		}
		subs = append(subs, sub)
	}
	return subs, rows.Err()
}

func (r *Repository) ListOutOfScopeDomainRules(ctx context.Context, programID string) ([]DomainScopeRule, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, program_id, asset_type, target_raw, target_normalized
		FROM zero_scope_assets
		WHERE active = true
		  AND in_scope = false
		  AND asset_type IN ('domain', 'url', 'wildcard')
		  AND ($1 = '' OR program_id::text = $1)
		ORDER BY target_normalized
	`, programID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	rules := []DomainScopeRule{}
	for rows.Next() {
		var rule DomainScopeRule
		var assetType, raw, normalized string
		if err := rows.Scan(&rule.ScopeAssetID, &rule.ProgramID, &assetType, &raw, &normalized); err != nil {
			return nil, err
		}
		host, ok := sanitize.DomainFromScopeTarget(firstNonEmpty(raw, normalized))
		if !ok {
			continue
		}
		rule.Host = host
		if assetType == "wildcard" {
			rule.MatchMode = ProbeMatchWildcard
		} else {
			rule.MatchMode = ProbeMatchExact
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

func (r *Repository) ListProbeTargets(ctx context.Context, programID string) ([]ProbeTarget, error) {
	targets := []ProbeTarget{}
	seen := map[string]bool{}
	exclusions, err := r.ListOutOfScopeDomainRules(ctx, programID)
	if err != nil {
		return nil, err
	}

	wildcardRows, err := r.pool.Query(ctx, `
		SELECT
			s.id,
			s.program_id,
			COALESCE(s.scope_asset_id::text, ''),
			COALESCE(a.target_raw, ''),
			COALESCE(a.target_normalized, ''),
			s.root_domain,
			s.fqdn,
			s.source
		FROM zero_subdomains s
		JOIN zero_scope_assets a ON a.id = s.scope_asset_id
		WHERE s.active = true
		  AND a.active = true
		  AND a.in_scope = true
		  AND a.eligible_for_bounty = true
		  AND a.asset_type = 'wildcard'
		  AND COALESCE(s.resolves, true) = true
		  AND ($1 = '' OR s.program_id::text = $1)
		ORDER BY s.fqdn
	`, programID)
	if err != nil {
		return nil, err
	}
	defer wildcardRows.Close()

	for wildcardRows.Next() {
		var target ProbeTarget
		var raw, normalized, storedRoot string
		if err := wildcardRows.Scan(
			&target.SubdomainID,
			&target.ProgramID,
			&target.ScopeAssetID,
			&raw,
			&normalized,
			&storedRoot,
			&target.FQDN,
			&target.Source,
		); err != nil {
			return nil, err
		}
		root, ok := sanitize.DomainFromScopeTarget(firstNonEmpty(raw, normalized, storedRoot))
		if !ok {
			continue
		}
		fqdn, ok := sanitize.CanonicalDomain(target.FQDN)
		if !ok || !sanitize.MatchesWildcard(fqdn, root) || domainExcluded(exclusions, target.ProgramID, fqdn) {
			continue
		}
		target.RootDomain = root
		target.FQDN = fqdn
		target.MatchMode = ProbeMatchWildcard
		addProbeTarget(&targets, seen, target)
	}
	if err := wildcardRows.Err(); err != nil {
		return nil, err
	}

	exactRows, err := r.pool.Query(ctx, `
		SELECT id, program_id, asset_type, target_raw, target_normalized
		FROM zero_scope_assets
		WHERE active = true
		  AND in_scope = true
		  AND eligible_for_bounty = true
		  AND asset_type IN ('domain', 'url')
		  AND ($1 = '' OR program_id::text = $1)
		ORDER BY target_normalized
	`, programID)
	if err != nil {
		return nil, err
	}
	defer exactRows.Close()

	for exactRows.Next() {
		var assetID, programID, assetType, raw, normalized string
		if err := exactRows.Scan(&assetID, &programID, &assetType, &raw, &normalized); err != nil {
			return nil, err
		}
		host, ok := sanitize.DomainFromScopeTarget(firstNonEmpty(raw, normalized))
		if !ok || domainExcluded(exclusions, programID, host) {
			continue
		}
		addProbeTarget(&targets, seen, ProbeTarget{
			ProgramID:    programID,
			ScopeAssetID: assetID,
			RootDomain:   host,
			FQDN:         host,
			Source:       "scope:" + assetType,
			MatchMode:    ProbeMatchExact,
		})
	}
	if err := exactRows.Err(); err != nil {
		return nil, err
	}

	return targets, nil
}

func (r *Repository) UpsertHTTPService(ctx context.Context, service HTTPService) (string, error) {
	tech, _ := json.Marshal(service.Technologies)
	if len(service.TLS) == 0 {
		service.TLS = json.RawMessage(`{}`)
	}
	if len(service.Raw) == 0 {
		service.Raw = json.RawMessage(`{}`)
	}

	var id string
	var inserted bool
	err := r.pool.QueryRow(ctx, `
		INSERT INTO zero_http_services(
			program_id, subdomain_id, url, scheme, host, port, status_code, title, webserver,
			technologies, favicon_hash, tls, raw, last_scan_run_id
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12::jsonb,$13::jsonb,NULLIF($14, '')::uuid)
		ON CONFLICT(program_id, url) DO UPDATE SET
			subdomain_id = COALESCE(excluded.subdomain_id, zero_http_services.subdomain_id),
			last_scan_run_id = COALESCE(excluded.last_scan_run_id, zero_http_services.last_scan_run_id),
			scheme = excluded.scheme,
			host = excluded.host,
			port = excluded.port,
			status_code = excluded.status_code,
			title = excluded.title,
			webserver = excluded.webserver,
			technologies = excluded.technologies,
			favicon_hash = excluded.favicon_hash,
			tls = excluded.tls,
			raw = excluded.raw,
			active = true,
			last_seen_at = now()
		RETURNING id, (xmax = 0) AS inserted
	`, service.ProgramID, nullString(service.SubdomainID), service.URL, service.Scheme, service.Host, service.Port, service.StatusCode,
		service.Title, service.Webserver, string(tech), service.FaviconHash, string(service.TLS), string(service.Raw), service.LastScanRunID).Scan(&id, &inserted)
	if err != nil {
		return "", fmt.Errorf("upsert http service: %w", err)
	}
	if inserted {
		if err := r.RecordChangeEvent(ctx, ChangeEvent{
			ProgramID:  service.ProgramID,
			ScanRunID:  service.LastScanRunID,
			EntityType: "http_service",
			EntityID:   id,
			EntityKey:  service.URL,
			ChangeType: "added",
			NewValue: map[string]any{
				"url":           service.URL,
				"host":          service.Host,
				"status_code":   service.StatusCode,
				"title":         service.Title,
				"webserver":     service.Webserver,
				"technologies":  service.Technologies,
				"favicon_hash":  service.FaviconHash,
				"subdomain_id":  service.SubdomainID,
				"probe_version": "httpx",
			},
		}); err != nil {
			return "", err
		}
	}

	for _, name := range service.Technologies {
		if strings.TrimSpace(name) == "" {
			continue
		}
		_, _, err := r.UpsertTechnologyObservation(ctx, TechnologyObservation{
			ProgramID:     service.ProgramID,
			HTTPServiceID: id,
			LastScanRunID: service.LastScanRunID,
			Name:          name,
			Source:        "httpx",
			Confidence:    60,
			Evidence: map[string]any{
				"url": service.URL,
			},
		})
		if err != nil {
			return "", fmt.Errorf("upsert technology observation: %w", err)
		}
	}
	if strings.TrimSpace(service.LastScanRunID) != "" {
		if _, err := r.MarkMissingTechnologyObservationsInactive(ctx, service.ProgramID, service.LastScanRunID, "httpx", []string{id}); err != nil {
			return "", err
		}
	}

	return id, nil
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func addProbeTarget(targets *[]ProbeTarget, seen map[string]bool, target ProbeTarget) {
	key := target.ProgramID + "\x00" + target.MatchMode + "\x00" + target.FQDN + "\x00" + target.ScopeAssetID
	if seen[key] {
		return
	}
	seen[key] = true
	*targets = append(*targets, target)
}

func domainExcluded(rules []DomainScopeRule, programID, host string) bool {
	for _, rule := range rules {
		if rule.ProgramID != programID {
			continue
		}
		switch rule.MatchMode {
		case ProbeMatchWildcard:
			if sanitize.MatchesWildcard(host, rule.Host) {
				return true
			}
		case ProbeMatchExact:
			if host == rule.Host {
				return true
			}
		}
	}
	return false
}
