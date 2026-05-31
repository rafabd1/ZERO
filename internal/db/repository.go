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

func (r *Repository) UpsertScopeAsset(ctx context.Context, asset ScopeAsset) (string, error) {
	if asset.Source == "" {
		asset.Source = "bbscope"
	}
	meta, _ := json.Marshal(asset.Metadata)
	var id string
	err := r.pool.QueryRow(ctx, `
		INSERT INTO zero_scope_assets(
			program_id, platform, handle, asset_type, target_raw, target_normalized,
			description, in_scope, eligible_for_bounty, source, metadata
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb)
		ON CONFLICT(program_id, asset_type, target_normalized, in_scope) DO UPDATE SET
			target_raw = excluded.target_raw,
			description = excluded.description,
			eligible_for_bounty = excluded.eligible_for_bounty,
			active = true,
			last_seen_at = now(),
			metadata = zero_scope_assets.metadata || excluded.metadata
		RETURNING id
	`, asset.ProgramID, asset.Platform, asset.Handle, asset.AssetType, asset.TargetRaw, asset.TargetNormalized,
		asset.Description, asset.InScope, asset.EligibleForBounty, asset.Source, string(meta)).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("upsert scope asset: %w", err)
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
				program_id, platform, handle, asset_type, target_raw, target_normalized,
				description, in_scope, eligible_for_bounty, source, metadata
			)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb)
			ON CONFLICT(program_id, asset_type, target_normalized, in_scope) DO UPDATE SET
				target_raw = excluded.target_raw,
				description = excluded.description,
				eligible_for_bounty = excluded.eligible_for_bounty,
				active = true,
				last_seen_at = now(),
				metadata = zero_scope_assets.metadata || excluded.metadata
		`, asset.ProgramID, asset.Platform, asset.Handle, asset.AssetType, asset.TargetRaw, asset.TargetNormalized,
			asset.Description, asset.InScope, asset.EligibleForBounty, asset.Source, string(meta))
	}

	results := r.pool.SendBatch(ctx, batch)
	defer results.Close()

	for range assets {
		if _, err := results.Exec(); err != nil {
			return 0, fmt.Errorf("batch upsert scope assets: %w", err)
		}
	}
	return len(assets), nil
}

func (r *Repository) ListDomainRoots(ctx context.Context) ([]DomainRoot, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, program_id, target_normalized
		FROM zero_scope_assets
		WHERE active = true
		  AND in_scope = true
		  AND asset_type IN ('domain', 'wildcard', 'url')
		  AND target_normalized NOT LIKE '%/%'
		ORDER BY target_normalized
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roots []DomainRoot
	for rows.Next() {
		var root DomainRoot
		if err := rows.Scan(&root.ScopeAssetID, &root.ProgramID, &root.RootDomain); err != nil {
			return nil, err
		}
		domain, ok := sanitize.DomainFromScopeTarget(root.RootDomain)
		if !ok {
			continue
		}
		root.RootDomain = domain
		roots = append(roots, root)
	}
	return roots, rows.Err()
}

func (r *Repository) UpsertSubdomain(ctx context.Context, sub Subdomain) (string, error) {
	var id string
	err := r.pool.QueryRow(ctx, `
		INSERT INTO zero_subdomains(program_id, scope_asset_id, root_domain, fqdn, source)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT(program_id, fqdn) DO UPDATE SET
			scope_asset_id = COALESCE(excluded.scope_asset_id, zero_subdomains.scope_asset_id),
			root_domain = excluded.root_domain,
			source = excluded.source,
			active = true,
			last_seen_at = now()
		RETURNING id
	`, sub.ProgramID, nullString(sub.ScopeAssetID), sub.RootDomain, sub.FQDN, sub.Source).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("upsert subdomain: %w", err)
	}
	return id, nil
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

func (r *Repository) UpsertHTTPService(ctx context.Context, service HTTPService) (string, error) {
	tech, _ := json.Marshal(service.Technologies)
	if len(service.TLS) == 0 {
		service.TLS = json.RawMessage(`{}`)
	}
	if len(service.Raw) == 0 {
		service.Raw = json.RawMessage(`{}`)
	}

	var id string
	err := r.pool.QueryRow(ctx, `
		INSERT INTO zero_http_services(
			program_id, subdomain_id, url, scheme, host, port, status_code, title, webserver,
			technologies, favicon_hash, tls, raw
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12::jsonb,$13::jsonb)
		ON CONFLICT(program_id, url) DO UPDATE SET
			subdomain_id = COALESCE(excluded.subdomain_id, zero_http_services.subdomain_id),
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
		RETURNING id
	`, service.ProgramID, nullString(service.SubdomainID), service.URL, service.Scheme, service.Host, service.Port, service.StatusCode,
		service.Title, service.Webserver, string(tech), service.FaviconHash, string(service.TLS), string(service.Raw)).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("upsert http service: %w", err)
	}

	for _, name := range service.Technologies {
		if strings.TrimSpace(name) == "" {
			continue
		}
		_, err := r.pool.Exec(ctx, `
			INSERT INTO zero_technology_observations(program_id, http_service_id, name, source, confidence, evidence)
			VALUES ($1,$2,$3,'httpx',60,jsonb_build_object('url',$4::text))
			ON CONFLICT(http_service_id, lower(name), version, source) DO UPDATE SET
				last_seen_at = now(),
				confidence = GREATEST(zero_technology_observations.confidence, excluded.confidence),
				evidence = zero_technology_observations.evidence || excluded.evidence
		`, service.ProgramID, id, name, service.URL)
		if err != nil {
			return "", fmt.Errorf("upsert technology observation: %w", err)
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
