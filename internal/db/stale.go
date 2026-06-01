package db

import (
	"context"
	"fmt"
)

type StaleResult struct {
	Subdomains   int
	HTTPServices int
	Technologies int
}

func (r *Repository) MarkStaleEntities(ctx context.Context, programID string, staleAfterHours int) (StaleResult, error) {
	if programID == "" || staleAfterHours <= 0 {
		return StaleResult{}, nil
	}
	var result StaleResult
	if err := r.pool.QueryRow(ctx, `
		WITH stale AS (
			UPDATE zero_subdomains
			SET active = false,
				metadata = metadata || jsonb_build_object('stale_marked_at', now(), 'stale_after_hours', $2)
			WHERE program_id = $1::uuid
			  AND active = true
			  AND last_seen_at < now() - make_interval(hours => $2)
			RETURNING id, program_id, fqdn, last_seen_at
		), events AS (
			INSERT INTO zero_change_events(program_id, entity_type, entity_id, entity_key, change_type, old_value, new_value, evidence_hash)
			SELECT program_id, 'subdomain', id, fqdn, 'removed',
				jsonb_build_object('active', true, 'last_seen_at', last_seen_at),
				jsonb_build_object('active', false, 'stale_after_hours', $2),
				encode(digest('stale:subdomain:' || id::text || ':' || $2::text, 'sha256'), 'hex')
			FROM stale
			ON CONFLICT(evidence_hash) DO NOTHING
		)
		SELECT count(*) FROM stale
	`, programID, staleAfterHours).Scan(&result.Subdomains); err != nil {
		return result, fmt.Errorf("mark stale subdomains: %w", err)
	}
	if err := r.pool.QueryRow(ctx, `
		WITH stale AS (
			UPDATE zero_http_services
			SET active = false,
				raw = raw || jsonb_build_object('stale_marked_at', now(), 'stale_after_hours', $2)
			WHERE program_id = $1::uuid
			  AND active = true
			  AND last_seen_at < now() - make_interval(hours => $2)
			RETURNING id, program_id, url, last_seen_at
		), events AS (
			INSERT INTO zero_change_events(program_id, entity_type, entity_id, entity_key, change_type, old_value, new_value, evidence_hash)
			SELECT program_id, 'http_service', id, url, 'removed',
				jsonb_build_object('active', true, 'last_seen_at', last_seen_at),
				jsonb_build_object('active', false, 'stale_after_hours', $2),
				encode(digest('stale:http_service:' || id::text || ':' || $2::text, 'sha256'), 'hex')
			FROM stale
			ON CONFLICT(evidence_hash) DO NOTHING
		)
		SELECT count(*) FROM stale
	`, programID, staleAfterHours).Scan(&result.HTTPServices); err != nil {
		return result, fmt.Errorf("mark stale http services: %w", err)
	}
	if err := r.pool.QueryRow(ctx, `
		WITH stale AS (
			UPDATE zero_technology_observations
			SET active = false,
				evidence = evidence || jsonb_build_object('stale_marked_at', now(), 'stale_after_hours', $2)
			WHERE program_id = $1::uuid
			  AND active = true
			  AND last_seen_at < now() - make_interval(hours => $2)
			RETURNING id, program_id, name, version, source, last_seen_at
		), events AS (
			INSERT INTO zero_change_events(program_id, entity_type, entity_id, entity_key, change_type, old_value, new_value, evidence_hash)
			SELECT program_id, 'technology', id, name || ':' || version || ':' || source, 'removed',
				jsonb_build_object('last_seen_at', last_seen_at),
				jsonb_build_object('active', false, 'stale_after_hours', $2),
				encode(digest('stale:technology:' || id::text || ':' || $2::text, 'sha256'), 'hex')
			FROM stale
			ON CONFLICT(evidence_hash) DO NOTHING
		)
		SELECT count(*) FROM stale
	`, programID, staleAfterHours).Scan(&result.Technologies); err != nil {
		return result, fmt.Errorf("mark stale technologies: %w", err)
	}
	return result, nil
}
