package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rafabd1/ZERO/internal/db"
)

type Server struct {
	repo    *db.Repository
	token   string
	mux     *http.ServeMux
	cacheMu sync.Mutex
	cache   map[string]cachedJSON
}

type cachedJSON struct {
	body    json.RawMessage
	expires time.Time
}

func NewServer(repo *db.Repository, token string) *Server {
	s := &Server{
		repo:  repo,
		token: token,
		mux:   http.NewServeMux(),
		cache: map[string]cachedJSON{},
	}
	s.routes()
	s.recoverStagingScanCampaigns()
	return s
}

func (s *Server) ListenAndServe(addr string) error {
	return http.ListenAndServe(addr, s)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/healthz" && s.token != "" {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if got == "" || got != s.token {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
	}
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
	s.mux.HandleFunc("GET /v1/programs", s.programs)
	s.mux.HandleFunc("GET /v1/assets", s.scopeAssets(""))
	s.mux.HandleFunc("GET /v1/scope-assets", s.scopeAssets(""))
	s.mux.HandleFunc("GET /v1/subdomains", s.subdomains(""))
	s.mux.HandleFunc("GET /v1/services", s.services(""))
	s.mux.HandleFunc("GET /v1/technologies", s.technologies(""))
	s.mux.HandleFunc("GET /v1/technology-vulnerabilities", s.technologyVulnerabilities(""))
	s.mux.HandleFunc("GET /v1/vulnerabilities", s.vulnerabilityRecords)
	s.mux.HandleFunc("GET /v1/nuclei-results", s.nucleiResults(""))
	s.mux.HandleFunc("GET /v1/findings", s.findings(""))
	s.mux.HandleFunc("GET /v1/reports", s.reports(""))
	s.mux.HandleFunc("GET /v1/scan-runs", s.scanRuns)
	s.mux.HandleFunc("GET /v1/inventory/overview", s.inventoryOverview)
	s.mux.HandleFunc("GET /v1/stats", s.globalStats)
	s.mux.HandleFunc("GET /v1/reports/latest", s.query(`
		SELECT jsonb_build_object(
			'id', r.id,
			'program_id', r.program_id,
			'scan_run_id', r.scan_run_id,
			'report_key', r.report_key,
			'title', r.title,
			'severity', r.severity,
			'confidence', r.confidence,
			'body_markdown', r.body_markdown,
			'finding_ids', r.finding_ids,
			'created_at', r.created_at,
			'metadata', r.metadata
		)
		FROM zero_reports r
		ORDER BY r.created_at DESC
		LIMIT 50
	`))
	s.mux.HandleFunc("GET /v1/default-scans", s.defaultScans)
	s.mux.HandleFunc("GET /v1/default-scans/{cycle_id}", s.defaultScanDetail)
	s.mux.HandleFunc("GET /v1/scans/latest", s.latestScans)
	s.mux.HandleFunc("GET /v1/scans/{scan_id}", s.scanDetail)
	s.mux.HandleFunc("GET /v1/scan-requests", s.scanRequests)
	s.mux.HandleFunc("GET /v1/scan-campaigns", s.scanCampaigns)
	s.mux.HandleFunc("GET /v1/scan-campaigns/{campaign_id}", s.scanCampaignDetail)
	s.mux.HandleFunc("POST /v1/scan-requests", s.createScanRequest)
	s.mux.HandleFunc("POST /v1/scan-requests/{request_id}/cancel", s.cancelScanRequest)
	s.mux.HandleFunc("DELETE /v1/scan-requests/{request_id}", s.cancelScanRequest)
	s.mux.HandleFunc("POST /v1/scan-campaigns/{campaign_id}/cancel", s.cancelScanCampaign)
	s.mux.HandleFunc("DELETE /v1/scan-campaigns/{campaign_id}", s.cancelScanCampaign)
	s.mux.HandleFunc("GET /v1/changes", s.changes(""))
	s.mux.HandleFunc("GET /v1/notifications/discord", s.query(`
		SELECT jsonb_build_object(
			'id', n.id,
			'program_id', n.program_id,
			'report_id', n.report_id,
			'finding_id', n.finding_id,
			'dedupe_key', n.dedupe_key,
			'status', n.status,
			'error', n.error,
			'created_at', n.created_at,
			'sent_at', n.sent_at
		)
		FROM zero_discord_notifications n
		ORDER BY n.created_at DESC
		LIMIT 100
	`))
	s.mux.HandleFunc("GET /v1/programs/{program_id}/latest-scan", func(w http.ResponseWriter, r *http.Request) {
		programID := r.PathValue("program_id")
		rows, err := s.repo.QueryJSONRows(r.Context(), `
			SELECT jsonb_build_object(
				'id', sr.id,
				'program_id', sr.program_id,
				'run_type', sr.run_type,
				'status', sr.status,
				'started_at', sr.started_at,
				'finished_at', sr.finished_at,
				'input_count', sr.input_count,
				'inserted_count', sr.inserted_count,
				'updated_count', sr.updated_count,
				'unchanged_count', sr.unchanged_count,
				'error', sr.error,
				'stats', sr.stats
			)
			FROM zero_scan_runs sr
			WHERE sr.program_id = $1::uuid
			  AND sr.run_type = 'full'
			ORDER BY sr.started_at DESC
			LIMIT 1
		`, programID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if len(rows) == 0 {
			writeError(w, http.StatusNotFound, "latest scan not found")
			return
		}
		writeRawJSON(w, rows[0])
	})
	s.mux.HandleFunc("GET /v1/programs/{program_id}/stats", s.programStats)
	s.mux.HandleFunc("GET /v1/programs/{program_id}/changes", func(w http.ResponseWriter, r *http.Request) {
		s.changes(r.PathValue("program_id"))(w, r)
	})
	s.mux.HandleFunc("GET /v1/programs/{program_id}/assets", func(w http.ResponseWriter, r *http.Request) {
		s.scopeAssets(r.PathValue("program_id"))(w, r)
	})
	s.mux.HandleFunc("GET /v1/programs/{program_id}/subdomains", func(w http.ResponseWriter, r *http.Request) {
		s.subdomains(r.PathValue("program_id"))(w, r)
	})
	s.mux.HandleFunc("GET /v1/programs/{program_id}/services", func(w http.ResponseWriter, r *http.Request) {
		s.services(r.PathValue("program_id"))(w, r)
	})
	s.mux.HandleFunc("GET /v1/programs/{program_id}/technologies", func(w http.ResponseWriter, r *http.Request) {
		s.technologies(r.PathValue("program_id"))(w, r)
	})
	s.mux.HandleFunc("GET /v1/programs/{program_id}/technology-vulnerabilities", func(w http.ResponseWriter, r *http.Request) {
		s.technologyVulnerabilities(r.PathValue("program_id"))(w, r)
	})
	s.mux.HandleFunc("GET /v1/programs/{program_id}/nuclei-results", func(w http.ResponseWriter, r *http.Request) {
		s.nucleiResults(r.PathValue("program_id"))(w, r)
	})
	s.mux.HandleFunc("GET /v1/programs/{program_id}/findings", func(w http.ResponseWriter, r *http.Request) {
		s.findings(r.PathValue("program_id"))(w, r)
	})
	s.mux.HandleFunc("GET /v1/programs/{program_id}/reports", func(w http.ResponseWriter, r *http.Request) {
		s.reports(r.PathValue("program_id"))(w, r)
	})
}

func (s *Server) programs(w http.ResponseWriter, r *http.Request) {
	p := listParamsFromRequest(r, 500)
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	active := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("active")))
	platform := strings.TrimSpace(r.URL.Query().Get("platform"))
	programID := strings.TrimSpace(r.URL.Query().Get("program_id"))
	if queryBool(r, "compact", false) {
		if q == "" && active == "" && platform == "" && programID == "" {
			rows, err := s.repo.QueryJSONRows(r.Context(), `
				WITH filtered AS MATERIALIZED (
					SELECT p.*
					FROM zero_programs p
					ORDER BY p.platform, p.handle
					LIMIT $1 OFFSET $2
				), running_full AS (
					SELECT
						sr.program_id,
						max(sr.started_at) AS running_scan_started_at
					FROM zero_scan_runs sr
					JOIN filtered p ON p.id = sr.program_id
					WHERE sr.run_type = 'full'
					  AND sr.status = 'running'
					GROUP BY sr.program_id
				)
				SELECT jsonb_build_object(
					'id', p.id,
					'platform', p.platform,
					'handle', p.handle,
					'program_url', p.program_url,
					'active', p.active,
					'scan_interval_hours', p.scan_interval_hours,
					'last_scan_started_at', p.last_scan_started_at,
					'last_scan_finished_at', p.last_scan_finished_at,
					'is_running', running_full.program_id IS NOT NULL,
					'running_scan_started_at', running_full.running_scan_started_at,
					'latest_scan_status', CASE WHEN running_full.program_id IS NOT NULL THEN 'running' ELSE '' END,
					'latest_scan_id', '',
					'first_seen_at', p.first_seen_at,
					'last_seen_at', p.last_seen_at
				)
				FROM filtered p
				LEFT JOIN running_full ON running_full.program_id = p.id
				ORDER BY p.platform, p.handle
			`, p.Limit, p.Offset)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeRawJSONArray(w, rows)
			return
		}
		rows, err := s.repo.QueryJSONRows(r.Context(), `
			WITH filtered AS MATERIALIZED (
				SELECT p.*
				FROM zero_programs p
				WHERE ($1 = '' OR p.handle ILIKE '%' || $1 || '%' OR p.platform ILIKE '%' || $1 || '%' OR p.program_url ILIKE '%' || $1 || '%')
				  AND ($2 = '' OR $2 = 'all' OR ($2 IN ('true','active','1') AND p.active) OR ($2 IN ('false','inactive','0') AND NOT p.active))
				  AND ($3 = '' OR p.platform = $3)
				  AND ($4 = '' OR p.id::text = $4)
				ORDER BY p.platform, p.handle
				LIMIT $5 OFFSET $6
			), running_full AS (
				SELECT
					sr.program_id,
					max(sr.started_at) AS running_scan_started_at
				FROM zero_scan_runs sr
				JOIN filtered p ON p.id = sr.program_id
				WHERE sr.run_type = 'full'
				  AND sr.status = 'running'
				GROUP BY sr.program_id
			)
			SELECT jsonb_build_object(
				'id', p.id,
				'platform', p.platform,
				'handle', p.handle,
				'program_url', p.program_url,
				'active', p.active,
				'scan_interval_hours', p.scan_interval_hours,
				'last_scan_started_at', p.last_scan_started_at,
				'last_scan_finished_at', p.last_scan_finished_at,
				'is_running', running_full.program_id IS NOT NULL,
				'running_scan_started_at', running_full.running_scan_started_at,
				'latest_scan_status', CASE WHEN running_full.program_id IS NOT NULL THEN 'running' ELSE '' END,
				'latest_scan_id', '',
				'first_seen_at', p.first_seen_at,
				'last_seen_at', p.last_seen_at
			)
			FROM filtered p
			LEFT JOIN running_full ON running_full.program_id = p.id
			ORDER BY p.platform, p.handle
		`, q, active, platform, programID, p.Limit, p.Offset)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeRawJSONArray(w, rows)
		return
	}
	rows, err := s.repo.QueryJSONRows(r.Context(), `
		SELECT jsonb_build_object(
			'id', p.id,
			'platform', p.platform,
			'handle', p.handle,
			'program_url', p.program_url,
			'active', p.active,
			'scan_interval_hours', p.scan_interval_hours,
			'max_parallel_tasks', p.max_parallel_tasks,
			'parallelism_scope', 'reserved; current scheduler uses ZERO_TARGET_PARALLELISM globally',
			'last_scan_started_at', p.last_scan_started_at,
			'last_scan_finished_at', p.last_scan_finished_at,
			'is_running', COALESCE(run_state.is_running, false),
			'running_scan_started_at', run_state.running_scan_started_at,
			'latest_scan_status', latest.status,
			'latest_scan_id', latest.id,
			'first_seen_at', p.first_seen_at,
			'last_seen_at', p.last_seen_at,
			'metadata', p.metadata,
			'counts', jsonb_build_object(
				'scope_assets', COALESCE(counts.scope_assets, 0),
				'in_scope_assets', COALESCE(counts.in_scope_assets, 0),
				'bounty_assets', COALESCE(counts.bounty_assets, 0),
				'subdomains', COALESCE(counts.subdomains, 0),
				'http_services', COALESCE(counts.http_services, 0),
				'technologies', COALESCE(counts.technologies, 0),
				'findings', COALESCE(counts.findings, 0),
				'nuclei_results', COALESCE(counts.nuclei_results, 0),
				'reports', COALESCE(counts.reports, 0)
			)
		)
		FROM zero_programs p
		LEFT JOIN LATERAL (
			SELECT
				bool_or(sr.status = 'running') AS is_running,
				max(sr.started_at) FILTER (WHERE sr.status = 'running') AS running_scan_started_at
			FROM zero_scan_runs sr
			WHERE sr.program_id = p.id
			  AND sr.run_type = 'full'
		) run_state ON true
		LEFT JOIN LATERAL (
			SELECT sr.id, sr.status
			FROM zero_scan_runs sr
			WHERE sr.program_id = p.id
			  AND sr.run_type = 'full'
			ORDER BY sr.started_at DESC
			LIMIT 1
		) latest ON true
		LEFT JOIN LATERAL (
			SELECT
				(SELECT count(*) FROM zero_scope_assets a WHERE a.program_id = p.id AND a.active) AS scope_assets,
				(SELECT count(*) FROM zero_scope_assets a WHERE a.program_id = p.id AND a.active AND a.in_scope) AS in_scope_assets,
				(SELECT count(*) FROM zero_scope_assets a WHERE a.program_id = p.id AND a.active AND a.eligible_for_bounty) AS bounty_assets,
				(SELECT count(*) FROM zero_subdomains sd WHERE sd.program_id = p.id AND sd.active) AS subdomains,
				(SELECT count(*) FROM zero_http_services hs WHERE hs.program_id = p.id AND hs.active) AS http_services,
				(SELECT count(*) FROM zero_technology_observations t WHERE t.program_id = p.id AND t.active) AS technologies,
				(SELECT count(*) FROM zero_candidate_findings f WHERE f.program_id = p.id) AS findings,
				(SELECT count(*) FROM zero_nuclei_results n WHERE n.program_id = p.id) AS nuclei_results,
				(SELECT count(*) FROM zero_reports rp WHERE rp.program_id = p.id) AS reports
		) counts ON true
		WHERE ($1 = '' OR p.handle ILIKE '%' || $1 || '%' OR p.platform ILIKE '%' || $1 || '%' OR p.program_url ILIKE '%' || $1 || '%')
		  AND ($2 = '' OR $2 = 'all' OR ($2 IN ('true','active','1') AND p.active) OR ($2 IN ('false','inactive','0') AND NOT p.active))
		  AND ($3 = '' OR p.platform = $3)
		  AND ($4 = '' OR p.id::text = $4)
		ORDER BY p.platform, p.handle
		LIMIT $5 OFFSET $6
	`, q, active, platform, programID, p.Limit, p.Offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeRawJSONArray(w, rows)
}

func (s *Server) inventoryOverview(w http.ResponseWriter, r *http.Request) {
	s.cachedJSONRow(w, r, "inventory-overview", 30*time.Second, `
		SELECT jsonb_build_object(
			'generated_at', now(),
			'tables', jsonb_build_object(
				'programs', (SELECT count(*) FROM zero_programs),
				'scope_assets', (SELECT count(*) FROM zero_scope_assets),
				'subdomains', (SELECT count(*) FROM zero_subdomains),
				'http_services', (SELECT count(*) FROM zero_http_services),
				'technology_observations', (SELECT count(*) FROM zero_technology_observations),
				'vulnerability_records', (SELECT count(*) FROM zero_vulnerability_records),
				'technology_vulnerability_matches', (SELECT count(*) FROM zero_technology_vulnerability_matches),
				'nuclei_results', (SELECT count(*) FROM zero_nuclei_results),
				'candidate_findings', (SELECT count(*) FROM zero_candidate_findings),
				'reports', (SELECT count(*) FROM zero_reports),
				'scan_runs', (SELECT count(*) FROM zero_scan_runs),
				'scan_requests', (SELECT count(*) FROM zero_scan_requests),
				'scan_campaigns', (SELECT count(*) FROM zero_scan_campaigns),
				'change_events', (SELECT count(*) FROM zero_change_events),
				'discord_notifications', (SELECT count(*) FROM zero_discord_notifications)
			),
			'active_inventory', jsonb_build_object(
				'programs', (SELECT count(*) FROM zero_programs WHERE active),
				'scope_assets', (SELECT count(*) FROM zero_scope_assets WHERE active),
				'in_scope_assets', (SELECT count(*) FROM zero_scope_assets WHERE active AND in_scope),
				'bounty_assets', (SELECT count(*) FROM zero_scope_assets WHERE active AND eligible_for_bounty),
				'subdomains', (SELECT count(*) FROM zero_subdomains WHERE active),
				'resolved_subdomains', (SELECT count(*) FROM zero_subdomains WHERE active AND COALESCE(resolves, true)),
				'http_services', (SELECT count(*) FROM zero_http_services WHERE active),
				'technologies', (SELECT count(*) FROM zero_technology_observations WHERE active)
			),
			'top_programs_by_services', COALESCE((
				SELECT jsonb_agg(row ORDER BY total DESC)
				FROM (
					SELECT jsonb_build_object('program_id', p.id, 'platform', p.platform, 'handle', p.handle, 'total', count(*)::int) AS row, count(*) AS total
					FROM zero_http_services h
					JOIN zero_programs p ON p.id = h.program_id
					WHERE h.active
					GROUP BY p.id, p.platform, p.handle
					ORDER BY count(*) DESC
					LIMIT 10
				) x
			), '[]'::jsonb),
			'top_technologies', COALESCE((
				SELECT jsonb_agg(row ORDER BY total DESC)
				FROM (
					SELECT jsonb_build_object('name', name, 'source', source, 'total', count(*)::int) AS row, count(*) AS total
					FROM zero_technology_observations
					WHERE active
					GROUP BY name, source
					ORDER BY count(*) DESC
					LIMIT 20
				) x
			), '[]'::jsonb)
		)
	`)
}

func (s *Server) globalStats(w http.ResponseWriter, r *http.Request) {
	s.cachedJSONRow(w, r, "global-stats", 20*time.Second, `
		SELECT jsonb_build_object(
			'programs', jsonb_build_object(
				'total', count(*),
				'active', count(*) FILTER (WHERE active),
				'scanned', count(*) FILTER (WHERE active AND last_scan_finished_at IS NOT NULL),
				'never_scanned', count(*) FILTER (WHERE active AND last_scan_finished_at IS NULL),
				'due', count(*) FILTER (
					WHERE active
					  AND (
						last_scan_finished_at IS NULL
						OR last_scan_finished_at < now() - (scan_interval_hours * interval '1 hour')
					  )
					  AND NOT EXISTS (
						SELECT 1
						FROM zero_scan_runs sr
						WHERE sr.program_id = zero_programs.id
						  AND sr.run_type = 'full'
						  AND sr.status = 'running'
					  )
				)
			),
			'scan_runs', jsonb_build_object(
				'running', (SELECT count(*) FROM zero_scan_runs WHERE status = 'running' AND run_type = 'full'),
				'running_programs', (SELECT count(DISTINCT program_id) FROM zero_scan_runs WHERE status = 'running' AND run_type = 'full' AND program_id IS NOT NULL),
				'succeeded', (SELECT count(*) FROM zero_scan_runs WHERE status = 'succeeded' AND run_type = 'full'),
				'failed', (SELECT count(*) FROM zero_scan_runs WHERE status = 'failed' AND run_type = 'full'),
				'incomplete', (SELECT count(*) FROM zero_scan_runs WHERE status = 'incomplete' AND run_type = 'full'),
				'total', (SELECT count(*) FROM zero_scan_runs WHERE run_type = 'full'),
				'recent_24h', jsonb_build_object(
					'running', (SELECT count(*) FROM zero_scan_runs WHERE status = 'running' AND run_type = 'full' AND started_at > now() - interval '24 hours'),
					'running_programs', (SELECT count(DISTINCT program_id) FROM zero_scan_runs WHERE status = 'running' AND run_type = 'full' AND program_id IS NOT NULL AND started_at > now() - interval '24 hours'),
					'succeeded', (SELECT count(*) FROM zero_scan_runs WHERE status = 'succeeded' AND run_type = 'full' AND started_at > now() - interval '24 hours'),
					'failed', (SELECT count(*) FROM zero_scan_runs WHERE status = 'failed' AND run_type = 'full' AND started_at > now() - interval '24 hours'),
					'incomplete', (SELECT count(*) FROM zero_scan_runs WHERE status = 'incomplete' AND run_type = 'full' AND started_at > now() - interval '24 hours'),
					'total', (SELECT count(*) FROM zero_scan_runs WHERE run_type = 'full' AND started_at > now() - interval '24 hours')
				),
				'task_runs', jsonb_build_object(
					'running', (SELECT count(*) FROM zero_scan_runs WHERE status = 'running' AND run_type <> 'full'),
					'succeeded', (SELECT count(*) FROM zero_scan_runs WHERE status = 'succeeded' AND run_type <> 'full'),
					'failed', (SELECT count(*) FROM zero_scan_runs WHERE status = 'failed' AND run_type <> 'full'),
					'incomplete', (SELECT count(*) FROM zero_scan_runs WHERE status = 'incomplete' AND run_type <> 'full'),
					'total', (SELECT count(*) FROM zero_scan_runs WHERE run_type <> 'full')
				)
			),
			'assets', jsonb_build_object(
				'active_scope_assets', (SELECT count(*) FROM zero_scope_assets WHERE active),
				'active_in_scope_assets', (SELECT count(*) FROM zero_scope_assets WHERE active AND in_scope),
				'active_bounty_assets', (SELECT count(*) FROM zero_scope_assets WHERE active AND eligible_for_bounty),
				'active_subdomains', (SELECT count(*) FROM zero_subdomains WHERE active),
				'active_http_services', (SELECT count(*) FROM zero_http_services WHERE active),
				'active_technologies', (SELECT count(*) FROM zero_technology_observations WHERE active)
			),
			'findings', jsonb_build_object(
				'total', (SELECT count(*) FROM zero_candidate_findings),
				'new', (SELECT count(*) FROM zero_candidate_findings WHERE status = 'new'),
				'reported', (SELECT count(*) FROM zero_candidate_findings WHERE status = 'reported'),
				'nuclei_confirmed', (SELECT count(*) FROM zero_candidate_findings WHERE nuclei_result_id IS NOT NULL),
				'passive_unconfirmed', (SELECT count(*) FROM zero_candidate_findings WHERE nuclei_result_id IS NULL)
			),
			'scan_campaigns', jsonb_build_object(
				'staging', (SELECT count(*) FROM zero_scan_campaigns WHERE status = 'staging'),
				'running', (SELECT count(*) FROM zero_scan_campaigns WHERE status = 'running'),
				'queued', (SELECT count(*) FROM zero_scan_campaigns WHERE status = 'queued'),
				'succeeded', (SELECT count(*) FROM zero_scan_campaigns WHERE status = 'succeeded'),
				'partial', (SELECT count(*) FROM zero_scan_campaigns WHERE status = 'partial'),
				'failed', (SELECT count(*) FROM zero_scan_campaigns WHERE status = 'failed'),
				'total', (SELECT count(*) FROM zero_scan_campaigns)
			),
			'nuclei_results', (SELECT count(*) FROM zero_nuclei_results),
			'reports', (SELECT count(*) FROM zero_reports),
			'generated_at', now()
		)
		FROM zero_programs
	`)
}

func (s *Server) programStats(w http.ResponseWriter, r *http.Request) {
	programID := r.PathValue("program_id")
	rows, err := s.repo.QueryJSONRows(r.Context(), `
		SELECT jsonb_build_object(
			'program', jsonb_build_object(
				'id', p.id,
				'platform', p.platform,
				'handle', p.handle,
				'program_url', p.program_url,
				'active', p.active,
				'scan_interval_hours', p.scan_interval_hours,
				'max_parallel_tasks', p.max_parallel_tasks,
				'parallelism_scope', 'reserved; current scheduler uses ZERO_TARGET_PARALLELISM globally',
				'last_scan_started_at', p.last_scan_started_at,
				'last_scan_finished_at', p.last_scan_finished_at,
				'is_running', EXISTS (
					SELECT 1
					FROM zero_scan_runs sr
					WHERE sr.program_id = p.id
					  AND sr.run_type = 'full'
					  AND sr.status = 'running'
				),
				'running_scan_started_at', (
					SELECT sr.started_at
					FROM zero_scan_runs sr
					WHERE sr.program_id = p.id
					  AND sr.run_type = 'full'
					  AND sr.status = 'running'
					ORDER BY sr.started_at DESC
					LIMIT 1
				),
				'latest_scan_status', (
					SELECT sr.status
					FROM zero_scan_runs sr
					WHERE sr.program_id = p.id
					  AND sr.run_type = 'full'
					ORDER BY sr.started_at DESC
					LIMIT 1
				),
				'is_due', p.active AND (
					p.last_scan_finished_at IS NULL
					OR p.last_scan_finished_at < now() - (p.scan_interval_hours * interval '1 hour')
				) AND NOT EXISTS (
					SELECT 1
					FROM zero_scan_runs sr
					WHERE sr.program_id = p.id
					  AND sr.run_type = 'full'
					  AND sr.status = 'running'
				)
			),
			'scan_runs', jsonb_build_object(
				'running', (SELECT count(*) FROM zero_scan_runs WHERE program_id = p.id AND status = 'running' AND run_type = 'full'),
				'running_programs', (SELECT count(DISTINCT program_id) FROM zero_scan_runs WHERE program_id = p.id AND status = 'running' AND run_type = 'full'),
				'succeeded', (SELECT count(*) FROM zero_scan_runs WHERE program_id = p.id AND status = 'succeeded' AND run_type = 'full'),
				'failed', (SELECT count(*) FROM zero_scan_runs WHERE program_id = p.id AND status = 'failed' AND run_type = 'full'),
				'incomplete', (SELECT count(*) FROM zero_scan_runs WHERE program_id = p.id AND status = 'incomplete' AND run_type = 'full'),
				'total', (SELECT count(*) FROM zero_scan_runs WHERE program_id = p.id AND run_type = 'full'),
				'recent_24h', jsonb_build_object(
					'running', (SELECT count(*) FROM zero_scan_runs WHERE program_id = p.id AND status = 'running' AND run_type = 'full' AND started_at > now() - interval '24 hours'),
					'running_programs', (SELECT count(DISTINCT program_id) FROM zero_scan_runs WHERE program_id = p.id AND status = 'running' AND run_type = 'full' AND started_at > now() - interval '24 hours'),
					'succeeded', (SELECT count(*) FROM zero_scan_runs WHERE program_id = p.id AND status = 'succeeded' AND run_type = 'full' AND started_at > now() - interval '24 hours'),
					'failed', (SELECT count(*) FROM zero_scan_runs WHERE program_id = p.id AND status = 'failed' AND run_type = 'full' AND started_at > now() - interval '24 hours'),
					'incomplete', (SELECT count(*) FROM zero_scan_runs WHERE program_id = p.id AND status = 'incomplete' AND run_type = 'full' AND started_at > now() - interval '24 hours'),
					'total', (SELECT count(*) FROM zero_scan_runs WHERE program_id = p.id AND run_type = 'full' AND started_at > now() - interval '24 hours')
				),
				'task_runs', jsonb_build_object(
					'running', (SELECT count(*) FROM zero_scan_runs WHERE program_id = p.id AND status = 'running' AND run_type <> 'full'),
					'succeeded', (SELECT count(*) FROM zero_scan_runs WHERE program_id = p.id AND status = 'succeeded' AND run_type <> 'full'),
					'failed', (SELECT count(*) FROM zero_scan_runs WHERE program_id = p.id AND status = 'failed' AND run_type <> 'full'),
					'incomplete', (SELECT count(*) FROM zero_scan_runs WHERE program_id = p.id AND status = 'incomplete' AND run_type <> 'full'),
					'total', (SELECT count(*) FROM zero_scan_runs WHERE program_id = p.id AND run_type <> 'full')
				),
				'by_type', COALESCE((
					SELECT jsonb_object_agg(run_type, count ORDER BY run_type)
					FROM (
						SELECT run_type, count(*) AS count
						FROM zero_scan_runs
						WHERE program_id = p.id
						GROUP BY run_type
					) x
				), '{}'::jsonb)
			),
			'assets', jsonb_build_object(
				'active_scope_assets', (SELECT count(*) FROM zero_scope_assets WHERE program_id = p.id AND active),
				'active_in_scope_assets', (SELECT count(*) FROM zero_scope_assets WHERE program_id = p.id AND active AND in_scope),
				'active_bounty_assets', (SELECT count(*) FROM zero_scope_assets WHERE program_id = p.id AND active AND eligible_for_bounty),
				'active_subdomains', (SELECT count(*) FROM zero_subdomains WHERE program_id = p.id AND active),
				'active_http_services', (SELECT count(*) FROM zero_http_services WHERE program_id = p.id AND active),
				'active_technologies', (SELECT count(*) FROM zero_technology_observations WHERE program_id = p.id AND active)
			),
			'findings', jsonb_build_object(
				'total', (SELECT count(*) FROM zero_candidate_findings WHERE program_id = p.id),
				'new', (SELECT count(*) FROM zero_candidate_findings WHERE program_id = p.id AND status = 'new'),
				'reported', (SELECT count(*) FROM zero_candidate_findings WHERE program_id = p.id AND status = 'reported'),
				'nuclei_confirmed', (SELECT count(*) FROM zero_candidate_findings WHERE program_id = p.id AND nuclei_result_id IS NOT NULL),
				'passive_unconfirmed', (SELECT count(*) FROM zero_candidate_findings WHERE program_id = p.id AND nuclei_result_id IS NULL)
			),
			'nuclei_results', (SELECT count(*) FROM zero_nuclei_results WHERE program_id = p.id),
			'reports', (SELECT count(*) FROM zero_reports WHERE program_id = p.id),
			'latest_scan', (
				SELECT jsonb_build_object(
					'id', sr.id,
					'run_type', sr.run_type,
					'status', sr.status,
					'started_at', sr.started_at,
					'finished_at', sr.finished_at,
					'error', sr.error,
					'stats', sr.stats
				)
				FROM zero_scan_runs sr
				WHERE sr.program_id = p.id
				  AND sr.run_type = 'full'
				ORDER BY sr.started_at DESC
				LIMIT 1
			),
			'generated_at', now()
		)
		FROM zero_programs p
		WHERE p.id = $1::uuid
	`, programID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(rows) == 0 {
		writeError(w, http.StatusNotFound, "program stats not found")
		return
	}
	writeRawJSON(w, rows[0])
}

func (s *Server) scanRequests(w http.ResponseWriter, r *http.Request) {
	p := listParamsFromRequest(r, 100)
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	campaignID := strings.TrimSpace(r.URL.Query().Get("campaign_id"))
	programID := strings.TrimSpace(r.URL.Query().Get("program_id"))
	platform := strings.TrimSpace(r.URL.Query().Get("platform"))
	rows, err := s.repo.QueryJSONRows(r.Context(), `
		SELECT jsonb_build_object(
			'id', r.id,
			'program_id', r.program_id,
			'program_handle', COALESCE(p.handle, ''),
			'program_platform', COALESCE(p.platform, ''),
			'campaign_id', r.campaign_id,
			'name', r.name,
			'status', r.status,
			'requested_by', r.requested_by,
			'run_after', r.run_after,
			'attempt_count', r.attempt_count,
			'started_at', r.started_at,
			'finished_at', r.finished_at,
			'locked_at', r.locked_at,
			'error', r.error,
			'progress_stage', r.progress_stage,
			'progress_current', r.progress_current,
			'progress_total', r.progress_total,
			'progress_message', r.progress_message,
			'progress_meta', r.progress_meta,
			'progress_updated_at', r.progress_updated_at,
			'params', r.params,
			'created_at', r.created_at,
			'updated_at', r.updated_at
		)
		FROM zero_scan_requests r
		LEFT JOIN zero_programs p ON p.id = r.program_id
		WHERE ($1 = '' OR r.status = $1)
		  AND ($2 = '' OR r.campaign_id::text = $2)
		  AND ($3 = '' OR r.program_id::text = $3)
		  AND ($4 = '' OR r.name ILIKE '%' || $4 || '%' OR r.status ILIKE '%' || $4 || '%' OR r.error ILIKE '%' || $4 || '%' OR p.handle ILIKE '%' || $4 || '%')
		  AND ($5 = '' OR p.platform = $5)
		  AND (NULLIF($6, '') IS NULL OR r.created_at > NULLIF($6, '')::timestamptz)
		ORDER BY r.created_at DESC
		LIMIT $7 OFFSET $8
	`, status, campaignID, programID, q, platform, p.Since, p.Limit, p.Offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeRawJSONArray(w, rows)
}

func (s *Server) scanCampaigns(w http.ResponseWriter, r *http.Request) {
	p := listParamsFromRequest(r, 100)
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	rows, err := s.repo.QueryJSONRows(r.Context(), `
		SELECT jsonb_build_object(
			'id', c.id,
			'name', c.name,
			'status', c.status,
			'requested_by', c.requested_by,
			'run_after', c.run_after,
			'parallelism', c.parallelism,
			'total_requests', c.total_requests,
			'queued_requests', c.queued_requests,
			'running_requests', c.running_requests,
			'succeeded_requests', c.succeeded_requests,
			'failed_requests', c.failed_requests,
			'canceled_requests', c.canceled_requests,
			'params', c.params,
			'program_filter', c.program_filter,
			'started_at', c.started_at,
			'finished_at', c.finished_at,
			'error', c.error,
			'created_at', c.created_at,
			'updated_at', c.updated_at
		)
		FROM zero_scan_campaigns c
		WHERE ($1 = '' OR c.status = $1)
		  AND ($2 = '' OR c.name ILIKE '%' || $2 || '%' OR c.requested_by ILIKE '%' || $2 || '%' OR c.error ILIKE '%' || $2 || '%')
		  AND (NULLIF($3, '') IS NULL OR c.created_at > NULLIF($3, '')::timestamptz)
		ORDER BY c.created_at DESC
		LIMIT $4 OFFSET $5
	`, status, q, p.Since, p.Limit, p.Offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeRawJSONArray(w, rows)
}

func (s *Server) scanCampaignDetail(w http.ResponseWriter, r *http.Request) {
	campaignID := strings.TrimSpace(r.PathValue("campaign_id"))
	if campaignID == "" {
		writeError(w, http.StatusBadRequest, "campaign id is required")
		return
	}
	rows, err := s.repo.QueryJSONRows(r.Context(), `
		WITH campaign AS (
			SELECT *
			FROM zero_scan_campaigns
			WHERE id = $1::uuid
		), campaign_scan_runs AS (
			SELECT DISTINCT sr.id, sr.program_id, sr.run_type, sr.started_at
			FROM zero_scan_runs sr
			WHERE sr.scan_campaign_id = $1::uuid
		), campaign_shape AS (
			SELECT
				CASE
					WHEN jsonb_typeof(params->'WebanalyzeProbePaths') = 'array' THEN jsonb_array_length(params->'WebanalyzeProbePaths')
					ELSE 0
				END AS webanalyze_probe_paths,
				COALESCE(NULLIF((params->>'WebanalyzeBatch')::int, 0), 50) AS webanalyze_batch_size
			FROM campaign
		)
		SELECT jsonb_build_object(
			'campaign', (
				SELECT jsonb_build_object(
					'id', c.id,
					'name', c.name,
					'status', c.status,
					'requested_by', c.requested_by,
					'run_after', c.run_after,
					'parallelism', c.parallelism,
					'total_requests', c.total_requests,
					'queued_requests', c.queued_requests,
					'running_requests', c.running_requests,
					'succeeded_requests', c.succeeded_requests,
					'failed_requests', c.failed_requests,
					'params', c.params,
					'program_filter', c.program_filter,
					'started_at', c.started_at,
					'finished_at', c.finished_at,
					'error', c.error,
					'created_at', c.created_at,
					'updated_at', c.updated_at
				)
				FROM campaign c
			),
			'request_counts', COALESCE((
				SELECT jsonb_object_agg(status, total)
				FROM (
					SELECT status, count(*)::int AS total
					FROM zero_scan_requests
					WHERE campaign_id = $1::uuid
					GROUP BY status
				) counts
			), '{}'::jsonb),
			'recent_requests', COALESCE((
				SELECT jsonb_agg(row ORDER BY sort_at DESC)
				FROM (
					SELECT
						jsonb_build_object(
							'id', r.id,
							'program_id', r.program_id,
							'program_handle', COALESCE(p.handle, ''),
							'program_platform', COALESCE(p.platform, ''),
							'status', r.status,
							'attempt_count', r.attempt_count,
							'started_at', r.started_at,
							'finished_at', r.finished_at,
							'locked_at', r.locked_at,
							'error', r.error,
							'active_http_services', COALESCE(hs.active_http_services, 0),
							'estimated_webanalyze_urls', COALESCE(hs.active_http_services, 0) * (1 + cs.webanalyze_probe_paths),
							'estimated_webanalyze_batches', CEIL((COALESCE(hs.active_http_services, 0) * (1 + cs.webanalyze_probe_paths))::numeric / GREATEST(cs.webanalyze_batch_size, 1))::int,
							'webanalyze_probe_paths', cs.webanalyze_probe_paths,
							'webanalyze_batch_size', cs.webanalyze_batch_size,
							'progress_stage', r.progress_stage,
							'progress_current', r.progress_current,
							'progress_total', r.progress_total,
							'progress_message', r.progress_message,
							'progress_meta', r.progress_meta,
							'progress_updated_at', r.progress_updated_at,
							'updated_at', r.updated_at
						) AS row,
						COALESCE(r.updated_at, r.created_at) AS sort_at
					FROM zero_scan_requests r
					LEFT JOIN zero_programs p ON p.id = r.program_id
					CROSS JOIN campaign_shape cs
					LEFT JOIN LATERAL (
						SELECT count(*)::int AS active_http_services
						FROM zero_http_services h
						WHERE h.program_id = r.program_id
						  AND h.active
					) hs ON true
					WHERE r.campaign_id = $1::uuid
					ORDER BY COALESCE(r.updated_at, r.created_at) DESC
					LIMIT 25
				) recent
			), '[]'::jsonb),
			'running_requests', COALESCE((
				SELECT jsonb_agg(row ORDER BY sort_at ASC)
				FROM (
					SELECT
						jsonb_build_object(
							'id', r.id,
							'program_id', r.program_id,
							'program_handle', COALESCE(p.handle, ''),
							'program_platform', COALESCE(p.platform, ''),
							'status', r.status,
							'attempt_count', r.attempt_count,
							'started_at', r.started_at,
							'locked_at', r.locked_at,
							'active_http_services', COALESCE(hs.active_http_services, 0),
							'estimated_webanalyze_urls', COALESCE(hs.active_http_services, 0) * (1 + cs.webanalyze_probe_paths),
							'estimated_webanalyze_batches', CEIL((COALESCE(hs.active_http_services, 0) * (1 + cs.webanalyze_probe_paths))::numeric / GREATEST(cs.webanalyze_batch_size, 1))::int,
							'webanalyze_probe_paths', cs.webanalyze_probe_paths,
							'webanalyze_batch_size', cs.webanalyze_batch_size,
							'progress_stage', r.progress_stage,
							'progress_current', r.progress_current,
							'progress_total', r.progress_total,
							'progress_message', r.progress_message,
							'progress_meta', r.progress_meta,
							'progress_updated_at', r.progress_updated_at,
							'updated_at', r.updated_at
						) AS row,
						COALESCE(r.started_at, r.updated_at, r.created_at) AS sort_at
					FROM zero_scan_requests r
					LEFT JOIN zero_programs p ON p.id = r.program_id
					CROSS JOIN campaign_shape cs
					LEFT JOIN LATERAL (
						SELECT count(*)::int AS active_http_services
						FROM zero_http_services h
						WHERE h.program_id = r.program_id
						  AND h.active
					) hs ON true
					WHERE r.campaign_id = $1::uuid
					  AND r.status = 'running'
					ORDER BY COALESCE(r.started_at, r.updated_at, r.created_at)
					LIMIT 50
				) running
			), '[]'::jsonb),
			'finding_counts', jsonb_build_object(
				'total', COALESCE((
					SELECT count(*)::int
					FROM zero_candidate_findings f
					LEFT JOIN zero_nuclei_results n ON n.id = f.nuclei_result_id
					WHERE (
						n.scan_run_id IN (SELECT id FROM campaign_scan_runs)
						OR EXISTS (
							SELECT 1
							FROM zero_change_events ce
							JOIN campaign_scan_runs csr ON csr.id = ce.scan_run_id
							WHERE ce.entity_type = 'candidate_finding'
							  AND ce.entity_id = f.id
						)
					)
				), 0),
				'nuclei_confirmed', COALESCE((
					SELECT count(*)::int
					FROM zero_candidate_findings f
					JOIN zero_nuclei_results n ON n.id = f.nuclei_result_id
					WHERE n.scan_run_id IN (SELECT id FROM campaign_scan_runs)
				), 0),
				'passive_unconfirmed', COALESCE((
					SELECT count(*)::int
					FROM zero_candidate_findings f
					WHERE f.nuclei_result_id IS NULL
					  AND EXISTS (
						SELECT 1
						FROM zero_change_events ce
						JOIN campaign_scan_runs csr ON csr.id = ce.scan_run_id
						WHERE ce.entity_type = 'candidate_finding'
						  AND ce.entity_id = f.id
					  )
				), 0)
			),
			'findings', COALESCE((
				SELECT jsonb_agg(row ORDER BY sort_at DESC)
				FROM (
					SELECT
						jsonb_build_object(
							'id', f.id,
							'program_id', f.program_id,
							'program_handle', COALESCE(p.handle, ''),
							'program_platform', COALESCE(p.platform, ''),
							'service_url', COALESCE(s.url, ''),
							'nuclei_template_id', COALESCE(n.template_id, ''),
							'vulnerability_id', COALESCE(v.vuln_id, ''),
							'nuclei_result_id', f.nuclei_result_id,
							'severity', f.severity,
							'confidence', f.confidence,
							'status', f.status,
							'evidence', f.evidence,
							'report_id', f.report_id,
							'first_seen_at', f.first_seen_at,
							'last_seen_at', f.last_seen_at
						) AS row,
						f.first_seen_at AS sort_at
					FROM zero_candidate_findings f
					LEFT JOIN zero_nuclei_results n ON n.id = f.nuclei_result_id
					LEFT JOIN zero_programs p ON p.id = f.program_id
					LEFT JOIN zero_http_services s ON s.id = f.http_service_id
					LEFT JOIN zero_vulnerability_records v ON v.id = f.vulnerability_id
					WHERE (
						n.scan_run_id IN (SELECT id FROM campaign_scan_runs)
						OR EXISTS (
							SELECT 1
							FROM zero_change_events ce
							JOIN campaign_scan_runs csr ON csr.id = ce.scan_run_id
							WHERE ce.entity_type = 'candidate_finding'
							  AND ce.entity_id = f.id
						)
					)
					ORDER BY f.first_seen_at DESC
					LIMIT 50
				) recent_findings
			), '[]'::jsonb),
			'nuclei_results', COALESCE((
				SELECT jsonb_agg(row ORDER BY sort_at DESC)
				FROM (
					SELECT
						jsonb_build_object(
							'id', n.id,
							'program_id', n.program_id,
							'program_handle', COALESCE(p.handle, ''),
							'service_url', COALESCE(s.url, ''),
							'template_id', n.template_id,
							'target_source', n.target_source,
							'target_id', n.target_id,
							'matched_at', n.matched_at,
							'severity', n.severity,
							'cves', n.cves,
							'tags', n.tags,
							'first_seen_at', n.first_seen_at
						) AS row,
						n.first_seen_at AS sort_at
					FROM zero_nuclei_results n
					LEFT JOIN zero_programs p ON p.id = n.program_id
					LEFT JOIN zero_http_services s ON s.id = n.http_service_id
					WHERE n.scan_run_id IN (SELECT id FROM campaign_scan_runs)
					ORDER BY n.first_seen_at DESC
					LIMIT 50
				) recent_nuclei
			), '[]'::jsonb)
		)
		FROM campaign
	`, campaignID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(rows) == 0 {
		writeError(w, http.StatusNotFound, "scan campaign not found")
		return
	}
	writeRawJSON(w, rows[0])
}

func (s *Server) defaultScans(w http.ResponseWriter, r *http.Request) {
	p := listParamsFromRequest(r, 25)
	rows, err := s.repo.QueryJSONRows(r.Context(), `
		WITH shaped AS (
			SELECT
				c.*,
				COALESCE(stats.input_count, 0)::int AS input_count,
				COALESCE(stats.inserted_count, 0)::int AS inserted_count,
				COALESCE(stats.updated_count, 0)::int AS updated_count,
				COALESCE(stats.unchanged_count, 0)::int AS unchanged_count,
				GREATEST(
					c.total_programs - c.running_programs - c.succeeded_programs - c.failed_programs - c.canceled_programs - c.incomplete_programs,
					0
				)::int AS queued_programs
			FROM zero_default_scan_cycles c
			LEFT JOIN LATERAL (
				SELECT
					sum(input_count) AS input_count,
					sum(inserted_count) AS inserted_count,
					sum(updated_count) AS updated_count,
					sum(unchanged_count) AS unchanged_count
				FROM zero_scan_runs sr
				WHERE sr.default_scan_cycle_id = c.id
				  AND sr.run_type = 'full'
			) stats ON true
		)
		SELECT jsonb_build_object(
			'id', id,
			'name', 'Default Scan ' || to_char(started_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI') || ' UTC',
			'status', status,
			'parallelism', parallelism,
			'total_requests', total_programs,
			'queued_requests', queued_programs,
			'running_requests', running_programs,
			'succeeded_requests', succeeded_programs,
			'failed_requests', failed_programs,
			'canceled_requests', canceled_programs,
			'incomplete_requests', incomplete_programs,
			'started_at', started_at,
			'finished_at', finished_at,
			'created_at', started_at,
			'updated_at', updated_at,
			'input_count', input_count,
			'inserted_count', inserted_count,
			'updated_count', updated_count,
			'unchanged_count', unchanged_count,
			'stats', jsonb_build_object(
				'program_scans', total_programs,
				'inputs', input_count,
				'inserted', inserted_count,
				'updated', updated_count,
				'unchanged', unchanged_count
			)
		)
		FROM shaped
		ORDER BY started_at DESC
		LIMIT $1 OFFSET $2
	`, p.Limit, p.Offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeRawJSONArray(w, rows)
}

func (s *Server) defaultScanDetail(w http.ResponseWriter, r *http.Request) {
	cycleID := strings.TrimSpace(r.PathValue("cycle_id"))
	if cycleID == "" {
		writeError(w, http.StatusBadRequest, "default scan id is required")
		return
	}
	rows, err := s.repo.QueryJSONRows(r.Context(), `
		WITH shaped AS (
			SELECT
				c.*,
				COALESCE(stats.input_count, 0)::int AS input_count,
				COALESCE(stats.inserted_count, 0)::int AS inserted_count,
				COALESCE(stats.updated_count, 0)::int AS updated_count,
				COALESCE(stats.unchanged_count, 0)::int AS unchanged_count,
				GREATEST(
					c.total_programs - c.running_programs - c.succeeded_programs - c.failed_programs - c.canceled_programs - c.incomplete_programs,
					0
				)::int AS queued_programs
			FROM zero_default_scan_cycles c
			LEFT JOIN LATERAL (
				SELECT
					sum(input_count) AS input_count,
					sum(inserted_count) AS inserted_count,
					sum(updated_count) AS updated_count,
					sum(unchanged_count) AS unchanged_count
				FROM zero_scan_runs sr
				WHERE sr.default_scan_cycle_id = c.id
				  AND sr.run_type = 'full'
			) stats ON true
		), cycle AS (
			SELECT *
			FROM shaped
			WHERE id = $1::uuid
		), cycle_runs AS (
			SELECT
				sr.*,
				COALESCE(p.handle, '') AS program_handle,
				COALESCE(p.platform, '') AS program_platform,
				COALESCE(p.program_url, '') AS program_url
			FROM zero_scan_runs sr
			JOIN cycle c ON c.id = sr.default_scan_cycle_id
			LEFT JOIN zero_programs p ON p.id = sr.program_id
			WHERE sr.run_type = 'full'
		), related_scan_runs AS (
			SELECT DISTINCT sr.id, sr.program_id, sr.run_type, sr.started_at
			FROM zero_scan_runs sr
			JOIN cycle_runs cr ON cr.id = sr.id OR sr.parent_scan_run_id = cr.id
		)
		SELECT jsonb_build_object(
			'scan', (
				SELECT jsonb_build_object(
					'id', c.id,
					'name', 'Default Scan ' || to_char(c.started_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI') || ' UTC',
					'status', c.status,
					'parallelism', c.parallelism,
					'total_requests', c.total_programs,
					'queued_requests', c.queued_programs,
					'running_requests', c.running_programs,
					'succeeded_requests', c.succeeded_programs,
					'failed_requests', c.failed_programs,
					'canceled_requests', c.canceled_programs,
					'incomplete_requests', c.incomplete_programs,
					'started_at', c.started_at,
					'finished_at', c.finished_at,
					'created_at', c.started_at,
					'updated_at', c.updated_at,
					'input_count', c.input_count,
					'inserted_count', c.inserted_count,
					'updated_count', c.updated_count,
					'unchanged_count', c.unchanged_count,
					'stats', jsonb_build_object(
						'program_scans', c.total_programs,
						'inputs', c.input_count,
						'inserted', c.inserted_count,
						'updated', c.updated_count,
						'unchanged', c.unchanged_count
					)
				)
				FROM cycle c
			),
			'request_counts', jsonb_build_object(
				'running', COALESCE((SELECT running_programs FROM cycle), 0),
				'queued', COALESCE((SELECT queued_programs FROM cycle), 0),
				'succeeded', COALESCE((SELECT succeeded_programs FROM cycle), 0),
				'failed', COALESCE((SELECT failed_programs FROM cycle), 0),
				'canceled', COALESCE((SELECT canceled_programs FROM cycle), 0),
				'incomplete', COALESCE((SELECT incomplete_programs FROM cycle), 0)
			),
			'recent_requests', COALESCE((
				SELECT jsonb_agg(row ORDER BY sort_at DESC)
				FROM (
					SELECT
						jsonb_build_object(
							'id', cr.id,
							'program_id', cr.program_id,
							'program_handle', cr.program_handle,
							'program_platform', cr.program_platform,
							'program_url', cr.program_url,
							'status', cr.status,
							'started_at', cr.started_at,
							'finished_at', cr.finished_at,
							'input_count', cr.input_count,
							'inserted_count', cr.inserted_count,
							'updated_count', cr.updated_count,
							'unchanged_count', cr.unchanged_count,
							'error', cr.error,
							'stats', cr.stats,
							'progress', COALESCE(progress.data, '{}'::jsonb)
						) AS row,
						cr.started_at AS sort_at
					FROM cycle_runs cr
					LEFT JOIN LATERAL (
						SELECT jsonb_build_object(
							'steps_total', 8,
							'child_scan_runs', count(*)::int,
							'child_succeeded', count(*) FILTER (WHERE child.status = 'succeeded')::int,
							'child_failed', count(*) FILTER (WHERE child.status = 'failed')::int,
							'child_incomplete', count(*) FILTER (WHERE child.status = 'incomplete')::int,
							'child_running', count(*) FILTER (WHERE child.status = 'running')::int,
							'current_step', COALESCE((
								SELECT jsonb_build_object(
									'id', latest.id,
									'run_type', latest.run_type,
									'status', latest.status,
									'started_at', latest.started_at,
									'finished_at', latest.finished_at,
									'input_count', latest.input_count,
									'inserted_count', latest.inserted_count,
									'error', latest.error,
									'stats', latest.stats
								)
								FROM zero_scan_runs latest
								WHERE latest.program_id = cr.program_id
								  AND latest.parent_scan_run_id = cr.id
								ORDER BY latest.started_at DESC
								LIMIT 1
							), '{}'::jsonb)
						) AS data
						FROM zero_scan_runs child
						WHERE child.program_id = cr.program_id
						  AND child.parent_scan_run_id = cr.id
					) progress ON true
					ORDER BY cr.started_at DESC
					LIMIT 250
				) recent
			), '[]'::jsonb),
			'running_requests', COALESCE((
				SELECT jsonb_agg(row ORDER BY sort_at ASC)
				FROM (
					SELECT
						jsonb_build_object(
							'id', cr.id,
							'program_id', cr.program_id,
							'program_handle', cr.program_handle,
							'program_platform', cr.program_platform,
							'status', cr.status,
							'started_at', cr.started_at,
							'input_count', cr.input_count,
							'stats', cr.stats,
							'progress', COALESCE(progress.data, '{}'::jsonb)
						) AS row,
						cr.started_at AS sort_at
					FROM cycle_runs cr
					LEFT JOIN LATERAL (
						SELECT jsonb_build_object(
							'steps_total', 8,
							'child_scan_runs', count(*)::int,
							'child_succeeded', count(*) FILTER (WHERE child.status = 'succeeded')::int,
							'child_failed', count(*) FILTER (WHERE child.status = 'failed')::int,
							'child_incomplete', count(*) FILTER (WHERE child.status = 'incomplete')::int,
							'child_running', count(*) FILTER (WHERE child.status = 'running')::int,
							'current_step', COALESCE((
								SELECT jsonb_build_object(
									'id', latest.id,
									'run_type', latest.run_type,
									'status', latest.status,
									'started_at', latest.started_at,
									'finished_at', latest.finished_at,
									'input_count', latest.input_count,
									'inserted_count', latest.inserted_count,
									'error', latest.error,
									'stats', latest.stats
								)
								FROM zero_scan_runs latest
								WHERE latest.program_id = cr.program_id
								  AND latest.parent_scan_run_id = cr.id
								ORDER BY latest.started_at DESC
								LIMIT 1
							), '{}'::jsonb)
						) AS data
						FROM zero_scan_runs child
						WHERE child.program_id = cr.program_id
						  AND child.parent_scan_run_id = cr.id
					) progress ON true
					WHERE cr.status = 'running'
					ORDER BY cr.started_at ASC
					LIMIT 100
				) running
			), '[]'::jsonb),
			'finding_counts', jsonb_build_object(
				'total', COALESCE((
					SELECT count(*)::int
					FROM zero_candidate_findings f
					LEFT JOIN zero_nuclei_results n ON n.id = f.nuclei_result_id
					WHERE (
						n.scan_run_id IN (SELECT id FROM related_scan_runs)
						OR EXISTS (
							SELECT 1
							FROM zero_change_events ce
							WHERE ce.entity_type = 'candidate_finding'
							  AND ce.entity_id = f.id
							  AND ce.scan_run_id IN (SELECT id FROM related_scan_runs)
						)
					)
				), 0),
				'nuclei_confirmed', COALESCE((
					SELECT count(*)::int
					FROM zero_candidate_findings f
					JOIN zero_nuclei_results n ON n.id = f.nuclei_result_id
					WHERE n.scan_run_id IN (SELECT id FROM related_scan_runs)
				), 0),
				'passive_unconfirmed', COALESCE((
					SELECT count(*)::int
					FROM zero_candidate_findings f
					WHERE f.nuclei_result_id IS NULL
					  AND EXISTS (
						SELECT 1
						FROM zero_change_events ce
						WHERE ce.entity_type = 'candidate_finding'
						  AND ce.entity_id = f.id
						  AND ce.scan_run_id IN (SELECT id FROM related_scan_runs)
					  )
				), 0)
			),
			'findings', COALESCE((
				SELECT jsonb_agg(row ORDER BY sort_at DESC)
				FROM (
					SELECT
						jsonb_build_object(
							'id', f.id,
							'program_id', f.program_id,
							'program_handle', COALESCE(p.handle, ''),
							'program_platform', COALESCE(p.platform, ''),
							'service_url', COALESCE(h.url, ''),
							'nuclei_template_id', COALESCE(n.template_id, ''),
							'vulnerability_id', COALESCE(v.vuln_id, ''),
							'nuclei_result_id', f.nuclei_result_id,
							'severity', f.severity,
							'confidence', f.confidence,
							'status', f.status,
							'evidence', f.evidence,
							'report_id', f.report_id,
							'first_seen_at', f.first_seen_at,
							'last_seen_at', f.last_seen_at
						) AS row,
						f.first_seen_at AS sort_at
					FROM zero_candidate_findings f
					LEFT JOIN zero_nuclei_results n ON n.id = f.nuclei_result_id
					LEFT JOIN zero_programs p ON p.id = f.program_id
					LEFT JOIN zero_http_services h ON h.id = f.http_service_id
					LEFT JOIN zero_vulnerability_records v ON v.id = f.vulnerability_id
					WHERE (
						n.scan_run_id IN (SELECT id FROM related_scan_runs)
						OR EXISTS (
							SELECT 1
							FROM zero_change_events ce
							WHERE ce.entity_type = 'candidate_finding'
							  AND ce.entity_id = f.id
							  AND ce.scan_run_id IN (SELECT id FROM related_scan_runs)
						)
					)
					ORDER BY f.first_seen_at DESC
					LIMIT 50
				) recent_findings
			), '[]'::jsonb),
			'nuclei_results', COALESCE((
				SELECT jsonb_agg(row ORDER BY sort_at DESC)
				FROM (
					SELECT
						jsonb_build_object(
							'id', n.id,
							'program_id', n.program_id,
							'program_handle', COALESCE(p.handle, ''),
							'service_url', COALESCE(h.url, ''),
							'template_id', n.template_id,
							'target_source', n.target_source,
							'target_id', n.target_id,
							'matched_at', n.matched_at,
							'severity', n.severity,
							'cves', n.cves,
							'tags', n.tags,
							'first_seen_at', n.first_seen_at
						) AS row,
						n.first_seen_at AS sort_at
					FROM zero_nuclei_results n
					LEFT JOIN zero_programs p ON p.id = n.program_id
					LEFT JOIN zero_http_services h ON h.id = n.http_service_id
					WHERE n.scan_run_id IN (SELECT id FROM related_scan_runs)
					ORDER BY n.first_seen_at DESC
					LIMIT 50
				) recent_nuclei
			), '[]'::jsonb)
		)
		FROM cycle
	`, cycleID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(rows) == 0 {
		writeError(w, http.StatusNotFound, "default scan not found")
		return
	}
	writeRawJSON(w, rows[0])
}

func (s *Server) latestScans(w http.ResponseWriter, r *http.Request) {
	p := listParamsFromRequest(r, 25)
	runType := strings.TrimSpace(r.URL.Query().Get("run_type"))
	rows, err := s.repo.QueryJSONRows(r.Context(), `
		SELECT jsonb_build_object(
			'id', sr.id,
			'program_id', sr.program_id,
			'program_handle', COALESCE(p.handle, ''),
			'program_platform', COALESCE(p.platform, ''),
			'program_url', COALESCE(p.program_url, ''),
			'run_type', sr.run_type,
			'status', sr.status,
			'started_at', sr.started_at,
			'finished_at', sr.finished_at,
			'input_count', sr.input_count,
			'inserted_count', sr.inserted_count,
			'updated_count', sr.updated_count,
			'unchanged_count', sr.unchanged_count,
			'error', sr.error,
			'stats', sr.stats,
			'progress', COALESCE(progress.data, '{}'::jsonb)
		)
		FROM zero_scan_runs sr
		LEFT JOIN zero_programs p ON p.id = sr.program_id
		LEFT JOIN LATERAL (
			SELECT jsonb_build_object(
				'steps_total', 8,
				'child_scan_runs', count(*)::int,
				'child_succeeded', count(*) FILTER (WHERE child.status = 'succeeded')::int,
				'child_failed', count(*) FILTER (WHERE child.status = 'failed')::int,
				'child_incomplete', count(*) FILTER (WHERE child.status = 'incomplete')::int,
				'child_running', count(*) FILTER (WHERE child.status = 'running')::int,
				'current_step', COALESCE((
					SELECT jsonb_build_object(
						'id', latest.id,
						'run_type', latest.run_type,
						'status', latest.status,
						'started_at', latest.started_at,
						'finished_at', latest.finished_at,
						'input_count', latest.input_count,
						'inserted_count', latest.inserted_count,
						'error', latest.error,
						'stats', latest.stats
					)
					FROM zero_scan_runs latest
					WHERE latest.program_id = sr.program_id
					  AND latest.parent_scan_run_id = sr.id
					ORDER BY latest.started_at DESC
					LIMIT 1
				), '{}'::jsonb)
			) AS data
			FROM zero_scan_runs child
			WHERE sr.run_type = 'full'
			  AND child.program_id = sr.program_id
			  AND child.parent_scan_run_id = sr.id
		) progress ON sr.run_type = 'full'
		WHERE ($1 = '' OR sr.run_type = $1)
		ORDER BY sr.started_at DESC
		LIMIT $2 OFFSET $3
	`, runType, p.Limit, p.Offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeRawJSONArray(w, rows)
}

func (s *Server) scanDetail(w http.ResponseWriter, r *http.Request) {
	scanID := r.PathValue("scan_id")
	rows, err := s.repo.QueryJSONRows(r.Context(), `
		WITH scan AS (
			SELECT sr.*, COALESCE(p.handle, '') AS program_handle, COALESCE(p.platform, '') AS program_platform, COALESCE(p.program_url, '') AS program_url
			FROM zero_scan_runs sr
			LEFT JOIN zero_programs p ON p.id = sr.program_id
			WHERE sr.id = $1::uuid
		), related_scan_runs AS (
			SELECT sr.*
			FROM zero_scan_runs sr
			JOIN scan s ON s.id = sr.id OR sr.parent_scan_run_id = s.id
			WHERE sr.id = s.id
			   OR s.run_type = 'full'
		), child_scan_runs AS (
			SELECT sr.*
			FROM related_scan_runs sr
			JOIN scan s ON s.id <> sr.id
		)
		SELECT jsonb_build_object(
			'scan', (
				SELECT jsonb_build_object(
					'id', s.id,
					'program_id', s.program_id,
					'program_handle', s.program_handle,
					'program_platform', s.program_platform,
					'program_url', s.program_url,
					'run_type', s.run_type,
					'status', s.status,
					'started_at', s.started_at,
					'finished_at', s.finished_at,
					'input_count', s.input_count,
					'inserted_count', s.inserted_count,
					'updated_count', s.updated_count,
					'unchanged_count', s.unchanged_count,
					'error', s.error,
					'stats', s.stats
				)
				FROM scan s
			),
			'step_counts', COALESCE((
				SELECT jsonb_object_agg(status, total)
				FROM (
					SELECT status, count(*)::int AS total
					FROM child_scan_runs
					GROUP BY status
				) counts
			), '{}'::jsonb),
			'child_scan_runs', COALESCE((
				SELECT jsonb_agg(row ORDER BY sort_at ASC)
				FROM (
					SELECT
						jsonb_build_object(
							'id', sr.id,
							'run_type', sr.run_type,
							'status', sr.status,
							'started_at', sr.started_at,
							'finished_at', sr.finished_at,
							'input_count', sr.input_count,
							'inserted_count', sr.inserted_count,
							'updated_count', sr.updated_count,
							'unchanged_count', sr.unchanged_count,
							'error', sr.error,
							'stats', sr.stats
						) AS row,
						sr.started_at AS sort_at
					FROM child_scan_runs sr
				) children
			), '[]'::jsonb),
			'finding_counts', jsonb_build_object(
				'total', COALESCE((
					SELECT count(*)::int
					FROM zero_candidate_findings f
					LEFT JOIN zero_nuclei_results n ON n.id = f.nuclei_result_id
					WHERE (
						n.scan_run_id IN (SELECT id FROM related_scan_runs)
						OR EXISTS (
							SELECT 1
							FROM zero_change_events ce
							WHERE ce.entity_type = 'candidate_finding'
							  AND ce.entity_id = f.id
							  AND ce.scan_run_id IN (SELECT id FROM related_scan_runs)
						)
					)
				), 0),
				'nuclei_confirmed', COALESCE((
					SELECT count(*)::int
					FROM zero_candidate_findings f
					JOIN zero_nuclei_results n ON n.id = f.nuclei_result_id
					WHERE n.scan_run_id IN (SELECT id FROM related_scan_runs)
				), 0),
				'passive_unconfirmed', COALESCE((
					SELECT count(*)::int
					FROM zero_candidate_findings f
					WHERE f.nuclei_result_id IS NULL
					  AND EXISTS (
						SELECT 1
						FROM zero_change_events ce
						WHERE ce.entity_type = 'candidate_finding'
						  AND ce.entity_id = f.id
						  AND ce.scan_run_id IN (SELECT id FROM related_scan_runs)
					  )
				), 0)
			),
			'findings', COALESCE((
				SELECT jsonb_agg(row ORDER BY sort_at DESC)
				FROM (
					SELECT
						jsonb_build_object(
							'id', f.id,
							'program_id', f.program_id,
							'program_handle', COALESCE(p.handle, ''),
							'program_platform', COALESCE(p.platform, ''),
							'service_url', COALESCE(h.url, ''),
							'nuclei_template_id', COALESCE(n.template_id, ''),
							'vulnerability_id', COALESCE(v.vuln_id, ''),
							'nuclei_result_id', f.nuclei_result_id,
							'severity', f.severity,
							'confidence', f.confidence,
							'status', f.status,
							'evidence', f.evidence,
							'report_id', f.report_id,
							'first_seen_at', f.first_seen_at,
							'last_seen_at', f.last_seen_at
						) AS row,
						f.first_seen_at AS sort_at
					FROM zero_candidate_findings f
					LEFT JOIN zero_nuclei_results n ON n.id = f.nuclei_result_id
					LEFT JOIN zero_programs p ON p.id = f.program_id
					LEFT JOIN zero_http_services h ON h.id = f.http_service_id
					LEFT JOIN zero_vulnerability_records v ON v.id = f.vulnerability_id
					WHERE (
						n.scan_run_id IN (SELECT id FROM related_scan_runs)
						OR EXISTS (
							SELECT 1
							FROM zero_change_events ce
							WHERE ce.entity_type = 'candidate_finding'
							  AND ce.entity_id = f.id
							  AND ce.scan_run_id IN (SELECT id FROM related_scan_runs)
						)
					)
					ORDER BY f.first_seen_at DESC
					LIMIT 50
				) recent_findings
			), '[]'::jsonb),
			'nuclei_results', COALESCE((
				SELECT jsonb_agg(row ORDER BY sort_at DESC)
				FROM (
					SELECT
						jsonb_build_object(
							'id', n.id,
							'program_id', n.program_id,
							'program_handle', COALESCE(p.handle, ''),
							'service_url', COALESCE(h.url, ''),
							'template_id', n.template_id,
							'target_source', n.target_source,
							'target_id', n.target_id,
							'matched_at', n.matched_at,
							'severity', n.severity,
							'cves', n.cves,
							'tags', n.tags,
							'first_seen_at', n.first_seen_at
						) AS row,
						n.first_seen_at AS sort_at
					FROM zero_nuclei_results n
					LEFT JOIN zero_programs p ON p.id = n.program_id
					LEFT JOIN zero_http_services h ON h.id = n.http_service_id
					WHERE n.scan_run_id IN (SELECT id FROM related_scan_runs)
					ORDER BY n.first_seen_at DESC
					LIMIT 50
				) recent_nuclei
			), '[]'::jsonb)
		)
		FROM scan
	`, scanID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(rows) == 0 {
		writeError(w, http.StatusNotFound, "scan not found")
		return
	}
	writeRawJSON(w, rows[0])
}

func (s *Server) scopeAssets(programID string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		programID = effectiveProgramID(programID, r)
		p := listParamsFromRequest(r, 500)
		q := strings.TrimSpace(r.URL.Query().Get("q"))
		active := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("active")))
		inScope := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("in_scope")))
		bounty := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("eligible_for_bounty")))
		assetType := strings.TrimSpace(r.URL.Query().Get("asset_type"))
		platform := strings.TrimSpace(r.URL.Query().Get("platform"))
		rows, err := s.repo.QueryJSONRows(r.Context(), `
			SELECT jsonb_build_object(
				'id', a.id,
				'program_id', a.program_id,
				'program_handle', COALESCE(p.handle, ''),
				'program_platform', COALESCE(p.platform, ''),
				'last_scan_run_id', a.last_scan_run_id,
				'platform', a.platform,
				'handle', a.handle,
				'asset_type', a.asset_type,
				'target_raw', a.target_raw,
				'target_normalized', a.target_normalized,
				'description', a.description,
				'in_scope', a.in_scope,
				'eligible_for_bounty', a.eligible_for_bounty,
				'active', a.active,
				'source', a.source,
				'metadata', a.metadata,
				'first_seen_at', a.first_seen_at,
				'last_seen_at', a.last_seen_at
			)
			FROM zero_scope_assets a
			LEFT JOIN zero_programs p ON p.id = a.program_id
			WHERE ($1 = '' OR a.program_id::text = $1)
			  AND ($2 = '' OR a.target_normalized ILIKE '%' || $2 || '%' OR a.target_raw ILIKE '%' || $2 || '%' OR a.description ILIKE '%' || $2 || '%' OR p.handle ILIKE '%' || $2 || '%')
			  AND ($3 = '' OR $3 = 'all' OR ($3 IN ('true','active','1') AND a.active) OR ($3 IN ('false','inactive','0') AND NOT a.active))
			  AND ($4 = '' OR $4 = 'all' OR ($4 IN ('true','1') AND a.in_scope) OR ($4 IN ('false','0') AND NOT a.in_scope))
			  AND ($5 = '' OR $5 = 'all' OR ($5 IN ('true','1') AND a.eligible_for_bounty) OR ($5 IN ('false','0') AND NOT a.eligible_for_bounty))
			  AND ($6 = '' OR a.asset_type = $6)
			  AND ($7 = '' OR p.platform = $7 OR a.platform = $7 OR a.source = $7)
			  AND (NULLIF($8, '') IS NULL OR a.last_seen_at > NULLIF($8, '')::timestamptz)
			ORDER BY a.last_seen_at DESC
			LIMIT $9 OFFSET $10
		`, programID, q, active, inScope, bounty, assetType, platform, p.Since, p.Limit, p.Offset)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeRawJSONArray(w, rows)
	}
}

func (s *Server) subdomains(programID string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		programID = effectiveProgramID(programID, r)
		p := listParamsFromRequest(r, 500)
		q := strings.TrimSpace(r.URL.Query().Get("q"))
		active := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("active")))
		resolves := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("resolves")))
		platform := strings.TrimSpace(r.URL.Query().Get("platform"))
		if q == "" && programID == "" && platform == "" && resolves == "" && p.Since == "" && isTruthyFilter(active) {
			rows, err := s.repo.QueryJSONRows(r.Context(), `
				WITH page AS MATERIALIZED (
					SELECT *
					FROM zero_subdomains
					WHERE active
					ORDER BY last_seen_at DESC
					LIMIT $1 OFFSET $2
				),
				service_counts AS (
					SELECT h.subdomain_id, count(*)::int AS service_count
					FROM zero_http_services h
					JOIN page sd ON sd.id = h.subdomain_id
					WHERE h.active
					GROUP BY h.subdomain_id
				)
				SELECT jsonb_build_object(
					'id', sd.id,
					'program_id', sd.program_id,
					'program_handle', COALESCE(p.handle, ''),
					'program_platform', COALESCE(p.platform, ''),
					'scope_asset_id', sd.scope_asset_id,
					'last_scan_run_id', sd.last_scan_run_id,
					'root_domain', sd.root_domain,
					'fqdn', sd.fqdn,
					'source', sd.source,
					'resolves', sd.resolves,
					'active', sd.active,
					'metadata', sd.metadata,
					'first_seen_at', sd.first_seen_at,
					'last_seen_at', sd.last_seen_at,
					'service_count', COALESCE(hs.service_count, 0)
				)
				FROM page sd
				LEFT JOIN zero_programs p ON p.id = sd.program_id
				LEFT JOIN service_counts hs ON hs.subdomain_id = sd.id
				ORDER BY sd.last_seen_at DESC
			`, p.Limit, p.Offset)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeRawJSONArray(w, rows)
			return
		}
		rows, err := s.repo.QueryJSONRows(r.Context(), `
			SELECT jsonb_build_object(
				'id', sd.id,
				'program_id', sd.program_id,
				'program_handle', COALESCE(p.handle, ''),
				'program_platform', COALESCE(p.platform, ''),
				'scope_asset_id', sd.scope_asset_id,
				'last_scan_run_id', sd.last_scan_run_id,
				'root_domain', sd.root_domain,
				'fqdn', sd.fqdn,
				'source', sd.source,
				'resolves', sd.resolves,
				'active', sd.active,
				'metadata', sd.metadata,
				'first_seen_at', sd.first_seen_at,
				'last_seen_at', sd.last_seen_at,
				'service_count', COALESCE(hs.service_count, 0)
			)
			FROM zero_subdomains sd
			LEFT JOIN zero_programs p ON p.id = sd.program_id
			LEFT JOIN LATERAL (
				SELECT count(*)::int AS service_count
				FROM zero_http_services h
				WHERE h.subdomain_id = sd.id
				  AND h.active
			) hs ON true
			WHERE ($1 = '' OR sd.program_id::text = $1)
			  AND ($2 = '' OR sd.fqdn ILIKE '%' || $2 || '%' OR sd.root_domain ILIKE '%' || $2 || '%' OR p.handle ILIKE '%' || $2 || '%')
			  AND ($3 = '' OR $3 = 'all' OR ($3 IN ('true','active','1') AND sd.active) OR ($3 IN ('false','inactive','0') AND NOT sd.active))
			  AND ($4 = '' OR $4 = 'all' OR ($4 IN ('true','1') AND sd.resolves IS TRUE) OR ($4 IN ('false','0') AND sd.resolves IS FALSE) OR ($4 = 'unknown' AND sd.resolves IS NULL))
			  AND ($5 = '' OR p.platform = $5 OR sd.source = $5)
			  AND (NULLIF($6, '') IS NULL OR sd.last_seen_at > NULLIF($6, '')::timestamptz)
			ORDER BY sd.last_seen_at DESC
			LIMIT $7 OFFSET $8
		`, programID, q, active, resolves, platform, p.Since, p.Limit, p.Offset)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeRawJSONArray(w, rows)
	}
}

func (s *Server) services(programID string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		programID = effectiveProgramID(programID, r)
		p := listParamsFromRequest(r, 500)
		q := strings.TrimSpace(r.URL.Query().Get("q"))
		active := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("active")))
		statusCode := queryInt(r, "status_code", 0)
		platform := strings.TrimSpace(r.URL.Query().Get("platform"))
		rows, err := s.repo.QueryJSONRows(r.Context(), `
			SELECT jsonb_build_object(
				'id', h.id,
				'program_id', h.program_id,
				'program_handle', COALESCE(p.handle, ''),
				'program_platform', COALESCE(p.platform, ''),
				'subdomain_id', h.subdomain_id,
				'last_scan_run_id', h.last_scan_run_id,
				'url', h.url,
				'scheme', h.scheme,
				'host', h.host,
				'port', h.port,
				'status_code', h.status_code,
				'title', h.title,
				'webserver', h.webserver,
				'technologies', h.technologies,
				'favicon_hash', h.favicon_hash,
				'tls', h.tls,
				'raw', h.raw,
				'active', h.active,
				'first_seen_at', h.first_seen_at,
				'last_seen_at', h.last_seen_at
			)
			FROM zero_http_services h
			LEFT JOIN zero_programs p ON p.id = h.program_id
			WHERE ($1 = '' OR h.program_id::text = $1)
			  AND ($2 = '' OR h.host ILIKE '%' || $2 || '%' OR h.url ILIKE '%' || $2 || '%' OR h.title ILIKE '%' || $2 || '%' OR h.webserver ILIKE '%' || $2 || '%' OR p.handle ILIKE '%' || $2 || '%')
			  AND ($3 = '' OR $3 = 'all' OR ($3 IN ('true','active','1') AND h.active) OR ($3 IN ('false','inactive','0') AND NOT h.active))
			  AND ($4 = 0 OR h.status_code = $4)
			  AND ($5 = '' OR p.platform = $5)
			  AND (NULLIF($6, '') IS NULL OR h.last_seen_at > NULLIF($6, '')::timestamptz)
			ORDER BY h.last_seen_at DESC
			LIMIT $7 OFFSET $8
		`, programID, q, active, statusCode, platform, p.Since, p.Limit, p.Offset)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeRawJSONArray(w, rows)
	}
}

func (s *Server) nucleiResults(programID string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		programID = effectiveProgramID(programID, r)
		p := listParamsFromRequest(r, 500)
		q := strings.TrimSpace(r.URL.Query().Get("q"))
		platform := strings.TrimSpace(r.URL.Query().Get("platform"))
		rows, err := s.repo.QueryJSONRows(r.Context(), `
			SELECT jsonb_build_object(
				'id', n.id,
				'program_id', n.program_id,
				'program_handle', COALESCE(p.handle, ''),
				'program_platform', COALESCE(p.platform, ''),
				'scan_run_id', n.scan_run_id,
				'http_service_id', n.http_service_id,
				'service_url', COALESCE(h.url, ''),
				'service_host', COALESCE(h.host, ''),
				'template_id', n.template_id,
				'template_path', n.template_path,
				'target_source', n.target_source,
				'target_id', n.target_id,
				'matched_at', n.matched_at,
				'severity', n.severity,
				'cves', n.cves,
				'tags', n.tags,
				'type', n.type,
				'extractor_name', n.extractor_name,
				'evidence_hash', n.evidence_hash,
				'raw', n.raw,
				'first_seen_at', n.first_seen_at,
				'last_seen_at', n.last_seen_at
			)
			FROM zero_nuclei_results n
			LEFT JOIN zero_programs p ON p.id = n.program_id
			LEFT JOIN zero_http_services h ON h.id = n.http_service_id
			WHERE ($1 = '' OR n.program_id::text = $1)
			  AND ($2 = '' OR n.severity = $2)
			  AND ($3 = '' OR n.template_id = $3)
			  AND ($4 = '' OR n.template_id ILIKE '%' || $4 || '%' OR n.matched_at ILIKE '%' || $4 || '%' OR n.template_path ILIKE '%' || $4 || '%' OR h.url ILIKE '%' || $4 || '%' OR h.host ILIKE '%' || $4 || '%' OR p.handle ILIKE '%' || $4 || '%' OR $4 = ANY(n.cves) OR $4 = ANY(n.tags))
			  AND ($5 = '' OR p.platform = $5)
			  AND (NULLIF($6, '') IS NULL OR n.first_seen_at > NULLIF($6, '')::timestamptz)
			ORDER BY n.first_seen_at DESC
			LIMIT $7 OFFSET $8
		`, programID, strings.TrimSpace(r.URL.Query().Get("severity")), strings.TrimSpace(r.URL.Query().Get("template_id")), q, platform, p.Since, p.Limit, p.Offset)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeRawJSONArray(w, rows)
	}
}

func (s *Server) findings(programID string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		programID = effectiveProgramID(programID, r)
		p := listParamsFromRequest(r, 500)
		q := strings.TrimSpace(r.URL.Query().Get("q"))
		platform := strings.TrimSpace(r.URL.Query().Get("platform"))
		rows, err := s.repo.QueryJSONRows(r.Context(), `
			SELECT jsonb_build_object(
				'id', f.id,
				'program_id', f.program_id,
				'program_handle', COALESCE(p.handle, ''),
				'program_platform', COALESCE(p.platform, ''),
				'http_service_id', f.http_service_id,
				'service_url', COALESCE(s.url, ''),
				'service_host', COALESCE(s.host, ''),
				'service_status_code', s.status_code,
				'service_title', COALESCE(s.title, ''),
				'service_webserver', COALESCE(s.webserver, ''),
				'nuclei_result_id', f.nuclei_result_id,
				'vulnerability_id', COALESCE(v.vuln_id, ''),
				'technology_name', f.technology_name,
				'technology_version', f.technology_version,
				'severity', f.severity,
				'confidence', f.confidence,
				'status', f.status,
				'evidence_hash', f.evidence_hash,
				'evidence', f.evidence,
				'report_id', f.report_id,
				'first_seen_at', f.first_seen_at,
				'last_seen_at', f.last_seen_at
			)
			FROM zero_candidate_findings f
			LEFT JOIN zero_http_services s ON s.id = f.http_service_id
			LEFT JOIN zero_programs p ON p.id = f.program_id
			LEFT JOIN zero_vulnerability_records v ON v.id = f.vulnerability_id
			WHERE ($1 = '' OR f.program_id::text = $1)
			  AND ($2 = '' OR f.status = $2)
			  AND ($3 = '' OR f.severity = $3)
			  AND ($4 = 0 OR f.confidence >= $4)
			  AND ($5 = '' OR f.technology_name ILIKE '%' || $5 || '%' OR f.technology_version ILIKE '%' || $5 || '%' OR f.severity ILIKE '%' || $5 || '%' OR s.url ILIKE '%' || $5 || '%' OR s.host ILIKE '%' || $5 || '%' OR p.handle ILIKE '%' || $5 || '%' OR v.vuln_id ILIKE '%' || $5 || '%')
			  AND ($6 = '' OR p.platform = $6)
			  AND (NULLIF($7, '') IS NULL OR f.first_seen_at > NULLIF($7, '')::timestamptz)
			ORDER BY f.first_seen_at DESC
			LIMIT $8 OFFSET $9
		`, programID, strings.TrimSpace(r.URL.Query().Get("status")), strings.TrimSpace(r.URL.Query().Get("severity")), queryInt(r, "min_confidence", 0), q, platform, p.Since, p.Limit, p.Offset)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeRawJSONArray(w, rows)
	}
}

func (s *Server) reports(programID string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		programID = effectiveProgramID(programID, r)
		p := listParamsFromRequest(r, 500)
		q := strings.TrimSpace(r.URL.Query().Get("q"))
		platform := strings.TrimSpace(r.URL.Query().Get("platform"))
		rows, err := s.repo.QueryJSONRows(r.Context(), `
			SELECT jsonb_build_object(
				'id', r.id,
				'program_id', r.program_id,
				'program_handle', COALESCE(p.handle, ''),
				'program_platform', COALESCE(p.platform, ''),
				'scan_run_id', r.scan_run_id,
				'report_key', r.report_key,
				'title', r.title,
				'severity', r.severity,
				'confidence', r.confidence,
				'body_markdown', CASE WHEN $3 THEN r.body_markdown ELSE '' END,
				'finding_ids', r.finding_ids,
				'created_at', r.created_at,
				'metadata', r.metadata
			)
			FROM zero_reports r
			LEFT JOIN zero_programs p ON p.id = r.program_id
			WHERE ($1 = '' OR r.program_id::text = $1)
			  AND ($2 = '' OR r.severity = $2)
			  AND ($4 = '' OR r.report_key ILIKE '%' || $4 || '%' OR r.title ILIKE '%' || $4 || '%' OR p.handle ILIKE '%' || $4 || '%')
			  AND ($5 = '' OR p.platform = $5)
			  AND (NULLIF($6, '') IS NULL OR r.created_at > NULLIF($6, '')::timestamptz)
			ORDER BY r.created_at DESC
			LIMIT $7 OFFSET $8
		`, programID, strings.TrimSpace(r.URL.Query().Get("severity")), queryBool(r, "include_body", false), q, platform, p.Since, p.Limit, p.Offset)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeRawJSONArray(w, rows)
	}
}

func (s *Server) scanRuns(w http.ResponseWriter, r *http.Request) {
	p := listParamsFromRequest(r, 500)
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	runType := strings.TrimSpace(r.URL.Query().Get("run_type"))
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	programID := strings.TrimSpace(r.URL.Query().Get("program_id"))
	platform := strings.TrimSpace(r.URL.Query().Get("platform"))
	rows, err := s.repo.QueryJSONRows(r.Context(), `
		SELECT jsonb_build_object(
			'id', sr.id,
			'program_id', sr.program_id,
			'program_handle', COALESCE(p.handle, ''),
			'program_platform', COALESCE(p.platform, ''),
			'default_scan_cycle_id', sr.default_scan_cycle_id,
			'parent_scan_run_id', sr.parent_scan_run_id,
			'scan_request_id', sr.scan_request_id,
			'scan_campaign_id', sr.scan_campaign_id,
			'run_type', sr.run_type,
			'status', sr.status,
			'started_at', sr.started_at,
			'finished_at', sr.finished_at,
			'worker_id', sr.worker_id,
			'input_count', sr.input_count,
			'inserted_count', sr.inserted_count,
			'updated_count', sr.updated_count,
			'unchanged_count', sr.unchanged_count,
			'error', sr.error,
			'stats', sr.stats
		)
		FROM zero_scan_runs sr
		LEFT JOIN zero_programs p ON p.id = sr.program_id
		WHERE ($1 = '' OR sr.program_id::text = $1)
		  AND ($2 = '' OR sr.run_type = $2)
		  AND ($3 = '' OR sr.status = $3)
		  AND ($4 = '' OR p.handle ILIKE '%' || $4 || '%' OR sr.run_type ILIKE '%' || $4 || '%' OR sr.status ILIKE '%' || $4 || '%' OR sr.error ILIKE '%' || $4 || '%')
		  AND ($5 = '' OR p.platform = $5)
		  AND (NULLIF($6, '') IS NULL OR sr.started_at > NULLIF($6, '')::timestamptz)
		ORDER BY sr.started_at DESC
		LIMIT $7 OFFSET $8
	`, programID, runType, status, q, platform, p.Since, p.Limit, p.Offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeRawJSONArray(w, rows)
}

func (s *Server) technologies(programID string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		programID = effectiveProgramID(programID, r)
		p := listParamsFromRequest(r, 500)
		q := strings.TrimSpace(r.URL.Query().Get("q"))
		active := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("active")))
		source := strings.TrimSpace(r.URL.Query().Get("source"))
		versioned := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("versioned")))
		platform := strings.TrimSpace(r.URL.Query().Get("platform"))
		rows, err := s.repo.QueryJSONRows(r.Context(), `
			SELECT jsonb_build_object(
				'id', t.id,
				'program_id', t.program_id,
				'program_handle', COALESCE(p.handle, ''),
				'program_platform', COALESCE(p.platform, ''),
				'http_service_id', t.http_service_id,
				'service_url', COALESCE(h.url, ''),
				'service_host', COALESCE(h.host, ''),
				'last_scan_run_id', t.last_scan_run_id,
				'name', t.name,
				'version', t.version,
				'source', t.source,
				'confidence', t.confidence,
				'active', t.active,
				'evidence', t.evidence,
				'first_seen_at', t.first_seen_at,
				'last_seen_at', t.last_seen_at
			)
			FROM zero_technology_observations t
			LEFT JOIN zero_programs p ON p.id = t.program_id
			LEFT JOIN zero_http_services h ON h.id = t.http_service_id
			WHERE ($1 = '' OR t.program_id::text = $1)
			  AND ($2 = '' OR t.name ILIKE '%' || $2 || '%' OR t.version ILIKE '%' || $2 || '%' OR t.source ILIKE '%' || $2 || '%' OR h.url ILIKE '%' || $2 || '%' OR h.host ILIKE '%' || $2 || '%' OR p.handle ILIKE '%' || $2 || '%')
			  AND ($3 = '' OR $3 = 'all' OR ($3 IN ('true','active','1') AND t.active) OR ($3 IN ('false','inactive','0') AND NOT t.active))
			  AND ($4 = '' OR t.source = $4)
			  AND ($5 = '' OR $5 = 'all' OR ($5 IN ('true','1') AND t.version <> '') OR ($5 IN ('false','0') AND t.version = ''))
			  AND ($6 = '' OR p.platform = $6)
			  AND (NULLIF($7, '') IS NULL OR t.last_seen_at > NULLIF($7, '')::timestamptz)
			ORDER BY t.last_seen_at DESC
			LIMIT $8 OFFSET $9
		`, programID, q, active, source, versioned, platform, p.Since, p.Limit, p.Offset)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeRawJSONArray(w, rows)
	}
}

func (s *Server) technologyVulnerabilities(programID string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		programID = effectiveProgramID(programID, r)
		p := listParamsFromRequest(r, 500)
		q := strings.TrimSpace(r.URL.Query().Get("q"))
		severity := strings.TrimSpace(r.URL.Query().Get("severity"))
		minConfidence := queryInt(r, "min_confidence", 0)
		platform := strings.TrimSpace(r.URL.Query().Get("platform"))
		rows, err := s.repo.QueryJSONRows(r.Context(), `
			SELECT jsonb_build_object(
				'id', m.id,
				'program_id', m.program_id,
				'program_handle', COALESCE(p.handle, ''),
				'program_platform', COALESCE(p.platform, ''),
				'http_service_id', m.http_service_id,
				'service_url', COALESCE(h.url, ''),
				'service_host', COALESCE(h.host, ''),
				'vulnerability_id', v.vuln_id,
				'technology_name', m.technology_name,
				'technology_version', m.technology_version,
				'source_observation', m.source_observation,
				'source_query', m.source_query,
				'confidence', m.confidence,
				'severity', v.severity,
				'cvss_score', v.cvss_score,
				'summary', v.summary,
				'references', v.references_json,
				'evidence', m.evidence,
				'first_seen_at', m.first_seen_at,
				'last_seen_at', m.last_seen_at
			)
			FROM zero_technology_vulnerability_matches m
			JOIN zero_vulnerability_records v ON v.id = m.vulnerability_id
			LEFT JOIN zero_programs p ON p.id = m.program_id
			LEFT JOIN zero_http_services h ON h.id = m.http_service_id
			WHERE ($1 = '' OR m.program_id::text = $1)
			  AND ($2 = '' OR m.technology_name ILIKE '%' || $2 || '%' OR m.technology_version ILIKE '%' || $2 || '%' OR v.vuln_id ILIKE '%' || $2 || '%' OR v.summary ILIKE '%' || $2 || '%' OR h.url ILIKE '%' || $2 || '%' OR p.handle ILIKE '%' || $2 || '%')
			  AND ($3 = '' OR v.severity = $3)
			  AND ($4 = 0 OR m.confidence >= $4)
			  AND ($5 = '' OR p.platform = $5)
			  AND (NULLIF($6, '') IS NULL OR m.last_seen_at > NULLIF($6, '')::timestamptz)
			ORDER BY m.last_seen_at DESC, m.confidence DESC
			LIMIT $7 OFFSET $8
		`, programID, q, severity, minConfidence, platform, p.Since, p.Limit, p.Offset)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeRawJSONArray(w, rows)
	}
}

func (s *Server) vulnerabilityRecords(w http.ResponseWriter, r *http.Request) {
	p := listParamsFromRequest(r, 500)
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	severity := strings.TrimSpace(r.URL.Query().Get("severity"))
	rows, err := s.repo.QueryJSONRows(r.Context(), `
		SELECT jsonb_build_object(
			'id', v.id,
			'vuln_id', v.vuln_id,
			'source', v.source,
			'summary', v.summary,
			'severity', v.severity,
			'cvss_score', v.cvss_score,
			'published_at', v.published_at,
			'modified_at', v.modified_at,
			'references', v.references_json,
			'raw', v.raw,
			'first_seen_at', v.first_seen_at,
			'last_seen_at', v.last_seen_at,
			'match_count', COALESCE(matches.match_count, 0),
			'finding_count', COALESCE(findings.finding_count, 0)
		)
		FROM zero_vulnerability_records v
		LEFT JOIN LATERAL (
			SELECT count(*)::int AS match_count
			FROM zero_technology_vulnerability_matches m
			WHERE m.vulnerability_id = v.id
		) matches ON true
		LEFT JOIN LATERAL (
			SELECT count(*)::int AS finding_count
			FROM zero_candidate_findings f
			WHERE f.vulnerability_id = v.id
		) findings ON true
		WHERE ($1 = '' OR v.vuln_id ILIKE '%' || $1 || '%' OR v.summary ILIKE '%' || $1 || '%' OR v.source ILIKE '%' || $1 || '%')
		  AND ($2 = '' OR v.severity = $2)
		  AND (NULLIF($3, '') IS NULL OR v.last_seen_at > NULLIF($3, '')::timestamptz)
		ORDER BY v.last_seen_at DESC
		LIMIT $4 OFFSET $5
	`, q, severity, p.Since, p.Limit, p.Offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeRawJSONArray(w, rows)
}

type listParams struct {
	Limit  int
	Offset int
	Since  string
}

func listParamsFromRequest(r *http.Request, defaultLimit int) listParams {
	limit := queryInt(r, "limit", defaultLimit)
	if limit < 1 {
		limit = defaultLimit
	}
	if limit > 1000 {
		limit = 1000
	}
	offset := queryInt(r, "offset", 0)
	if offset < 0 {
		offset = 0
	}
	return listParams{
		Limit:  limit,
		Offset: offset,
		Since:  strings.TrimSpace(r.URL.Query().Get("since")),
	}
}

func effectiveProgramID(pathProgramID string, r *http.Request) string {
	if strings.TrimSpace(pathProgramID) != "" {
		return strings.TrimSpace(pathProgramID)
	}
	return strings.TrimSpace(r.URL.Query().Get("program_id"))
}

func isTruthyFilter(value string) bool {
	switch strings.TrimSpace(strings.ToLower(value)) {
	case "true", "active", "1", "yes", "y", "on":
		return true
	default:
		return false
	}
}

func queryInt(r *http.Request, name string, fallback int) int {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return n
}

func queryBool(r *http.Request, name string, fallback bool) bool {
	raw := strings.TrimSpace(strings.ToLower(r.URL.Query().Get(name)))
	if raw == "" {
		return fallback
	}
	switch raw {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return fallback
	}
}

func (s *Server) createScanRequest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ProgramID   string          `json:"program_id"`
		Name        string          `json:"name"`
		RunAfter    string          `json:"run_after"`
		Params      json.RawMessage `json:"params"`
		AllPrograms bool            `json:"all_programs"`
		DueOnly     bool            `json:"due_only"`
		Limit       int             `json:"limit"`
		Parallelism int             `json:"parallelism"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	runAfter := time.Now().UTC()
	if strings.TrimSpace(body.RunAfter) != "" {
		parsed, err := parseRunAfter(body.RunAfter)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		runAfter = parsed
	}
	params := json.RawMessage(`{}`)
	if len(body.Params) > 0 {
		params = body.Params
	}
	if body.AllPrograms {
		result, err := s.repo.CreateStagedScanCampaign(r.Context(), strings.TrimSpace(body.Name), "api", runAfter, params, body.DueOnly, body.Limit, body.Parallelism)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.stageScanCampaign(result.ID)
		writeJSON(w, http.StatusAccepted, map[string]any{
			"id":          result.ID,
			"type":        "scan_campaign",
			"status":      result.Status,
			"total":       result.Total,
			"queued":      result.Queued,
			"due_only":    result.DueOnly,
			"limit":       result.Limit,
			"parallelism": result.Parallel,
			"run_after":   runAfter,
		})
		return
	}
	id, err := s.repo.CreateScanRequest(r.Context(), strings.TrimSpace(body.ProgramID), strings.TrimSpace(body.Name), "api", runAfter, params)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"id":         id,
		"program_id": body.ProgramID,
		"run_after":  runAfter,
	})
}

func (s *Server) cancelScanRequest(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("request_id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "request id is required")
		return
	}
	result, err := s.repo.CancelScanRequest(r.Context(), id)
	if err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "not found") {
			status = http.StatusNotFound
		}
		writeError(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, result)
}

func (s *Server) cancelScanCampaign(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("campaign_id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "campaign id is required")
		return
	}
	result, err := s.repo.CancelScanCampaign(r.Context(), id)
	if err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "not found") {
			status = http.StatusNotFound
		}
		writeError(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, result)
}

func (s *Server) stageScanCampaign(campaignID string) {
	campaignID = strings.TrimSpace(campaignID)
	if campaignID == "" {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		if _, err := s.repo.StageScanCampaignRequests(ctx, campaignID); err != nil {
			failCtx, failCancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer failCancel()
			_ = s.repo.FailStagingScanCampaign(failCtx, campaignID, err)
		}
	}()
}

func (s *Server) recoverStagingScanCampaigns() {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		ids, err := s.repo.ListStagingScanCampaigns(ctx, 50)
		cancel()
		if err != nil {
			return
		}
		for _, id := range ids {
			s.stageScanCampaign(id)
		}
	}()
}

func parseRunAfter(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "now") {
		return time.Now().UTC(), nil
	}
	if d, err := time.ParseDuration(value); err == nil {
		return time.Now().UTC().Add(d), nil
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid run_after %q: use a duration like 30m or an RFC3339 timestamp", value)
	}
	return t, nil
}

func (s *Server) changes(programID string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		programID = effectiveProgramID(programID, r)
		p := listParamsFromRequest(r, 500)
		q := strings.TrimSpace(r.URL.Query().Get("q"))
		entityType := strings.TrimSpace(r.URL.Query().Get("entity_type"))
		changeType := strings.TrimSpace(r.URL.Query().Get("change_type"))
		platform := strings.TrimSpace(r.URL.Query().Get("platform"))
		rows, err := s.repo.QueryJSONRows(r.Context(), `
			SELECT jsonb_build_object(
				'id', c.id,
				'program_id', c.program_id,
				'program_handle', COALESCE(p.handle, ''),
				'program_platform', COALESCE(p.platform, ''),
				'scan_run_id', c.scan_run_id,
				'entity_type', c.entity_type,
				'entity_id', c.entity_id,
				'entity_key', c.entity_key,
				'change_type', c.change_type,
				'old_value', c.old_value,
				'new_value', c.new_value,
				'occurred_at', c.occurred_at
			)
			FROM zero_change_events c
			LEFT JOIN zero_programs p ON p.id = c.program_id
			WHERE ($1 = '' OR c.program_id::text = $1)
			  AND ($2 = '' OR c.entity_type = $2)
			  AND ($3 = '' OR c.change_type = $3)
			  AND ($4 = '' OR c.entity_key ILIKE '%' || $4 || '%' OR c.entity_type ILIKE '%' || $4 || '%' OR p.handle ILIKE '%' || $4 || '%')
			  AND ($5 = '' OR p.platform = $5)
			  AND (NULLIF($6, '') IS NULL OR c.occurred_at > NULLIF($6, '')::timestamptz)
			ORDER BY c.occurred_at DESC
			LIMIT $7 OFFSET $8
		`, programID, entityType, changeType, q, platform, p.Since, p.Limit, p.Offset)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeRawJSONArray(w, rows)
	}
}

func (s *Server) query(sql string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := s.repo.QueryJSONRows(r.Context(), sql)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeRawJSONArray(w, rows)
	}
}

func (s *Server) cachedJSONRow(w http.ResponseWriter, r *http.Request, key string, ttl time.Duration, sql string, args ...any) {
	now := time.Now()
	s.cacheMu.Lock()
	if item, ok := s.cache[key]; ok && now.Before(item.expires) {
		body := append(json.RawMessage(nil), item.body...)
		s.cacheMu.Unlock()
		writeRawJSON(w, body)
		return
	}
	s.cacheMu.Unlock()

	rows, err := s.repo.QueryJSONRows(r.Context(), sql, args...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(rows) == 0 {
		writeError(w, http.StatusNotFound, "record not found")
		return
	}
	body := append(json.RawMessage(nil), rows[0]...)
	s.cacheMu.Lock()
	s.cache[key] = cachedJSON{body: body, expires: now.Add(ttl)}
	s.cacheMu.Unlock()
	writeRawJSON(w, body)
}

func writeRawJSONArray(w http.ResponseWriter, rows []json.RawMessage) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("["))
	for i, row := range rows {
		if i > 0 {
			_, _ = w.Write([]byte(","))
		}
		_, _ = w.Write(row)
	}
	_, _ = w.Write([]byte("]"))
}

func writeRawJSON(w http.ResponseWriter, row json.RawMessage) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(row)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}

func Shutdown(ctx context.Context, srv *http.Server) error {
	if srv == nil {
		return nil
	}
	if err := srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown api server: %w", err)
	}
	return nil
}
