package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rafabd1/ZERO/internal/db"
)

type Server struct {
	repo  *db.Repository
	token string
	mux   *http.ServeMux
}

func NewServer(repo *db.Repository, token string) *Server {
	s := &Server{
		repo:  repo,
		token: token,
		mux:   http.NewServeMux(),
	}
	s.routes()
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
	s.mux.HandleFunc("GET /v1/programs", s.query(`
		SELECT jsonb_build_object(
			'id', id,
			'platform', platform,
			'handle', handle,
			'program_url', program_url,
			'active', active,
			'scan_interval_hours', scan_interval_hours,
			'last_scan_started_at', last_scan_started_at,
			'last_scan_finished_at', last_scan_finished_at,
			'first_seen_at', first_seen_at,
			'last_seen_at', last_seen_at
		)
		FROM zero_programs
		ORDER BY platform, handle
	`))
	s.mux.HandleFunc("GET /v1/assets", s.query(`
		SELECT jsonb_build_object(
			'id', a.id,
			'program_id', a.program_id,
			'last_scan_run_id', a.last_scan_run_id,
			'asset_type', a.asset_type,
			'target_normalized', a.target_normalized,
			'in_scope', a.in_scope,
			'eligible_for_bounty', a.eligible_for_bounty,
			'active', a.active,
			'first_seen_at', a.first_seen_at,
			'last_seen_at', a.last_seen_at
		)
		FROM zero_scope_assets a
		WHERE a.active = true
		ORDER BY a.last_seen_at DESC
		LIMIT 500
	`))
	s.mux.HandleFunc("GET /v1/services", s.services(""))
	s.mux.HandleFunc("GET /v1/technologies", s.technologies(""))
	s.mux.HandleFunc("GET /v1/technology-vulnerabilities", s.technologyVulnerabilities(""))
	s.mux.HandleFunc("GET /v1/nuclei-results", s.nucleiResults(""))
	s.mux.HandleFunc("GET /v1/findings", s.findings(""))
	s.mux.HandleFunc("GET /v1/reports", s.reports(""))
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
	s.mux.HandleFunc("GET /v1/scans/latest", s.query(`
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
		ORDER BY sr.started_at DESC
		LIMIT 25
	`))
	s.mux.HandleFunc("GET /v1/scan-requests", s.query(`
		SELECT jsonb_build_object(
			'id', r.id,
			'program_id', r.program_id,
			'name', r.name,
			'status', r.status,
			'requested_by', r.requested_by,
			'run_after', r.run_after,
			'attempt_count', r.attempt_count,
			'started_at', r.started_at,
			'finished_at', r.finished_at,
			'error', r.error,
			'params', r.params,
			'created_at', r.created_at,
			'updated_at', r.updated_at
		)
		FROM zero_scan_requests r
		ORDER BY r.created_at DESC
		LIMIT 100
	`))
	s.mux.HandleFunc("POST /v1/scan-requests", s.createScanRequest)
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
	s.mux.HandleFunc("GET /v1/programs/{program_id}/changes", func(w http.ResponseWriter, r *http.Request) {
		s.changes(r.PathValue("program_id"))(w, r)
	})
	s.mux.HandleFunc("GET /v1/programs/{program_id}/assets", func(w http.ResponseWriter, r *http.Request) {
		programID := r.PathValue("program_id")
		rows, err := s.repo.QueryJSONRows(r.Context(), `
			SELECT jsonb_build_object(
				'id', a.id,
				'program_id', a.program_id,
				'last_scan_run_id', a.last_scan_run_id,
				'asset_type', a.asset_type,
				'target_normalized', a.target_normalized,
				'in_scope', a.in_scope,
				'eligible_for_bounty', a.eligible_for_bounty,
				'active', a.active,
				'first_seen_at', a.first_seen_at,
				'last_seen_at', a.last_seen_at
			)
			FROM zero_scope_assets a
			WHERE a.program_id = $1::uuid
			ORDER BY a.last_seen_at DESC
			LIMIT 500
		`, programID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeRawJSONArray(w, rows)
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
}

func (s *Server) services(programID string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := listParamsFromRequest(r, 500)
		rows, err := s.repo.QueryJSONRows(r.Context(), `
			SELECT jsonb_build_object(
				'id', s.id,
				'program_id', s.program_id,
				'last_scan_run_id', s.last_scan_run_id,
				'url', s.url,
				'host', s.host,
				'status_code', s.status_code,
				'title', s.title,
				'webserver', s.webserver,
				'technologies', s.technologies,
				'first_seen_at', s.first_seen_at,
				'last_seen_at', s.last_seen_at
			)
			FROM zero_http_services s
			WHERE s.active = true
			  AND ($1 = '' OR s.program_id::text = $1)
			  AND ($2 = '' OR s.host ILIKE '%' || $2 || '%' OR s.url ILIKE '%' || $2 || '%')
			  AND ($3 = '' OR s.last_seen_at > $3::timestamptz)
			ORDER BY s.last_seen_at DESC
			LIMIT $4 OFFSET $5
		`, programID, strings.TrimSpace(r.URL.Query().Get("q")), p.Since, p.Limit, p.Offset)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeRawJSONArray(w, rows)
	}
}

func (s *Server) nucleiResults(programID string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := listParamsFromRequest(r, 500)
		rows, err := s.repo.QueryJSONRows(r.Context(), `
			SELECT jsonb_build_object(
				'id', n.id,
				'program_id', n.program_id,
				'scan_run_id', n.scan_run_id,
				'http_service_id', n.http_service_id,
				'template_id', n.template_id,
				'matched_at', n.matched_at,
				'severity', n.severity,
				'cves', n.cves,
				'tags', n.tags,
				'first_seen_at', n.first_seen_at,
				'last_seen_at', n.last_seen_at
			)
			FROM zero_nuclei_results n
			WHERE ($1 = '' OR n.program_id::text = $1)
			  AND ($2 = '' OR n.severity = $2)
			  AND ($3 = '' OR n.template_id = $3)
			  AND ($4 = '' OR n.first_seen_at > $4::timestamptz)
			ORDER BY n.first_seen_at DESC
			LIMIT $5 OFFSET $6
		`, programID, strings.TrimSpace(r.URL.Query().Get("severity")), strings.TrimSpace(r.URL.Query().Get("template_id")), p.Since, p.Limit, p.Offset)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeRawJSONArray(w, rows)
	}
}

func (s *Server) findings(programID string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := listParamsFromRequest(r, 500)
		rows, err := s.repo.QueryJSONRows(r.Context(), `
			SELECT jsonb_build_object(
				'id', f.id,
				'program_id', f.program_id,
				'http_service_id', f.http_service_id,
				'nuclei_result_id', f.nuclei_result_id,
				'severity', f.severity,
				'confidence', f.confidence,
				'status', f.status,
				'evidence', f.evidence,
				'report_id', f.report_id,
				'first_seen_at', f.first_seen_at,
				'last_seen_at', f.last_seen_at
			)
			FROM zero_candidate_findings f
			WHERE ($1 = '' OR f.program_id::text = $1)
			  AND ($2 = '' OR f.status = $2)
			  AND ($3 = '' OR f.severity = $3)
			  AND ($4 = 0 OR f.confidence >= $4)
			  AND ($5 = '' OR f.first_seen_at > $5::timestamptz)
			ORDER BY f.first_seen_at DESC
			LIMIT $6 OFFSET $7
		`, programID, strings.TrimSpace(r.URL.Query().Get("status")), strings.TrimSpace(r.URL.Query().Get("severity")), queryInt(r, "min_confidence", 0), p.Since, p.Limit, p.Offset)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeRawJSONArray(w, rows)
	}
}

func (s *Server) reports(programID string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := listParamsFromRequest(r, 500)
		rows, err := s.repo.QueryJSONRows(r.Context(), `
			SELECT jsonb_build_object(
				'id', r.id,
				'program_id', r.program_id,
				'scan_run_id', r.scan_run_id,
				'report_key', r.report_key,
				'title', r.title,
				'severity', r.severity,
				'confidence', r.confidence,
				'finding_ids', r.finding_ids,
				'created_at', r.created_at,
				'metadata', r.metadata
			)
			FROM zero_reports r
			WHERE ($1 = '' OR r.program_id::text = $1)
			  AND ($2 = '' OR r.severity = $2)
			  AND ($3 = '' OR r.created_at > $3::timestamptz)
			ORDER BY r.created_at DESC
			LIMIT $4 OFFSET $5
		`, programID, strings.TrimSpace(r.URL.Query().Get("severity")), p.Since, p.Limit, p.Offset)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeRawJSONArray(w, rows)
	}
}

func (s *Server) technologies(programID string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := s.repo.QueryJSONRows(r.Context(), `
			SELECT jsonb_build_object(
				'id', t.id,
				'program_id', t.program_id,
				'http_service_id', t.http_service_id,
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
			WHERE ($1 = '' OR t.program_id::text = $1)
			  AND t.active = true
			ORDER BY t.last_seen_at DESC
			LIMIT 500
		`, programID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeRawJSONArray(w, rows)
	}
}

func (s *Server) technologyVulnerabilities(programID string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := s.repo.QueryJSONRows(r.Context(), `
			SELECT jsonb_build_object(
				'id', m.id,
				'program_id', m.program_id,
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
			WHERE ($1 = '' OR m.program_id::text = $1)
			ORDER BY m.last_seen_at DESC, m.confidence DESC
			LIMIT 500
		`, programID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeRawJSONArray(w, rows)
	}
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

func (s *Server) createScanRequest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ProgramID string          `json:"program_id"`
		Name      string          `json:"name"`
		RunAfter  string          `json:"run_after"`
		Params    json.RawMessage `json:"params"`
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
		since := strings.TrimSpace(r.URL.Query().Get("since"))
		rows, err := s.repo.QueryJSONRows(r.Context(), `
			SELECT jsonb_build_object(
				'id', c.id,
				'program_id', c.program_id,
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
			WHERE ($1 = '' OR c.program_id::text = $1)
			  AND ($2 = '' OR c.occurred_at > $2::timestamptz)
			ORDER BY c.occurred_at DESC
			LIMIT 500
		`, programID, since)
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
