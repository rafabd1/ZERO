CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS zero_programs (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	platform text NOT NULL,
	handle text NOT NULL,
	program_url text NOT NULL UNIQUE,
	active boolean NOT NULL DEFAULT true,
	scan_interval_hours integer NOT NULL DEFAULT 72 CHECK (scan_interval_hours >= 24),
	max_parallel_tasks integer NOT NULL DEFAULT 4 CHECK (max_parallel_tasks >= 1 AND max_parallel_tasks <= 16),
	last_scan_started_at timestamptz,
	last_scan_finished_at timestamptz,
	first_seen_at timestamptz NOT NULL DEFAULT now(),
	last_seen_at timestamptz NOT NULL DEFAULT now(),
	metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
	UNIQUE(platform, handle)
);

CREATE INDEX IF NOT EXISTS idx_zero_programs_due
	ON zero_programs(active, last_scan_finished_at, scan_interval_hours);

CREATE TABLE IF NOT EXISTS zero_scan_runs (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	program_id uuid REFERENCES zero_programs(id) ON DELETE CASCADE,
	run_type text NOT NULL CHECK (run_type IN ('scope','enum','probe','nuclei','intel','full')),
	status text NOT NULL DEFAULT 'running' CHECK (status IN ('queued','running','succeeded','failed','canceled')),
	started_at timestamptz NOT NULL DEFAULT now(),
	finished_at timestamptz,
	worker_id text NOT NULL DEFAULT '',
	input_count integer NOT NULL DEFAULT 0,
	inserted_count integer NOT NULL DEFAULT 0,
	updated_count integer NOT NULL DEFAULT 0,
	unchanged_count integer NOT NULL DEFAULT 0,
	error text NOT NULL DEFAULT '',
	stats jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_zero_scan_runs_program_started
	ON zero_scan_runs(program_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_zero_scan_runs_status
	ON zero_scan_runs(status, run_type, started_at DESC);

CREATE TABLE IF NOT EXISTS zero_scan_requests (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	program_id uuid REFERENCES zero_programs(id) ON DELETE CASCADE,
	name text NOT NULL DEFAULT '',
	status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','succeeded','failed','canceled')),
	requested_by text NOT NULL DEFAULT 'cli',
	run_after timestamptz NOT NULL DEFAULT now(),
	params jsonb NOT NULL DEFAULT '{}'::jsonb,
	attempt_count integer NOT NULL DEFAULT 0,
	started_at timestamptz,
	finished_at timestamptz,
	locked_at timestamptz,
	error text NOT NULL DEFAULT '',
	created_at timestamptz NOT NULL DEFAULT now(),
	updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_zero_scan_requests_due
	ON zero_scan_requests(status, run_after, created_at);
CREATE INDEX IF NOT EXISTS idx_zero_scan_requests_program
	ON zero_scan_requests(program_id, created_at DESC);

CREATE TABLE IF NOT EXISTS zero_scope_assets (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	program_id uuid NOT NULL REFERENCES zero_programs(id) ON DELETE CASCADE,
	last_scan_run_id uuid REFERENCES zero_scan_runs(id) ON DELETE SET NULL,
	platform text NOT NULL,
	handle text NOT NULL,
	asset_type text NOT NULL,
	target_raw text NOT NULL,
	target_normalized text NOT NULL,
	description text NOT NULL DEFAULT '',
	in_scope boolean NOT NULL,
	eligible_for_bounty boolean NOT NULL DEFAULT false,
	active boolean NOT NULL DEFAULT true,
	source text NOT NULL DEFAULT 'bbscope',
	first_seen_at timestamptz NOT NULL DEFAULT now(),
	last_seen_at timestamptz NOT NULL DEFAULT now(),
	metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
	UNIQUE(program_id, asset_type, target_normalized, in_scope)
);

CREATE INDEX IF NOT EXISTS idx_zero_scope_assets_program
	ON zero_scope_assets(program_id, active, in_scope, asset_type);
CREATE INDEX IF NOT EXISTS idx_zero_scope_assets_target
	ON zero_scope_assets(target_normalized);

CREATE TABLE IF NOT EXISTS zero_subdomains (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	program_id uuid NOT NULL REFERENCES zero_programs(id) ON DELETE CASCADE,
	scope_asset_id uuid REFERENCES zero_scope_assets(id) ON DELETE SET NULL,
	last_scan_run_id uuid REFERENCES zero_scan_runs(id) ON DELETE SET NULL,
	root_domain text NOT NULL,
	fqdn text NOT NULL,
	source text NOT NULL DEFAULT 'subfinder',
	resolves boolean,
	active boolean NOT NULL DEFAULT true,
	first_seen_at timestamptz NOT NULL DEFAULT now(),
	last_seen_at timestamptz NOT NULL DEFAULT now(),
	metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
	UNIQUE(program_id, fqdn)
);

CREATE INDEX IF NOT EXISTS idx_zero_subdomains_program_root
	ON zero_subdomains(program_id, root_domain);
CREATE INDEX IF NOT EXISTS idx_zero_subdomains_fqdn
	ON zero_subdomains(fqdn);

CREATE TABLE IF NOT EXISTS zero_http_services (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	program_id uuid NOT NULL REFERENCES zero_programs(id) ON DELETE CASCADE,
	subdomain_id uuid REFERENCES zero_subdomains(id) ON DELETE SET NULL,
	last_scan_run_id uuid REFERENCES zero_scan_runs(id) ON DELETE SET NULL,
	url text NOT NULL,
	scheme text NOT NULL,
	host text NOT NULL,
	port integer,
	status_code integer,
	title text NOT NULL DEFAULT '',
	webserver text NOT NULL DEFAULT '',
	technologies jsonb NOT NULL DEFAULT '[]'::jsonb,
	favicon_hash text NOT NULL DEFAULT '',
	tls jsonb NOT NULL DEFAULT '{}'::jsonb,
	raw jsonb NOT NULL DEFAULT '{}'::jsonb,
	active boolean NOT NULL DEFAULT true,
	first_seen_at timestamptz NOT NULL DEFAULT now(),
	last_seen_at timestamptz NOT NULL DEFAULT now(),
	UNIQUE(program_id, url)
);

CREATE INDEX IF NOT EXISTS idx_zero_http_services_program_host
	ON zero_http_services(program_id, host);
CREATE INDEX IF NOT EXISTS idx_zero_http_services_technologies
	ON zero_http_services USING gin(technologies);

CREATE TABLE IF NOT EXISTS zero_technology_observations (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	program_id uuid NOT NULL REFERENCES zero_programs(id) ON DELETE CASCADE,
	http_service_id uuid NOT NULL REFERENCES zero_http_services(id) ON DELETE CASCADE,
	last_scan_run_id uuid REFERENCES zero_scan_runs(id) ON DELETE SET NULL,
	name text NOT NULL,
	version text NOT NULL DEFAULT '',
	source text NOT NULL DEFAULT 'httpx',
	confidence integer NOT NULL DEFAULT 50 CHECK (confidence >= 0 AND confidence <= 100),
	evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
	first_seen_at timestamptz NOT NULL DEFAULT now(),
	last_seen_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_zero_technology_observations_unique
	ON zero_technology_observations(http_service_id, lower(name), version, source);
CREATE INDEX IF NOT EXISTS idx_zero_technology_observations_program
	ON zero_technology_observations(program_id, lower(name), version);

CREATE TABLE IF NOT EXISTS zero_vulnerability_records (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	vuln_id text NOT NULL UNIQUE,
	source text NOT NULL,
	summary text NOT NULL DEFAULT '',
	severity text NOT NULL DEFAULT 'unknown',
	cvss_score numeric,
	published_at timestamptz,
	modified_at timestamptz,
	references_json jsonb NOT NULL DEFAULT '[]'::jsonb,
	raw jsonb NOT NULL DEFAULT '{}'::jsonb,
	first_seen_at timestamptz NOT NULL DEFAULT now(),
	last_seen_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS zero_technology_vulnerability_matches (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	program_id uuid NOT NULL REFERENCES zero_programs(id) ON DELETE CASCADE,
	vulnerability_id uuid NOT NULL REFERENCES zero_vulnerability_records(id) ON DELETE CASCADE,
	last_scan_run_id uuid REFERENCES zero_scan_runs(id) ON DELETE SET NULL,
	technology_name text NOT NULL,
	technology_version text NOT NULL DEFAULT '',
	source_observation text NOT NULL DEFAULT '',
	source_query text NOT NULL DEFAULT '',
	confidence integer NOT NULL DEFAULT 0 CHECK (confidence >= 0 AND confidence <= 100),
	evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
	first_seen_at timestamptz NOT NULL DEFAULT now(),
	last_seen_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_zero_technology_vulnerability_matches_unique
	ON zero_technology_vulnerability_matches(program_id, vulnerability_id, lower(technology_name), technology_version, source_query);
CREATE INDEX IF NOT EXISTS idx_zero_technology_vulnerability_matches_program
	ON zero_technology_vulnerability_matches(program_id, confidence DESC, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_zero_technology_vulnerability_matches_vuln
	ON zero_technology_vulnerability_matches(vulnerability_id);

CREATE TABLE IF NOT EXISTS zero_nuclei_results (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	program_id uuid NOT NULL REFERENCES zero_programs(id) ON DELETE CASCADE,
	http_service_id uuid REFERENCES zero_http_services(id) ON DELETE CASCADE,
	scan_run_id uuid REFERENCES zero_scan_runs(id) ON DELETE SET NULL,
	template_id text NOT NULL,
	template_path text NOT NULL DEFAULT '',
	matched_at text NOT NULL,
	severity text NOT NULL,
	cves text[] NOT NULL DEFAULT '{}',
	tags text[] NOT NULL DEFAULT '{}',
	type text NOT NULL DEFAULT '',
	extractor_name text NOT NULL DEFAULT '',
	evidence_hash text NOT NULL,
	raw jsonb NOT NULL DEFAULT '{}'::jsonb,
	first_seen_at timestamptz NOT NULL DEFAULT now(),
	last_seen_at timestamptz NOT NULL DEFAULT now(),
	UNIQUE(program_id, template_id, matched_at, evidence_hash)
);

CREATE INDEX IF NOT EXISTS idx_zero_nuclei_results_program_severity
	ON zero_nuclei_results(program_id, severity, first_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_zero_nuclei_results_cves
	ON zero_nuclei_results USING gin(cves);
CREATE INDEX IF NOT EXISTS idx_zero_nuclei_results_tags
	ON zero_nuclei_results USING gin(tags);

CREATE TABLE IF NOT EXISTS zero_candidate_findings (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	program_id uuid NOT NULL REFERENCES zero_programs(id) ON DELETE CASCADE,
	http_service_id uuid REFERENCES zero_http_services(id) ON DELETE CASCADE,
	nuclei_result_id uuid REFERENCES zero_nuclei_results(id) ON DELETE SET NULL,
	vulnerability_id uuid REFERENCES zero_vulnerability_records(id) ON DELETE SET NULL,
	technology_name text NOT NULL DEFAULT '',
	technology_version text NOT NULL DEFAULT '',
	severity text NOT NULL DEFAULT 'unknown',
	confidence integer NOT NULL CHECK (confidence >= 0 AND confidence <= 100),
	status text NOT NULL DEFAULT 'new' CHECK (status IN ('new','reported','dismissed','stale')),
	evidence_hash text NOT NULL,
	evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
	first_seen_at timestamptz NOT NULL DEFAULT now(),
	last_seen_at timestamptz NOT NULL DEFAULT now(),
	report_id uuid,
	UNIQUE(evidence_hash)
);

CREATE INDEX IF NOT EXISTS idx_zero_candidate_findings_program_status
	ON zero_candidate_findings(program_id, status, severity, confidence);

CREATE TABLE IF NOT EXISTS zero_change_events (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	program_id uuid NOT NULL REFERENCES zero_programs(id) ON DELETE CASCADE,
	scan_run_id uuid REFERENCES zero_scan_runs(id) ON DELETE SET NULL,
	entity_type text NOT NULL CHECK (entity_type IN ('scope_asset','subdomain','http_service','technology','nuclei_result','candidate_finding')),
	entity_id uuid,
	entity_key text NOT NULL,
	change_type text NOT NULL CHECK (change_type IN ('added','updated','removed')),
	old_value jsonb NOT NULL DEFAULT '{}'::jsonb,
	new_value jsonb NOT NULL DEFAULT '{}'::jsonb,
	evidence_hash text NOT NULL,
	occurred_at timestamptz NOT NULL DEFAULT now(),
	UNIQUE(evidence_hash)
);

CREATE INDEX IF NOT EXISTS idx_zero_change_events_program_time
	ON zero_change_events(program_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_zero_change_events_scan
	ON zero_change_events(scan_run_id, entity_type, change_type);

CREATE TABLE IF NOT EXISTS zero_reports (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	program_id uuid REFERENCES zero_programs(id) ON DELETE SET NULL,
	scan_run_id uuid REFERENCES zero_scan_runs(id) ON DELETE SET NULL,
	report_key text NOT NULL UNIQUE,
	title text NOT NULL,
	severity text NOT NULL DEFAULT 'unknown',
	confidence integer NOT NULL DEFAULT 0,
	body_markdown text NOT NULL,
	finding_ids uuid[] NOT NULL DEFAULT '{}',
	created_at timestamptz NOT NULL DEFAULT now(),
	metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS zero_discord_notifications (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	program_id uuid REFERENCES zero_programs(id) ON DELETE SET NULL,
	report_id uuid REFERENCES zero_reports(id) ON DELETE SET NULL,
	finding_id uuid REFERENCES zero_candidate_findings(id) ON DELETE SET NULL,
	dedupe_key text NOT NULL UNIQUE,
	status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','sent','failed','suppressed')),
	error text NOT NULL DEFAULT '',
	created_at timestamptz NOT NULL DEFAULT now(),
	sent_at timestamptz
);
