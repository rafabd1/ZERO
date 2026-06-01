# Roadmap

## Phase 1: Foundation

- Go CLI and Docker worker.
- Supabase/Postgres migrations.
- HackerOne scope import through bbscope.
- `subfinder` enumeration.
- `httpx` probing and technology storage.
- Nuclei result schema and scan policy.

## Phase 2: Data Quality

- Add DNS validation with `dnsx`.
- Mark stale subdomains/services inactive after repeated misses.
- Add scope safety checks for wildcard expansion.
- Normalize technology names with a small alias table.
- Add batch insert/upsert paths for first scans with large scopes and large subdomain lists.

## Phase 3: Vulnerability Validation

- Keep `httpx` fingerprints as target intelligence only.
- Add optimized Nuclei runner with `tags=cve`, severity `medium,high,critical`, per-program URL batches, and moderate rate/concurrency defaults.
- Create candidate findings from new Nuclei results.
- Score findings by severity, confidence, exploit maturity, and evidence quality.

## Phase 4: Reporting

- Generate Markdown reports grouped by severity and confidence.
- Deduplicate by stable `evidence_hash`.
- Suppress prior reports and dismissed findings.
- Export candidate bundles for Proteus/Codex manual triage.
- Add Discord notification delivery for new findings only.

## Phase 4.5: API

- Add authenticated API endpoints for latest scan state.
- Expose latest assets, alive services, Nuclei hits, candidate findings, reports, and change events.
- Use a bearer token or service-to-service auth; do not expose Supabase service keys to clients.

## Phase 5: More Scope Sources

- Add bbscope adapters for Bugcrowd, Intigriti, YesWeHack, and Immunefi.
- Add per-platform credentials and scheduling controls.
