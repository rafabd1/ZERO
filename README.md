# Zero

Zero is a public bug bounty target-monitoring pipeline for continuously collecting program scopes, enumerating exposed assets, fingerprinting technologies, and preparing high-signal vulnerability triage candidates.

The project is intentionally conservative: a CVE candidate should be emitted only when there is enough evidence to justify follow-up. Weak technology guesses are stored as observations, not findings.

## Pipeline

1. Scope sync: imports HackerOne scopes through the `sw33tLie/bbscope` Go poller.
2. Enumeration: expands in-scope wildcard assets with `subfinder`.
3. DNS validation: resolves discovered wildcard hosts with `dnsx`.
4. Probing: fingerprints alive discovered subdomains and exact URL/domain scope assets with `httpx`.
5. Target intel: stores `httpx` status/title/webserver/TLS/favicon/tech observations for triage context.
6. Enrichment: fingerprints alive services with Webanalyze/Wappalyzer definitions and stores versioned technology observations when available.
7. Passive CVE intel: queries NVD for versioned technologies, links plausible CVEs to the program, and keeps them as non-reportable intel.
8. Active validation: runs optimized `nuclei` CVE templates selected from the passive CVE links when possible.
9. Reporting: deduplicates prior reports and emits new Nuclei-validated candidates grouped by severity and confidence.

## Quick Start

```bash
cp .env.example .env
go mod tidy
go run ./cmd/zero migrate up
go run ./cmd/zero sync h1
go run ./cmd/zero enum subfinder
go run ./cmd/zero probe dnsx
go run ./cmd/zero probe httpx
go run ./cmd/zero enrich webanalyze
go run ./cmd/zero analyze cves
go run ./cmd/zero analyze nuclei
go run ./cmd/zero report generate
go run ./cmd/zero notify discord --dry-run
```

For Docker:

```bash
docker compose --profile tools run --rm migrate
docker compose up -d zero api
```

The container runs `zero worker` by default. The worker schedules due-program scans through `ZERO_SCHEDULE_FULL`, honoring each program's `scan_interval_hours` and `ZERO_TARGET_PARALLELISM`. The same due-program planner can be inspected safely with:

```bash
zero run due --dry-run --limit 4
```

Use `zero run once` only when you intentionally want the unbounded global pipeline.

On startup, the worker marks interrupted `running` scan runs as failed/recovered and immediately runs the due-program planner by default. Set `ZERO_RUN_ON_STARTUP=false` only when you want cron-only execution.

The Compose API service binds `zero api` to `127.0.0.1:8080` on the host and exposes `/healthz`, latest scans, reports, changes, and findings.

Discord delivery is opt-in through `ZERO_DISCORD_WEBHOOK_URL`. Without a webhook, notification delivery is a safe no-op and reports remain available through the API.

## Required Tools

- Go 1.24+
- Supabase cloud Postgres URL in `ZERO_DATABASE_URL`
- HackerOne API username/token in `ZERO_H1_USERNAME` and `ZERO_H1_TOKEN`
- `subfinder` for passive subdomain enumeration
- `dnsx` for DNS resolution filtering
- `httpx` for alive checks and technology fingerprinting
- `webanalyze` for Wappalyzer-style technology enrichment
- `nuclei` for final active validation of CVE candidates

`httpx` is target intel, not proof of vulnerability. It gives stable JSON, status/title/webserver/TLS/favicon/tech data in one pass. Webanalyze expands technology/version coverage. NVD matches are passive intel only. `nuclei` is the CVE validator and defaults to template IDs derived from medium/high/critical passive CVE matches, moderate rate limits, and per-target batching.

Use `zero run manual` for one-off scans with custom parameters, for example a custom Webanalyze technologies file, CVE-derived Nuclei templates, a specific Nuclei template ID, a local Nuclei template path, or per-run rate/concurrency/severity settings. These flags apply only to that run and do not change the global worker configuration.

Use `zero run schedule --run-after 30m ...` to queue the same custom scan parameters for the worker. Queued requests are visible through `/v1/scan-requests`.

## Current Status

This commit establishes the base project:

- Go CLI and scheduler.
- Supabase/Postgres schema.
- Direct HackerOne scope sync through the bbscope library.
- `subfinder`, `dnsx`, and `httpx` task runners.
- Webanalyze enrichment, NVD CVE matching, and Nuclei result ingestion.
- New-only report generation from unreported findings.

Passive CVE matching never creates findings by itself. Fingerprints from `httpx` and Webanalyze are kept as asset intelligence; reportable CVE candidates come from Nuclei validation.
