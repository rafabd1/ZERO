# Zero

Zero is a public bug bounty target-monitoring pipeline for continuously collecting program scopes, enumerating exposed assets, fingerprinting technologies, and preparing high-signal vulnerability triage candidates.

The project is intentionally conservative: a CVE candidate should be emitted only when there is enough evidence to justify follow-up. Weak technology guesses are stored as observations, not findings.

## Pipeline

1. Scope sync: imports HackerOne scopes through the `sw33tLie/bbscope` Go poller.
2. Enumeration: expands in-scope wildcard assets with `subfinder`.
3. Probing: fingerprints alive discovered subdomains and exact URL/domain scope assets with `httpx`.
4. Target intel: stores `httpx` status/title/webserver/TLS/favicon/tech observations for triage context.
5. Active validation: runs optimized `nuclei` CVE templates only where useful.
6. Reporting: deduplicates prior reports and emits new Nuclei-validated candidates grouped by severity and confidence.

## Quick Start

```bash
cp .env.example .env
go mod tidy
go run ./cmd/zero migrate up
go run ./cmd/zero sync h1
go run ./cmd/zero enum subfinder
go run ./cmd/zero probe httpx
go run ./cmd/zero analyze nuclei
go run ./cmd/zero report generate
go run ./cmd/zero notify discord --dry-run
```

For Docker:

```bash
docker compose --profile tools run --rm migrate
docker compose up -d zero
```

The container runs `zero worker` by default. The worker schedules due-program scans through `ZERO_SCHEDULE_FULL`, honoring each program's `scan_interval_hours` and `ZERO_TARGET_PARALLELISM`. The same due-program planner can be inspected safely with:

```bash
zero run due --dry-run --limit 4
```

Use `zero run once` only when you intentionally want the unbounded global pipeline.

On startup, the worker marks interrupted `running` scan runs as failed/recovered and immediately runs the due-program planner by default. Set `ZERO_RUN_ON_STARTUP=false` only when you want cron-only execution.

Discord delivery is opt-in through `ZERO_DISCORD_WEBHOOK_URL`. Without a webhook, notification delivery is a safe no-op and reports remain available through the API.

## Required Tools

- Go 1.24+
- Supabase cloud Postgres URL in `ZERO_DATABASE_URL`
- HackerOne API username/token in `ZERO_H1_USERNAME` and `ZERO_H1_TOKEN`
- `subfinder` for passive subdomain enumeration
- `httpx` for alive checks and technology fingerprinting
- `nuclei` for final active validation of CVE candidates

`httpx` is target intel, not proof of vulnerability. It gives stable JSON, status/title/webserver/TLS/favicon/tech data in one pass. `nuclei` is the CVE validator and should default to CVE templates with severity above low, moderate rate limits, and per-target batching.

## Current Status

This commit establishes the base project:

- Go CLI and scheduler.
- Supabase/Postgres schema.
- Direct HackerOne scope sync through the bbscope library.
- `subfinder` and `httpx` task runners.
- Nuclei result ingestion and candidate finding creation.
- New-only report generation from unreported findings.

Passive CVE matching is intentionally disabled. Fingerprints from `httpx` are kept as asset intelligence; reportable CVE candidates come from Nuclei validation.
