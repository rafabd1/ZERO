# Zero

Zero is a public bug bounty target-monitoring pipeline for continuously collecting program scopes, enumerating exposed assets, fingerprinting technologies, and preparing high-signal vulnerability triage candidates.

The project is intentionally conservative: a CVE candidate should be emitted only when there is enough evidence to justify follow-up. Weak technology guesses are stored as observations, not findings.

## Pipeline

1. Scope sync: imports HackerOne scopes through the `sw33tLie/bbscope` Go poller.
2. Enumeration: expands wildcard and URL-host scope assets with `subfinder`.
3. Probing: fingerprints alive HTTP services with `httpx`.
4. Passive intelligence: stores target intel and matches strong technology/version evidence to CVE/KEV/advisory sources.
5. Active validation: runs optimized `nuclei` CVE templates only where useful.
6. Reporting: deduplicates prior reports and emits new candidates grouped by severity and confidence.

## Quick Start

```bash
cp .env.example .env
go mod tidy
go run ./cmd/zero migrate up
go run ./cmd/zero sync h1
go run ./cmd/zero enum subfinder
go run ./cmd/zero probe httpx
```

For Docker:

```bash
docker compose --profile tools run --rm migrate
docker compose up -d zero
```

## Required Tools

- Go 1.24+
- Supabase cloud Postgres URL in `ZERO_DATABASE_URL`
- HackerOne API username/token in `ZERO_H1_USERNAME` and `ZERO_H1_TOKEN`
- `subfinder` for passive subdomain enumeration
- `httpx` for alive checks and technology fingerprinting
- `nuclei` for final active validation of CVE candidates

`httpx` is target intel, not proof of vulnerability. It gives stable JSON, status/title/webserver/TLS/favicon/tech data in one pass. `nuclei` is kept as the active validator and should default to CVE templates with severity above low, moderate rate limits, and per-target batching.

## Current Status

This commit establishes the base project:

- Go CLI and scheduler.
- Supabase/Postgres schema.
- Direct HackerOne scope sync through the bbscope library.
- `subfinder` and `httpx` task runners.
- Nuclei/result/report schema and design docs.

The CVE matcher is deliberately not pretending to be complete yet. Matching web technologies to CVEs without version evidence creates noisy reports; the first implementation should prioritize confirmed versions, CISA KEV, Nuclei CVE templates, deduplication, and "new results only" reporting.
