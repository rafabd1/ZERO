# Zero Agent Guide

This file is the public agent instruction set for Zero. It is intended for Codex, Claude Code, and similar coding agents working in this repository.

## Project Intent

Zero is a Go-based monitoring pipeline for authorized bug bounty and attack-surface research at scale. Its main value is not generic scanning; it is durable, focused vulnerability-analysis campaigns across many authorized programs with structured state, deduplication, and reporting.

Keep changes aligned with that purpose:

- Scope safety is non-negotiable. Enumeration and validation must stay tied to in-scope, bounty-eligible assets.
- Custom campaigns are first-class. Prefer options that let operators run targeted fingerprinting, CVE validation, and Nuclei templates without changing global defaults.
- Postgres/Supabase is the source of truth for programs, scope assets, subdomains, HTTP services, technologies, findings, reports, scan requests, and campaigns.
- Nuclei is an active validator. Passive CVE matches are prioritization/intelligence unless active evidence confirms them.

## Development Rules

- Use the existing Go packages and CLI/API patterns before adding new abstractions.
- Keep edits narrowly scoped and avoid unrelated refactors.
- Run `gofmt` on changed Go files.
- Run `go test ./...` before handing off whenever feasible.
- Do not commit secrets, `.env`, API keys, Discord webhooks, provider configs, generated scan output, local DB files, or private target/fingerprint files.
- Local custom Webanalyze files under `configs/webanalyze/*.json` are ignored by default. Public examples may use `*.example.json`.
- Prefer Docker-compatible paths and behavior. Do not assume locally installed Windows/Linux binaries when the container image already provides the external tools.

## Operational Model

The normal worker path is:

```text
scope sync -> subfinder -> dnsx -> httpx -> Webanalyze -> passive CVE context -> Nuclei -> report -> notify
```

Custom campaigns can skip parts of that path:

- `--skip-enum` skips subfinder.
- `--reuse-active-services` skips `dnsx/httpx` and uses active HTTP services already stored in Postgres.
- `--webanalyze-apps` adds focused technology fingerprints for a run without clearing the full technology inventory.
- `--webanalyze-probe-path` fingerprints additional relative paths such as `/admin/`, `/console/`, or `/api/version` on each alive service.
- `--nuclei-tech-filter` should gate focused active validation to assets whose fingerprint/title/server/banner matches the intended technology.
- `--nuclei-tech-max-age` is mainly for scans that skip fingerprinting and intentionally use existing database observations.
- `--disable-passive-fingerprint-reports` should be used when a custom campaign must report only Nuclei-confirmed findings.

Default/due scans use `ZERO_TARGET_PARALLELISM`. Custom campaigns use their own campaign parallelism and can run independently.

Before scheduling a broad custom campaign:

- Check whether recent alive inventory exists; prefer `--reuse-active-services` when it does.
- Stage expensive campaigns with `--campaign-limit` before running across all programs.
- Remember that each service expands to `base URL + every --webanalyze-probe-path`; `--webanalyze-batch-size` counts expanded URLs, not base services.
- Keep custom Nuclei templates gated with `--nuclei-tech-filter` unless the template is safe and specific enough to run on every active service.
- Ensure custom files referenced by queued campaigns are available in the worker container under `/home/zero/custom-assets`.

For detailed recipes and template examples, read `docs/CUSTOM_CAMPAIGNS.md`.

## Security Research Standards

Zero should help produce useful, low-noise leads:

- Prefer high-impact, realistically exploitable CVEs and exposure classes.
- Avoid broad noisy validation when a fingerprint or targeted template can reduce scope first.
- Treat unconfirmed passive matches clearly as potential.
- Preserve evidence integrity and deduplication; do not delete evidence-linked services, findings, reports, or Nuclei results casually.
- Do not overclaim. Reports should distinguish passive intelligence from active validation.

## Public Repo Hygiene

When adding examples or docs, keep them generic. Do not mention private campaigns, real customer/program selections, local credentials, internal webhooks, or operator-specific paths unless they are standard container paths documented by the project.
