# Zero

<p align="center">
  <img src="assets/zero-banner.gif" alt="Animated ASCII ZERO wordmark" width="960">
</p>

Zero is a Docker-first pipeline for custom vulnerability analysis at bug bounty scale.

It keeps target scope, discovered assets, fingerprints, passive CVE context, active validation results, reports, and notifications in one persistent Postgres/Supabase state model. The goal is not to run a generic scanner against everything. Zero is built to launch focused analysis campaigns across many authorized targets, then report only new, deduplicated evidence.

## What Zero Does

- Syncs bug bounty scope from configured providers.
- Expands only authorized wildcard roots with `subfinder`.
- Filters discoveries through scope rules, out-of-scope rules, DNS resolution, and live probing.
- Collects target intelligence with `httpx` and Webanalyze/Wappalyzer definitions.
- Links versioned technology observations to CVE context.
- Runs Nuclei as an active validator when a relevant template or custom template is selected.
- Stores every stage in Postgres for deduplication, change tracking, dashboards, API reads, and Discord notifications.
- Supports custom campaigns across one program or the whole active inventory without changing global worker defaults.

## Quick Start

Zero is easiest to run with Docker Compose.

```bash
cp .env.example .env
```

Edit `.env` and set at least:

```env
ZERO_DATABASE_URL="postgres://postgres:password@db.project-ref.supabase.co:5432/postgres?sslmode=require"
ZERO_H1_USERNAME=""
ZERO_H1_TOKEN=""
ZERO_API_TOKEN=""
```

Set `ZERO_API_TOKEN` to a strong random bearer token before exposing the API.

Then start the stack:

```bash
docker compose --profile tools run --rm migrate
docker compose up -d zero api dashboard
```

Open the dashboard:

```text
http://127.0.0.1:8090
```

The `zero` container runs the continuous worker. The `api` service exposes read endpoints on `127.0.0.1:8080`, and the `dashboard` service proxies API reads without exposing backend secrets to the browser.

## First Checks

Run small checks before starting broad work:

```bash
docker compose run --rm zero sync all
docker compose run --rm zero run due --dry-run --limit 5
docker compose run --rm zero probe httpx --limit 25
docker compose run --rm zero notify discord --dry-run
```

The worker is self-starting by default. It runs a daily scope-sync guard and scans due programs based on each program's configured interval.

## Custom Scan Campaigns

Custom campaigns are the main reason Zero exists.

Use them when you want to test a specific technology, fingerprint, CVE, exposure class, or Nuclei template across many targets without turning the global worker configuration into a one-off experiment.

Example: queue a focused campaign across all active programs with a custom Webanalyze technology file and a specific Nuclei template path.

```bash
docker compose run --rm zero run schedule \
  --all-programs \
  --campaign-parallelism 8 \
  --name "focused-technology-cve-sweep" \
  --skip-sync \
  --reuse-active-services \
  --webanalyze-apps /work/custom/webanalyze/technology.json \
  --webanalyze-probe-path /admin/ \
  --webanalyze-probe-path /api/version \
  --webanalyze-workers 4 \
  --webanalyze-batch-size 50 \
  --webanalyze-batch-timeout 10m \
  --nuclei-tech-filter "product-name" \
  --nuclei-template /work/custom/nuclei/CVE-YYYY-NNNN.yaml \
  --nuclei-force \
  --nuclei-rate-limit 40 \
  --nuclei-concurrency 10 \
  --nuclei-bulk-size 5 \
  --nuclei-timeout 10 \
  --nuclei-retries 1
```

Campaigns are durable. They create one parent row and one child request per selected program. If the container restarts, running child requests are requeued and completed children stay completed. The worker pool keeps campaign slots filled until the campaign drains.

Use `--reuse-active-services` for campaigns that should skip fresh `dnsx/httpx` probing and load active HTTP services already stored in Postgres. This is useful when several focused scans run close together and the alive inventory was just refreshed. In that mode, `httpx` flags are intentionally ignored.

Normal fingerprints are authoritative for the technologies they own: fresh `httpx` and full Webanalyze runs reactivate newly observed technologies and mark missing old observations inactive. A custom `--webanalyze-apps` run is treated as partial intelligence, so it can add focused matches without clearing the full technology inventory. Add `--webanalyze-probe-path` when a product fingerprint lives on known paths such as `/admin/`, `/console/`, or `/api/jolokia/version`; these path probes are also treated as partial intelligence. When a campaign runs fingerprinting before Nuclei, Zero keeps `--nuclei-tech-filter` tied to fresh observations automatically. Use `--nuclei-tech-max-age` only when skipping fingerprinting and relying on existing database observations.

Custom fingerprint matches can produce potential/unconfirmed reports when Nuclei does not confirm the target. Add `--disable-passive-fingerprint-reports` when the campaign should only report Nuclei-confirmed findings.

For a single program, use `--program-id <uuid>` instead of `--all-programs`.

## Scope Safety

Zero is designed for authorized bug bounty work.

- `subfinder` receives only authorized wildcard roots.
- Exact `domain` and `url` assets are probed exactly; they are not expanded into child subdomains.
- Out-of-scope assets override broad in-scope wildcards.
- Assets that are not bounty-eligible are stored as out-of-scope when provider data exposes that distinction.
- Passive technology/CVE matches are stored as intelligence; Nuclei-backed results carry stronger validation confidence.

## Useful Commands

```bash
docker compose run --rm zero sync all
docker compose run --rm zero run due --dry-run --limit 5
docker compose run --rm zero run schedule --all-programs --campaign-parallelism 4 --campaign-limit 25 --skip-sync --reuse-active-services --skip-cves --nuclei-template ./templates/custom.yaml
docker compose run --rm zero report export-triage --status new --limit 100 --output triage.jsonl
docker compose logs -f zero
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md): how the pipeline and state model fit together.
- [Operations](docs/OPERATIONS.md): configuration, schedules, custom campaigns, and runtime tuning.
- [Custom Campaigns](docs/CUSTOM_CAMPAIGNS.md): efficient targeted scan recipes and custom template guidance.
- [API](docs/API.md): read endpoints and custom scan request examples.
- [Database](docs/DATABASE.md): state tables and deduplication rules.
- [Nuclei](docs/NUCLEI.md): validation policy and how template selection works.
- [Tools](docs/TOOLS.md): why each external tool is used.

## Status

Zero is an early operational project. It already supports Dockerized continuous scanning, custom campaigns, scope-safe enumeration, Webanalyze enrichment, passive CVE context, Nuclei validation, reports, Discord notifications, a read API, and a local dashboard.

Use it only against assets you are authorized to test.
