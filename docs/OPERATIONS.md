# Operations

This guide covers the practical path from a fresh Docker setup to continuous scans and custom campaigns.

## Configure

Copy the environment template and fill the required values:

```bash
cp .env.example .env
```

Minimum required settings:

- `ZERO_DATABASE_URL`: Supabase/Postgres connection string. Use `sslmode=require` for hosted Supabase.
- `ZERO_H1_USERNAME` and `ZERO_H1_TOKEN`: HackerOne API credentials when `ZERO_SCOPE_PROVIDERS=h1`.
- `ZERO_API_TOKEN`: bearer token used by the API and dashboard proxy.

Useful optional settings:

- `ZERO_NVD_API_KEY`: improves NVD rate limits for passive CVE context.
- `ZERO_DISCORD_VALIDATED_WEBHOOK_URL`: Nuclei-confirmed report channel.
- `ZERO_DISCORD_PASSIVE_WEBHOOK_URL`: passive/unconfirmed report channel.
- `ZERO_DISCORD_ALERT_WEBHOOK_URL`: operational alerts such as tool timeouts.
- `ZERO_SUBFINDER_*_API_KEY`: provider keys for better subdomain discovery.

The Docker image already includes `subfinder`, `dnsx`, `httpx`, `webanalyze`, and `nuclei`.

## Start

```bash
docker compose --profile tools run --rm migrate
docker compose up -d zero api dashboard
```

Open:

```text
http://127.0.0.1:8090
```

The `zero` service runs the worker. The `api` service listens on `127.0.0.1:8080`. The dashboard listens on `127.0.0.1:8090` and proxies API reads from the container network.

## Continuous Worker

The worker is the normal execution mode.

- `ZERO_RUN_ON_STARTUP=true` runs a startup scope-sync guard and due-program planner.
- `ZERO_SCOPE_SYNC_MAX_AGE=24h` prevents scope sync from running on every restart.
- `ZERO_DEFAULT_SCAN_INTERVAL_HOURS=72` is the default per-program scan interval.
- `ZERO_TARGET_PARALLELISM=12` caps total concurrent program scans.
- `ZERO_TOOL_TIMEOUT=20m` bounds each external tool invocation.

The main pipeline per due program is:

```text
subfinder -> dnsx -> httpx -> webanalyze -> passive CVE context -> nuclei -> report -> notify
```

Each stage writes structured state to Postgres. A restart requeues interrupted custom requests and marks interrupted scan runs with recovery metadata.

## Custom Campaigns

Custom campaigns let you run targeted analysis across one program or the full active inventory.

Single program:

```bash
docker compose run --rm zero run schedule \
  --program-id <uuid> \
  --name "targeted-template-check" \
  --skip-sync \
  --nuclei-template ./templates/custom.yaml \
  --nuclei-header "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36" \
  --nuclei-rate-limit 40 \
  --nuclei-concurrency 10
```

All active programs:

```bash
docker compose run --rm zero run schedule \
  --all-programs \
  --campaign-parallelism 8 \
  --name "custom-technology-sweep" \
  --skip-sync \
  --httpx-batch-size 50 \
  --httpx-batch-timeout 5m \
  --webanalyze-apps ./custom-technologies.json \
  --nuclei-template ./templates/custom \
  --nuclei-severity medium,high,critical
```

Use `--due-only` if the campaign should respect each program's normal scan interval. Use `--campaign-limit` for staged rollouts.

The worker pool keeps campaign slots filled while respecting both the campaign's `--campaign-parallelism` and the global `ZERO_TARGET_PARALLELISM`.

## Tuning

Broad scopes can contain many near-identical tenant, CDN, or default-page hosts. Start conservative:

- `ZERO_HTTPX_TIMEOUT=4`
- `ZERO_HTTPX_THREADS=20`
- `ZERO_HTTPX_BATCH_SIZE=50`
- `ZERO_HTTPX_BATCH_TIMEOUT=5m`
- `ZERO_HTTPX_PATTERN_MIN_GROUP=200`
- `ZERO_HTTPX_PATTERN_CAP=120`
- `ZERO_HTTPX_TLS_PROBE=false`

For Nuclei:

- use specific template IDs or paths when possible;
- keep `ZERO_NUCLEI_SEVERITIES=medium,high,critical` for broad runs;
- set `ZERO_NUCLEI_HEADERS` or `--nuclei-header` to use normal browser-like request headers without reducing scan coverage;
- optionally set `ZERO_NUCLEI_PROXY`, `ZERO_NUCLEI_SCAN_STRATEGY`, or `ZERO_NUCLEI_MAX_HOST_ERROR` for controlled campaigns;
- tune `ZERO_NUCLEI_RATE`, `ZERO_NUCLEI_CONCURRENCY`, and `ZERO_NUCLEI_BULK_SIZE` for the environment;
- avoid using Nuclei as a broad generic scanner unless that is the explicit campaign goal.

`ZERO_NUCLEI_HEADERS` uses `|` as the separator, so values such as the `Accept` header can safely contain commas.

## Scope Safety

Zero enumerates only authorized wildcard roots. Exact `domain` and `url` assets are probed exactly and do not authorize child enumeration. Out-of-scope assets override broad wildcard scope.

After `subfinder`, every discovered hostname must match the wildcard rule that authorized it. `*.example.com` can accept `app.example.com` and `a.b.example.com`, but not `example.com` or sibling domains.

## Smoke Tests

Use limits for setup validation:

```bash
docker compose run --rm zero sync all
docker compose run --rm zero run due --dry-run --limit 5
docker compose run --rm zero enum subfinder --limit 2
docker compose run --rm zero probe dnsx --limit 50
docker compose run --rm zero probe httpx --limit 50
docker compose run --rm zero enrich webanalyze --limit 50
docker compose run --rm zero analyze nuclei --limit 10 --template-id CVE-YYYY-NNNN
docker compose run --rm zero notify discord --dry-run
```

## Notifications

Reports are deduplicated before notification. Confirmed Nuclei reports can be sent to a different Discord webhook than passive/unconfirmed reports. Operational alerts use the alert webhook when configured.

If no webhook is configured, notification commands are safe no-ops and reports remain available through the API.

## Security Notes

Do not commit `.env`, provider configs, API keys, Discord webhooks, or Supabase service-role keys. Keep the API and dashboard bound to localhost unless they are behind trusted access control.
