# Operations

This guide covers the practical path from a fresh setup to continuous scans, visual monitoring, and custom research campaigns.

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
- `ZERO_TARGET_PARALLELISM=12` controls default/due pipeline program parallelism.
- `ZERO_SCAN_REQUEST_MAX_ACTIVE=10` caps concurrent custom scan requests so database poolers are not exhausted.
- `ZERO_SCAN_REQUEST_RETRY_ATTEMPTS=4` and `ZERO_SCAN_REQUEST_RETRY_BASE_DELAY=2m` requeue transient DB/NVD failures instead of discarding the scan.
- `ZERO_SCAN_REQUEST_HEARTBEAT=30s` updates long-running request progress and DB liveness.
- `ZERO_SCAN_REQUEST_STALE_AFTER=30m` requeues running requests whose heartbeat is stale.
- `ZERO_TOOL_TIMEOUT=20m` bounds external steps without dedicated batch timeouts, such as subfinder and template updates.
- `ZERO_INACTIVE_RETENTION_HOURS=72` and `ZERO_INACTIVE_RETENTION_SCANS=2` control cleanup of inactive inventory.

The main pipeline per due program is:

```text
subfinder -> dnsx -> httpx -> webanalyze -> passive CVE context -> nuclei -> report -> notify
```

Each stage writes structured state to Postgres. A restart requeues interrupted custom requests and marks interrupted scan runs with recovery metadata.

## Custom Campaigns

Custom campaigns let you run targeted analysis across one program or the full active inventory. They can combine all pipeline stages or use only the tools needed for the question being asked.

For the full command surface, see [CLI Reference](CLI.md). For detailed parameter recipes, custom Webanalyze templates, Nuclei template examples, and staged rollout guidance, see [Custom Campaigns](CUSTOM_CAMPAIGNS.md).

Single program:

```bash
docker compose run --rm zero run schedule \
  --program-id <uuid> \
  --name "targeted-template-check" \
  --skip-sync \
  --nuclei-template /home/zero/custom-assets/custom.yaml \
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
  --reuse-active-services \
  --webanalyze-apps /home/zero/custom-assets/custom-technologies.json \
  --webanalyze-probe-path /admin/ \
  --webanalyze-probe-path /api/version \
  --webanalyze-batch-size 50 \
  --webanalyze-batch-timeout 10m \
  --nuclei-tech-filter "product-name" \
  --nuclei-template /home/zero/custom-assets/templates \
  --nuclei-severity medium,high,critical
```

Use `--due-only` if the campaign should respect each program's normal scan interval. Use `--campaign-limit` for staged rollouts.

The worker pool keeps custom campaign slots filled from each campaign's own `--campaign-parallelism`. Multiple custom campaigns can run side by side; their capacity is additive and is not capped by `ZERO_TARGET_PARALLELISM`, which only controls default/due scans.

Docker Compose includes a local `dbpool` sidecar powered by PgBouncer. The `zero`, `api`, and `migrate` containers connect to `dbpool:6432`; `dbpool` is the only service that opens upstream sessions to Supabase. This lets operators run more local worker processes while keeping Supabase session usage bounded. Tune:

- `ZERO_DBPOOL_DEFAULT_POOL_SIZE=8`
- `ZERO_DBPOOL_RESERVE_POOL_SIZE=2`
- `ZERO_DBPOOL_MAX_CLIENT_CONN=500`
- `ZERO_SCAN_REQUEST_MAX_ACTIVE=10`

If the Supabase project has a small session pool, increase `ZERO_SCAN_REQUEST_MAX_ACTIVE` only after enabling the local `dbpool`. Broad path-probe campaigns can still be CPU/network heavy, so the dashboard exposes per-request progress, active service counts, expanded Webanalyze URL estimates, and batch progress.

Normal `httpx` and full Webanalyze fingerprints update the active technology state for each processed service. If a previously active technology from that same source is not reobserved in the current scan, Zero marks it inactive. Custom Webanalyze app files are treated as partial fingerprints, so they add focused matches but do not clear the full inventory. Use `--webanalyze-probe-path` for products whose fingerprint appears on known paths such as `/admin/`, `/console/`, `/demo/`, or `/api/jolokia/version`; each path is derived from the already authorized alive service URL and tied back to the same HTTP service record. Path probes are partial fingerprints too, so they do not clear existing technology inventory. Webanalyze batch size counts expanded URLs after path expansion, so keep `--webanalyze-batch-size` conservative for broad path-probe campaigns. For targeted validation, pair `--nuclei-tech-filter` with fresh fingerprinting in the same campaign; Zero automatically applies a freshness window before Nuclei. Use `--nuclei-tech-max-age` only when skipping fingerprint stages and intentionally relying on observations already in the database.

When custom fingerprinting is used, reports include fresh fingerprint matches as potential/unconfirmed findings if Nuclei runs but does not confirm them. Use `--disable-passive-fingerprint-reports` for campaigns that should emit only Nuclei-confirmed findings.

Use `--reuse-active-services` to skip `dnsx/httpx` and run enrichment, CVE context, Nuclei, reporting, and notification against active HTTP services already stored in Postgres. This avoids repeated alive probing when multiple focused campaigns are launched soon after a fresh full scan. In this mode, `httpx` tuning flags are intentionally ignored.

## Cancel Work

Cancel one queued/running request:

```bash
docker compose run --rm zero run cancel --request-id <scan-request-id>
```

Cancel an entire campaign:

```bash
docker compose run --rm zero run cancel --campaign-id <scan-campaign-id>
```

The API exposes the same operation through `POST /v1/scan-requests/{id}/cancel` and `POST /v1/scan-campaigns/{id}/cancel`.

## Cleanup

The worker schedules operational cleanup with `ZERO_SCHEDULE_CLEANUP`. By default it runs every 12 hours, skips while scans are running, and deletes inactive inventory immediately. This keeps the database focused on current alive/reusable assets plus finding evidence.

Manual cleanup:

```bash
docker compose run --rm zero run cleanup
```

HTTP services linked to Nuclei results or candidate findings are preserved for evidence integrity. Cleanup deletes in bounded batches controlled by `ZERO_CLEANUP_BATCH_SIZE`.

For a database that already accumulated inventory change history, run a manual compaction during a quiet maintenance window:

```bash
docker compose run --rm zero run cleanup --compact-change-events
```

This rewrites `zero_change_events` after pruning disallowed event types, so avoid running it during broad campaigns.

## Tuning

Broad scopes can contain many near-identical tenant, CDN, or default-page hosts. Start conservative:

- `ZERO_HTTPX_TIMEOUT=4`
- `ZERO_HTTPX_THREADS=20`
- `ZERO_HTTPX_BATCH_SIZE=50`
- `ZERO_HTTPX_BATCH_TIMEOUT=5m`
- `ZERO_HTTPX_PATTERN_MIN_GROUP=200`
- `ZERO_HTTPX_PATTERN_CAP=120`
- `ZERO_HTTPX_TLS_PROBE=false`

For DNS resolution:

- `ZERO_DNSX_RATE=200`
- `ZERO_DNSX_BATCH_SIZE=1000`
- `ZERO_DNSX_BATCH_TIMEOUT=10m`

For Webanalyze and custom path probes:

- `ZERO_WEBANALYZE_WORKERS=4`
- `ZERO_WEBANALYZE_BATCH_SIZE=50`
- `ZERO_WEBANALYZE_BATCH_TIMEOUT=10m`

Webanalyze batches count expanded URLs, not base services. A service plus four probe paths becomes five Webanalyze URLs.

For Nuclei:

- use specific template IDs or paths when possible;
- keep `ZERO_NUCLEI_SEVERITIES=medium,high,critical` for broad runs;
- set `ZERO_NUCLEI_HEADERS` or `--nuclei-header` to use normal browser-like request headers without reducing scan coverage;
- optionally set `ZERO_NUCLEI_PROXY`, `ZERO_NUCLEI_SCAN_STRATEGY`, or `ZERO_NUCLEI_MAX_HOST_ERROR` for controlled campaigns;
- tune `ZERO_NUCLEI_RATE`, `ZERO_NUCLEI_CONCURRENCY`, and `ZERO_NUCLEI_BULK_SIZE` for the environment;
- keep `ZERO_NUCLEI_TARGET_BATCH_SIZE=500` and `ZERO_NUCLEI_TARGET_BATCH_TIMEOUT=20m` as a starting point for large programs;
- avoid using Nuclei as a broad generic scanner unless that is the explicit campaign goal.

`ZERO_NUCLEI_HEADERS` uses `|` as the separator, so values such as the `Accept` header can safely contain commas.

For NVD passive CVE enrichment:

- `ZERO_NVD_RETRIES=5`
- `ZERO_NVD_RETRY_WAIT=10s`

Zero serializes NVD requests across concurrent scan workers and respects `Retry-After` on 429 responses.

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
