# Operations

## Credentials Needed

To run the first real scan, Zero needs:

- `ZERO_DATABASE_URL`: Supabase Postgres connection string with `sslmode=require`.
- `ZERO_DATABASE_MAX_CONNS`: max pgx pool connections per Zero process. Default: 1. Keep this low when using Supabase session pooler because parallel scans run many short-lived task processes.
- `ZERO_DATABASE_RETRIES` and `ZERO_DATABASE_RETRY_WAIT`: retry opening/migrating the repository before a command returns failure. Defaults: `4` attempts, `3s` wait. This absorbs transient Supabase pooler/Docker DNS timeouts without killing the worker process.
- HackerOne API credentials:
  - `ZERO_H1_USERNAME`
  - `ZERO_H1_TOKEN`
- Supabase backend credentials for future API/admin operations:
  - Supabase project URL
  - Supabase anon key for read-only client contexts, if ever needed
  - Supabase service-role key only for backend workers/API, never public clients
- Optional Subfinder provider credentials:
  - `ZERO_SUBFINDER_SHODAN_API_KEY`
  - `ZERO_SUBFINDER_BEVIGIL_API_KEY`
  - `ZERO_SUBFINDER_VIRUSTOTAL_API_KEY`
  - `ZERO_SUBFINDER_SECURITYTRAILS_API_KEY`
- Optional NVD API key:
  - `ZERO_NVD_API_KEY` reduces NVD rate-limit delays during passive CVE matching.
  - `ZERO_CVE_MIN_YEAR` controls the minimum CVE year allowed into passive matching, CVE-derived Nuclei template selection, and passive reports. Default: `2018`.
  - `ZERO_NVD_RETRIES` and `ZERO_NVD_RETRY_WAIT` control retry/backoff for transient NVD DNS, 429, and 5xx failures. Defaults: `3` attempts, `3s` base wait.
- External tools installed or available in Docker:
  - `subfinder`
  - `dnsx`
  - `httpx`
  - `webanalyze`
  - `nuclei`
- `ZERO_TOOL_TIMEOUT`: maximum wall-clock time for each external tool invocation. Default: `20m`.
- Discord integration:
  - `ZERO_DISCORD_WEBHOOK_URL` legacy fallback and passive-only report channel.
  - `ZERO_DISCORD_PASSIVE_WEBHOOK_URL` optional explicit passive-only report channel.
  - `ZERO_DISCORD_VALIDATED_WEBHOOK_URL` Nuclei-confirmed report channel.
  - `ZERO_DISCORD_ALERT_WEBHOOK_URL` operational alert channel.
- API protection:
  - `ZERO_API_TOKEN`

## Scan Cadence

Default per-target scan interval: 72 hours.

Default target parallelism: 12 programs at the same time.

Program-level scan cadence lives in `zero_programs.scan_interval_hours`. `zero_programs.max_parallel_tasks` is reserved for a future per-program internal task limiter; the current scheduler processes whole programs concurrently through the global `ZERO_TARGET_PARALLELISM` setting.

The main continuous execution path is `zero worker`, which schedules `zero run due` using `ZERO_SCHEDULE_FULL`. It first refreshes HackerOne scope, then selects active programs whose `last_scan_finished_at` is older than their configured interval, and processes up to `ZERO_TARGET_PARALLELISM` programs concurrently.

By default the worker also runs this due-program planner immediately on container startup (`ZERO_RUN_ON_STARTUP=true`). This makes the container self-starting after deploy/restart instead of waiting for the next cron tick.

Commands that open the database run idempotent migrations first when `ZERO_AUTO_MIGRATE=true`. Migration execution uses a Postgres advisory transaction lock, so the worker and API containers can start together safely.

Database connection failures are returned as normal command errors after the configured retry budget. Inside the worker, this means a transient DB/DNS failure can fail the current program/task and be reported, but it must not terminate the whole `zero worker` process.

Custom one-off scans can be launched immediately with `zero run manual` or queued for the worker with `zero run schedule`. Queued requests are stored in `zero_scan_requests`, picked up every 30 seconds, and executed with the request-specific parameters instead of mutating global `.env` defaults.

Broad custom scan campaigns can be queued with `zero run schedule --all-programs`. A campaign stores one durable parent row in `zero_scan_campaigns` and one child request per selected program in `zero_scan_requests`. Child requests force `SkipSync=true`, so a campaign that spans hundreds of programs does not refresh HackerOne scope before every program. Use `--campaign-parallelism` to set how many programs from that campaign may run at the same time. The worker still caps total queued custom work with `ZERO_TARGET_PARALLELISM`.

Campaign selection defaults to every active program, regardless of the normal interval. Add `--due-only` when the campaign should respect each program's `scan_interval_hours`, and `--campaign-limit` for staged rollouts. A campaign survives worker/container restarts: running child requests are requeued on startup, campaign counters are refreshed, and completed children remain completed.

For each due program, Zero executes:

```text
enum subfinder --program-id ... -> probe dnsx --program-id ... -> probe httpx --program-id ... -> enrich webanalyze --program-id ... -> analyze cves --program-id ... -> analyze nuclei --program-id ... -> report generate --program-id ... -> notify discord --program-id ...
```

The default full-pipeline schedule is `0 15 3 */3 * *` with seconds-enabled cron syntax, matching the initial three-day cadence.

Each external tool call is bounded by `ZERO_TOOL_TIMEOUT` and defaults to 20 minutes. When a tool times out inside `zero run once`, `zero run due`, `zero run manual`, or `zero tools nuclei-update`, Zero stops that step, marks the current scan run as failed when applicable, and emits a Discord operational alert if `ZERO_DISCORD_ALERT_WEBHOOK_URL` or the legacy `ZERO_DISCORD_WEBHOOK_URL` fallback is configured. The alert includes the alert type, program, step command, configured timeout, and error text. The Docker entrypoint also bounds the optional startup Nuclei template update with the same timeout so the container can continue booting if template refresh stalls.

`ZERO_HTTPX_TIMEOUT` controls the per-request timeout passed to httpx with `-timeout`; it defaults to 4 seconds. `ZERO_HTTPX_THREADS` controls httpx internal worker threads with `-threads`; it defaults to 20. These are separate from `ZERO_TOOL_TIMEOUT`, which bounds the whole scan step.

`ZERO_HTTPX_BATCH_SIZE` controls how many hosts are sent to one httpx process. Default: `50`. `ZERO_HTTPX_BATCH_TIMEOUT` controls the wall-clock timeout for each httpx batch and defaults to `5m`; it is capped by `ZERO_TOOL_TIMEOUT` when the global timeout is lower. Broad roots with thousands of live hosts, such as tenant/UGC/customer platforms, are processed in multiple bounded chunks so one slow batch does not discard all progress for the program.

`ZERO_HTTPX_PATTERN_MIN_GROUP` and `ZERO_HTTPX_PATTERN_CAP` control the pre-httpx host budget heuristic. Defaults: group threshold `200`, cap `120`. The heuristic applies only after scope/out-of-scope/bounty/DNS filtering and only to large roots that look tenant-like, UGC-like, hash-like, numeric, or extremely broad. It preserves exact scope assets and priority labels such as `api`, `admin`, `auth`, `login`, `payment`, `portal`, `staging`, `dev`, `vpn`, and similar operationally sensitive names. Set cap/min-group to `0` to disable only if the config value is also `0`.

`ZERO_WEBANALYZE_BATCH_SIZE` controls how many alive services are sent to one Webanalyze process. Default: `500`. This matters for programs where many hosts collapse to the same SaaS/CDN/default page.

`ZERO_HTTPX_TLS_PROBE` defaults to `false`. Keep it disabled for broad continuous scans: on real targets such as `valve`, httpx v1.9.0 can emit results quickly but keep the process alive until the global tool timeout when `-tls-probe` is enabled. Use `zero probe httpx --tls-probe` or `zero run manual --httpx-tls-probe` only for targeted certificate/TLS inspection.

Nuclei templates are updated on container startup when `ZERO_NUCLEI_UPDATE_TEMPLATES_ON_STARTUP=true` and by the worker schedule `ZERO_SCHEDULE_NUCLEI_TEMPLATES` (default: `0 5 3 * * *`). They are not updated before every program scan because template updates are global, network-dependent, and can add avoidable latency/noise to target processing.

Passive CVE matching defaults to `ZERO_CVE_MIN_YEAR=2018`. CVEs older than this threshold are ignored during NVD matching, excluded from CVE-derived Nuclei template selection, and blocked from passive/unconfirmed report generation even if older records already exist in the database.

Passive findings are prioritization context, not proof. Zero lowers confidence and annotates evidence when an NVD summary appears configuration- or module-dependent, for example Apache module issues, Varnish VCL/proxy conditions, TLS termination conditions, or HTTP/2-specific cases. Those reports should be treated as conditional passive intel unless Nuclei or manual validation confirms the target condition.

## Data Lifecycle

Zero should not blindly delete missing data. Missing assets should be marked inactive only after enough scan evidence shows they are gone. New or changed entities are written to `zero_change_events`, and reports/Discord notifications should use that table to avoid repeating old results.

Current change events are emitted for newly inserted scope assets, subdomains, HTTP services, technology observations, Nuclei results, and candidate findings. They are deduped by stable evidence hash and can be read from `/v1/changes` or `/v1/programs/{program_id}/changes`.

Task-generated entities carry the current scan id: scope assets, subdomains, HTTP services, and technology observations use `last_scan_run_id`; Nuclei results, reports, and change events use `scan_run_id`. This is the authoritative audit trail for tying a report or notification back to the execution that produced it.

Stale cleanup is conservative and time-based. `ZERO_STALE_AFTER_HOURS=168` means a target must be unseen for roughly seven days before subdomains, HTTP services, or technology observations are marked inactive. Set it to `0` to disable stale cleanup.

On worker startup, `ZERO_RECOVER_RUNNING_SCANS=true` marks interrupted `zero_scan_runs.status='running'` rows as failed with recovery metadata. Since the program's `last_scan_finished_at` is not advanced by an interrupted run, that program remains due and the startup run can continue from the persisted database state. Interrupted `zero_scan_requests.status='running'` rows are requeued with `run_after=now()`, so a custom scan that was claimed before a container shutdown does not stay stuck forever.

HTTP services, subdomains, and technology observations are not hard-deleted when they disappear once. They remain deduped by stable keys and are marked inactive by stale cleanup after `ZERO_STALE_AFTER_HOURS`. This keeps the API focused on currently active rows while avoiding noisy deletes caused by transient DNS, WAF, or network failures.

HackerOne scope sync defaults to `ZERO_SCOPE_PRIVATE_ONLY=false`, so bbscope imports both public and private open programs visible to the configured account. `ZERO_SCOPE_BOUNTY_ONLY=true` keeps VDP programs out. Assets that are listed as in-scope by the platform but are not bounty-eligible are stored as out-of-scope in Zero, so they block broad wildcard expansion instead of being scanned. Set `ZERO_SCOPE_PRIVATE_ONLY=true` only when intentionally limiting Zero to private/soft-launched programs.

## Smoke Tests

Use limits when validating external tools:

```bash
zero sync h1
zero enum subfinder --limit 2
zero probe dnsx --limit 50
zero probe httpx --limit 50
zero enrich webanalyze --limit 50
zero analyze cves --limit 1
zero analyze nuclei --from-cves --limit 5 --cve-limit 10
zero analyze nuclei --limit 5 --template-id CVE-2025-20362
zero report generate --limit 50
zero report export-triage --limit 50 --output triage-bundles.jsonl
zero notify discord --dry-run
zero run due --dry-run --limit 4
zero run manual --skip-sync --program-id <uuid> --webanalyze-apps ./custom-technologies.json --cve-limit 5 --nuclei-from-cves --nuclei-cve-limit 10 --nuclei-limit 20
zero run manual --skip-sync --program-id <uuid> --httpx-batch-size 50 --httpx-batch-timeout 5m --httpx-pattern-min-group 200 --httpx-pattern-cap 80 --webanalyze-batch-size 250 --webanalyze-apps ./custom-technologies.json --cve-limit 5 --nuclei-template ./templates/custom-cve.yaml --nuclei-severity high,critical --nuclei-rate-limit 40 --nuclei-concurrency 10 --nuclei-limit 20
zero run manual --skip-sync --program-id <uuid> --webanalyze-apps ./custom-technologies.json --nuclei-template-id CVE-2025-20362 --nuclei-timeout 10 --nuclei-retries 1 --nuclei-limit 20
zero run schedule --run-after 30m --program-id <uuid> --skip-sync --nuclei-from-cves --nuclei-cve-limit 20
zero run schedule --all-programs --campaign-parallelism 4 --campaign-limit 25 --skip-sync --httpx-batch-size 50 --httpx-batch-timeout 5m --httpx-pattern-cap 80 --webanalyze-apps ./custom-technologies.json --webanalyze-workers 6 --webanalyze-batch-size 250 --cve-limit 10 --nuclei-template ./templates/custom --nuclei-severity medium,high,critical --nuclei-rate-limit 40 --nuclei-concurrency 10 --nuclei-limit 100
zero run schedule --all-programs --due-only --campaign-parallelism 2 --skip-sync --skip-enum --skip-dns --skip-probe --webanalyze-apps ./custom-technologies.json --skip-nuclei
zero api
```

This validates the pipeline without turning a local setup check into a broad scan.

Use `zero run once` only when you want the full configured global pipeline without per-step smoke-test limits. Use `zero run due` for the normal continuous per-program execution model.

Use `zero run manual` for targeted one-off scans. Use `zero run schedule` for the same parameter set when the worker should execute it later. Add `--all-programs` when the same custom scan should become a persistent campaign across the active program inventory. Flags such as `--httpx-timeout`, `--httpx-threads`, `--httpx-batch-size`, `--httpx-batch-timeout`, `--httpx-pattern-min-group`, `--httpx-pattern-cap`, `--httpx-tls-probe`, `--webanalyze-apps`, `--webanalyze-workers`, `--webanalyze-crawl`, `--webanalyze-batch-size`, `--skip-cves`, `--cve-limit`, `--nuclei-from-cves`, `--nuclei-cve-limit`, `--nuclei-template-id`, `--nuclei-template`, `--nuclei-tags`, `--nuclei-severity`, `--nuclei-rate-limit`, `--nuclei-concurrency`, `--nuclei-bulk-size`, `--nuclei-timeout`, `--nuclei-retries`, and `--nuclei-limit` affect only that execution and do not change `.env`, worker schedules, or global defaults.

Some valid bounty scopes are intentionally massive tenant platforms. Examples observed in the first run were `fanbox.cc`, `hubspotpagebuilder.*`, `hubspotemail.net`, `varonis.io`, `glance.net`, and hash-like `wurl.com` hosts. These are not automatically out-of-scope, but they can produce thousands of near-identical CloudFront/Cloudflare/S3/default-page results. For those targets, prefer smaller `--httpx-batch-size`, smaller `--httpx-batch-timeout`, smaller `--webanalyze-batch-size`, or a targeted custom campaign before broad active validation.

## Discord Notifications

`zero notify discord` sends only reports that do not have a successful `zero_discord_notifications` row for the report dedupe key. Failed notifications are stored and can be retried; successful notifications are not sent again.

Report notifications label validation status explicitly. Nuclei-backed findings are announced as confirmed by Nuclei; passive CVE candidates without a linked Nuclei result are announced as potential/passive and require manual validation.

If both report webhooks are empty, the command is a safe no-op. Use `--dry-run` to count pending reports without creating notification rows or sending webhooks. Reports with at least one linked Nuclei result are sent to `ZERO_DISCORD_VALIDATED_WEBHOOK_URL`; passive-only reports are sent to `ZERO_DISCORD_PASSIVE_WEBHOOK_URL`, falling back to `ZERO_DISCORD_WEBHOOK_URL`.

## Triage Export

Use `zero report export-triage` to create JSONL bundles for Proteus/Codex review. Each line contains the finding, program, service, Nuclei result, active technology observations, passive CVE context, and report metadata when available.

```bash
zero report export-triage --status new --limit 100 --output triage-bundles.jsonl
zero report export-triage --program-id <uuid> --status reported --limit 50
```

## Docker Services

`docker compose up -d zero api dashboard` starts the continuous worker, read API, and local dashboard. The API service overrides `ZERO_API_ADDR` to `0.0.0.0:8080` inside the container and publishes it on `127.0.0.1:8080` on the host. The worker/API image uses `tini` as PID 1 so interrupted external tools are reaped cleanly. The dashboard service listens on `127.0.0.1:8090` by default and proxies API reads from the container network using `ZERO_API_TOKEN`, so the browser does not receive the API token.

Open the dashboard at:

```text
http://127.0.0.1:8090
```

The dashboard reads:

- global stats from `/v1/stats`;
- full program list from `/v1/programs`;
- selected program stats from `/v1/programs/{program_id}/stats`;
- recent scans from `/v1/scans/latest`;
- recent findings from `/v1/findings`.

Keep `ZERO_API_TOKEN` set when exposing either the API or dashboard beyond localhost. If the dashboard needs to be exposed remotely, put it behind a trusted auth layer or tunnel with access control instead of publishing the container directly.

## Subfinder Providers

The public repo ships only a safe template at `configs/subfinder/provider-config.example.yaml`.

For Docker runs, put provider API keys in `.env`. The image writes a private Subfinder provider config at startup from:

```env
ZERO_SUBFINDER_SHODAN_API_KEY=""
ZERO_SUBFINDER_BEVIGIL_API_KEY=""
ZERO_SUBFINDER_VIRUSTOTAL_API_KEY=""
ZERO_SUBFINDER_SECURITYTRAILS_API_KEY=""
```

The Docker defaults are:

```env
ZERO_SUBFINDER_BIN="subfinder"
ZERO_DNSX_BIN="dnsx"
ZERO_DNSX_RATE=200
ZERO_HTTPX_BIN="httpx"
ZERO_WEBANALYZE_BIN="webanalyze"
ZERO_WEBANALYZE_APPS="/usr/local/share/webanalyze/technologies.json"
ZERO_NUCLEI_BIN="nuclei"
ZERO_NUCLEI_TEMPLATE_DIR="/home/zero/nuclei-templates"
ZERO_NUCLEI_UPDATE_TEMPLATES_ON_STARTUP=true
ZERO_NUCLEI_FROM_CVES=true
ZERO_NUCLEI_CVE_LIMIT=100
ZERO_HTTPX_TIMEOUT=4
ZERO_HTTPX_THREADS=20
ZERO_HTTPX_TLS_PROBE=false
ZERO_SUBFINDER_PROVIDER_CONFIG="/home/zero/.config/subfinder/provider-config.yaml"
ZERO_SUBFINDER_SOURCES="shodan,bevigil,virustotal,securitytrails"
ZERO_SUBFINDER_RATE_LIMITS="shodan=1/s,virustotal=4/m,securitytrails=1/s,bevigil=1/s"
```

Do not commit provider configs containing real API keys.

## Scope Safety

`subfinder` only receives active in-scope `wildcard` assets from the database. For `*.sub.example.com`, the root sent to Subfinder is `sub.example.com`; Zero does not collapse it to `example.com`.

After enumeration, each result must match the wildcard regex derived from that exact asset. `*.example.com` accepts `app.example.com` and `a.b.example.com`, but rejects `example.com`, `example.com.evil.test`, and sibling domains.

Enumeration roots are derived only from explicit wildcard assets whose registrable/root domain is also authorized by the program scope. `*.example.com` sends `example.com` to Subfinder. `*.api.example.com` sends `example.com` only if `example.com` or `*.example.com` is also in-scope, then filters results back to `*.api.example.com`. `*.sub.heroku.com` is skipped unless `heroku.com` itself is authorized, so SaaS/provider roots are not enumerated accidentally. A plain `sub.heroku.com` domain/url asset is probed exactly and does not authorize child enumeration.

After Subfinder enumeration, exact in-scope `domain` and `url` assets that are themselves subdomains are also upserted into `zero_subdomains` with the `scope:*` source. This keeps the final deduplicated subdomain list complete even when a scoped host was provided directly by the platform and not rediscovered by Subfinder.

Out-of-scope `domain`, `url`, and `wildcard` assets override broad in-scope wildcards. This keeps assets such as `*.excluded.example.com` or `admin.example.com` from being probed when the program has explicitly excluded them.

Exact `domain` and `url` assets are probed by `httpx` as exact hosts only. They are not used as enumeration roots and they do not authorize arbitrary child subdomains.
