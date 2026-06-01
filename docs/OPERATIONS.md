# Operations

## Credentials Needed

To run the first real scan, Zero needs:

- `ZERO_DATABASE_URL`: Supabase Postgres connection string with `sslmode=require`.
- `ZERO_DATABASE_MAX_CONNS`: max pgx pool connections per Zero process. Default: 1. Keep this low when using Supabase session pooler because parallel scans run many short-lived task processes.
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

Custom one-off scans can be launched immediately with `zero run manual` or queued for the worker with `zero run schedule`. Queued requests are stored in `zero_scan_requests`, picked up every 30 seconds, and executed with the request-specific parameters instead of mutating global `.env` defaults.

For each due program, Zero executes:

```text
enum subfinder --program-id ... -> probe dnsx --program-id ... -> probe httpx --program-id ... -> enrich webanalyze --program-id ... -> analyze cves --program-id ... -> analyze nuclei --program-id ... -> report generate --program-id ... -> notify discord --program-id ...
```

The default full-pipeline schedule is `0 15 3 */3 * *` with seconds-enabled cron syntax, matching the initial three-day cadence.

Each external tool call is bounded by `ZERO_TOOL_TIMEOUT` and defaults to 20 minutes. When a tool times out inside `zero run once`, `zero run due`, `zero run manual`, or `zero tools nuclei-update`, Zero stops that step, marks the current scan run as failed when applicable, and emits a Discord operational alert if `ZERO_DISCORD_ALERT_WEBHOOK_URL` or the legacy `ZERO_DISCORD_WEBHOOK_URL` fallback is configured. The alert includes the alert type, program, step command, configured timeout, and error text. The Docker entrypoint also bounds the optional startup Nuclei template update with the same timeout so the container can continue booting if template refresh stalls.

`ZERO_HTTPX_TIMEOUT` controls the per-request timeout passed to httpx with `-timeout`; it defaults to 4 seconds. `ZERO_HTTPX_THREADS` controls httpx internal worker threads with `-threads`; it defaults to 20. These are separate from `ZERO_TOOL_TIMEOUT`, which bounds the whole httpx process for a program.

`ZERO_HTTPX_TLS_PROBE` defaults to `false`. Keep it disabled for broad continuous scans: on real targets such as `valve`, httpx v1.9.0 can emit results quickly but keep the process alive until the global tool timeout when `-tls-probe` is enabled. Use `zero probe httpx --tls-probe` or `zero run manual --httpx-tls-probe` only for targeted certificate/TLS inspection.

Nuclei templates are updated on container startup when `ZERO_NUCLEI_UPDATE_TEMPLATES_ON_STARTUP=true` and by the worker schedule `ZERO_SCHEDULE_NUCLEI_TEMPLATES` (default: `0 5 3 * * *`). They are not updated before every program scan because template updates are global, network-dependent, and can add avoidable latency/noise to target processing.

Passive CVE matching defaults to `ZERO_CVE_MIN_YEAR=2018`. CVEs older than this threshold are ignored during NVD matching, excluded from CVE-derived Nuclei template selection, and blocked from passive/unconfirmed report generation even if older records already exist in the database.

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
zero run manual --skip-sync --program-id <uuid> --webanalyze-apps ./custom-technologies.json --cve-limit 5 --nuclei-template ./templates/custom-cve.yaml --nuclei-severity high,critical --nuclei-rate-limit 40 --nuclei-concurrency 10 --nuclei-limit 20
zero run manual --skip-sync --program-id <uuid> --webanalyze-apps ./custom-technologies.json --nuclei-template-id CVE-2025-20362 --nuclei-timeout 10 --nuclei-retries 1 --nuclei-limit 20
zero run schedule --run-after 30m --program-id <uuid> --skip-sync --nuclei-from-cves --nuclei-cve-limit 20
zero api
```

This validates the pipeline without turning a local setup check into a broad scan.

Use `zero run once` only when you want the full configured global pipeline without per-step smoke-test limits. Use `zero run due` for the normal continuous per-program execution model.

Use `zero run manual` for targeted one-off scans. Use `zero run schedule` for the same parameter set when the worker should execute it later. Flags such as `--httpx-timeout`, `--httpx-threads`, `--httpx-tls-probe`, `--webanalyze-apps`, `--webanalyze-workers`, `--webanalyze-crawl`, `--skip-cves`, `--cve-limit`, `--nuclei-from-cves`, `--nuclei-cve-limit`, `--nuclei-template-id`, `--nuclei-template`, `--nuclei-tags`, `--nuclei-severity`, `--nuclei-rate-limit`, `--nuclei-concurrency`, `--nuclei-bulk-size`, `--nuclei-timeout`, `--nuclei-retries`, and `--nuclei-limit` affect only that execution and do not change `.env`, worker schedules, or global defaults.

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

`docker compose up -d zero api` starts the continuous worker and read API. The API service overrides `ZERO_API_ADDR` to `0.0.0.0:8080` inside the container and publishes it on `127.0.0.1:8080` on the host. Keep `ZERO_API_TOKEN` set when exposing the API beyond localhost.

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
