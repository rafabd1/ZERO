# Operations

## Credentials Needed

To run the first real scan, Zero needs:

- `ZERO_DATABASE_URL`: Supabase Postgres connection string with `sslmode=require`.
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
- External tools installed or available in Docker:
  - `subfinder`
  - `httpx`
  - `nuclei`
- Discord integration:
  - `ZERO_DISCORD_WEBHOOK_URL`
- API protection:
  - `ZERO_API_TOKEN`

## Scan Cadence

Default per-target scan interval: 72 hours.

Default target parallelism: 4 programs at the same time.

Program-level overrides live in `zero_programs.scan_interval_hours` and `zero_programs.max_parallel_tasks`.

The main continuous execution path is `zero worker`, which schedules `zero run due` using `ZERO_SCHEDULE_FULL`. It first refreshes HackerOne scope, then selects active programs whose `last_scan_finished_at` is older than their configured interval, and processes up to `ZERO_TARGET_PARALLELISM` programs concurrently.

By default the worker also runs this due-program planner immediately on container startup (`ZERO_RUN_ON_STARTUP=true`). This makes the container self-starting after deploy/restart instead of waiting for the next cron tick.

For each due program, Zero executes:

```text
enum subfinder --program-id ... -> probe httpx --program-id ... -> analyze cves --program-id ... -> analyze nuclei --program-id ... -> report generate --program-id ... -> notify discord --program-id ...
```

The default full-pipeline schedule is `0 15 3 */3 * *` with seconds-enabled cron syntax, matching the initial three-day cadence.

## Data Lifecycle

Zero should not blindly delete missing data. Missing assets should be marked inactive only after enough scan evidence shows they are gone. New or changed entities are written to `zero_change_events`, and reports/Discord notifications should use that table to avoid repeating old results.

On worker startup, `ZERO_RECOVER_RUNNING_SCANS=true` marks interrupted `zero_scan_runs.status='running'` rows as failed with recovery metadata. Since the program's `last_scan_finished_at` is not advanced by an interrupted run, that program remains due and the startup run can continue from the persisted database state.

HackerOne scope sync defaults to `ZERO_SCOPE_PRIVATE_ONLY=false`, so bbscope imports both public and private open programs visible to the configured account. `ZERO_SCOPE_BOUNTY_ONLY=true` keeps VDP programs out. Assets that are listed as in-scope by the platform but are not bounty-eligible are stored as out-of-scope in Zero, so they block broad wildcard expansion instead of being scanned. Set `ZERO_SCOPE_PRIVATE_ONLY=true` only when intentionally limiting Zero to private/soft-launched programs.

## Smoke Tests

Use limits when validating external tools:

```bash
zero sync h1
zero enum subfinder --limit 2
zero probe httpx --limit 50
zero analyze nuclei --limit 5 --template-id CVE-2025-20362
zero report generate --limit 50
zero notify discord --dry-run
zero run due --dry-run --limit 4
zero api
```

This validates the pipeline without turning a local setup check into a broad scan.

Use `zero run once` only when you want the full configured global pipeline without per-step smoke-test limits. Use `zero run due` for the normal continuous per-program execution model.

## Discord Notifications

`zero notify discord` sends only reports that do not have a successful `zero_discord_notifications` row for the report dedupe key. Failed notifications are stored and can be retried; successful notifications are not sent again.

If `ZERO_DISCORD_WEBHOOK_URL` is empty, the command is a safe no-op. Use `--dry-run` to count pending reports without creating notification rows or sending webhooks.

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
ZERO_HTTPX_BIN="httpx"
ZERO_NUCLEI_BIN="nuclei"
ZERO_SUBFINDER_PROVIDER_CONFIG="/home/zero/.config/subfinder/provider-config.yaml"
ZERO_SUBFINDER_SOURCES="shodan,bevigil,virustotal,securitytrails"
ZERO_SUBFINDER_RATE_LIMITS="shodan=1/s,virustotal=4/m,securitytrails=1/s,bevigil=1/s"
```

Do not commit provider configs containing real API keys.

## Scope Safety

`subfinder` only receives active in-scope `wildcard` assets from the database. For `*.sub.example.com`, the root sent to Subfinder is `sub.example.com`; Zero does not collapse it to `example.com`.

After enumeration, each result must match the wildcard regex derived from that exact asset. `*.example.com` accepts `app.example.com` and `a.b.example.com`, but rejects `example.com`, `example.com.evil.test`, and sibling domains.

Out-of-scope `domain`, `url`, and `wildcard` assets override broad in-scope wildcards. This keeps assets such as `*.excluded.example.com` or `admin.example.com` from being probed when the program has explicitly excluded them.

Exact `domain` and `url` assets are probed by `httpx` as exact hosts only. They are not used as enumeration roots and they do not authorize arbitrary child subdomains.
