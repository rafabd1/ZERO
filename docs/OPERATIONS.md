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
- Later Discord integration:
  - `ZERO_DISCORD_WEBHOOK_URL`
- API protection:
  - `ZERO_API_TOKEN`

## Scan Cadence

Default per-target scan interval: 72 hours.

Default target parallelism: 4 programs at the same time.

Program-level overrides live in `zero_programs.scan_interval_hours` and `zero_programs.max_parallel_tasks`.

## Data Lifecycle

Zero should not blindly delete missing data. Missing assets should be marked inactive only after enough scan evidence shows they are gone. New or changed entities are written to `zero_change_events`, and reports/Discord notifications should use that table to avoid repeating old results.

## Smoke Tests

Use limits when validating external tools:

```bash
zero sync h1
zero enum subfinder --limit 2
zero probe httpx --limit 50
zero analyze nuclei --limit 5 --template-id CVE-2025-20362
zero api
```

This validates the pipeline without turning a local setup check into a broad scan.

## Subfinder Providers

The public repo ships only a safe template at `configs/subfinder/provider-config.example.yaml`.

For local runs, either let Subfinder use its default `$HOME/.config/subfinder/provider-config.yaml`, or create a private provider config and point Zero to it:

```env
ZERO_SUBFINDER_PROVIDER_CONFIG="C:\\Users\\rafae\\.config\\subfinder\\provider-config.yaml"
ZERO_SUBFINDER_SOURCES="shodan,bevigil,virustotal,securitytrails"
ZERO_SUBFINDER_RATE_LIMITS="shodan=1/s,virustotal=4/m,securitytrails=1/s,bevigil=1/s"
```

Do not commit provider configs containing real API keys.
