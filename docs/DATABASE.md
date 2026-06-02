# Database

Zero uses Postgres, commonly through Supabase hosted Postgres.

Set:

```env
ZERO_DATABASE_URL="postgres://postgres:password@db.project-ref.supabase.co:5432/postgres?sslmode=require"
```

Apply migrations:

```bash
docker compose --profile tools run --rm migrate
```

All tables are prefixed with `zero_`.

## Deduplication

Zero avoids duplicate rows by using stable program-scoped keys:

- scope assets: program, type, normalized target, and direction;
- subdomains: program and hostname;
- HTTP services: program and URL;
- technology observations: service, normalized name, version, and source;
- vulnerability records: CVE/advisory/template id;
- passive technology/CVE matches: program, vulnerability, technology/version, and source query;
- Nuclei results: program, template, matched URL, and evidence hash;
- candidate findings and change events: evidence hash.

This lets campaigns rerun safely without repeating old reports.

## Lifecycle

Data is deactivated conservatively instead of deleted immediately. `ZERO_STALE_AFTER_HOURS` controls when stale subdomains, services, and technology observations become inactive.

Scan runs and custom scan requests keep execution history, recovery metadata, and campaign progress.

## Supabase Notes

Zero talks directly to Postgres with `pgx` because batch ingestion is simpler and faster through SQL than through Supabase REST.

Keep service-role keys backend-only. Do not expose database credentials in browser clients or public dashboards.
