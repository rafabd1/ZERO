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

Fingerprint lifecycle is source-aware. A normal `httpx` run updates the service's latest `technologies` JSON and marks missing `source=httpx` observations inactive for that service. A full Webanalyze run does the same for `source=webanalyze` observations after all selected services are processed. Custom Webanalyze app files are treated as partial intelligence and do not deactivate missing technologies.

Scan runs and custom scan requests keep execution history, recovery metadata, and campaign progress. Queued or running requests and campaigns can be canceled through the API or CLI; canceled requests cannot be marked succeeded by a late-finishing worker step.

Inactive inventory cleanup removes old inactive scope assets, subdomains, services, technology observations, and passive technology/CVE rows after the configured retention window or after they have been absent from the configured number of successful full scans. HTTP services linked to Nuclei results or candidate findings are preserved for evidence integrity.

## Supabase Notes

Zero talks directly to Postgres with `pgx` because batch ingestion is simpler and faster through SQL than through Supabase REST.

Keep service-role keys backend-only. Do not expose database credentials in browser clients or public dashboards.
