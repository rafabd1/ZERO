# Database

Zero uses Supabase as a managed Postgres database. Set `ZERO_DATABASE_URL` to a Supabase Postgres connection string with `sslmode=require`.

Apply migrations:

```bash
go run ./cmd/zero migrate up
```

The initial migration creates tables prefixed with `zero_` to avoid collisions with other public schemas.

## Deduplication

- Scope assets are unique per program, asset type, normalized target, and scope direction.
- Subdomains are unique per program and FQDN.
- HTTP services are unique per program and URL.
- Technology observations are unique by service, lowercased name, version, and source.
- Vulnerability records are unique by vulnerability id, for example `CVE-2025-20362`.
- Technology/CVE matches are unique per program, vulnerability, technology/version, and source query.
- Nuclei results are unique per program, template, matched URL, and evidence hash.
- Candidate findings are unique by `evidence_hash`.
- Change events are unique by `evidence_hash`.

## Supabase Notes

The pipeline currently talks directly to Postgres using `pgx`, which is simpler and faster than using Supabase REST for batch ingestion. Row-level security should not be enabled for these internal tables unless service-role access policies are added deliberately.

For production, use the Supabase service-role key only on the backend/worker side. Do not put service keys in browser clients or public dashboards.
