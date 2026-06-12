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

Zero stores current reusable state by default. Assets that stop resolving or services that disappear from an authoritative probe are marked inactive and then removed by cleanup unless they are linked to Nuclei evidence or candidate findings. DNS-only subdomains that have no active HTTP service are also removed by default during cleanup; set `ZERO_RETAIN_DNS_ONLY_SUBDOMAINS=true` when a deployment intentionally needs a broad DNS inventory for DNS templates or takeover-style research.

Fingerprint lifecycle is source-aware. A normal `httpx` run updates the service's latest `technologies` JSON and marks missing `source=httpx` observations inactive for that service. A full Webanalyze run does the same for `source=webanalyze` observations after all selected services are processed. Custom Webanalyze app files are treated as partial intelligence and do not deactivate missing technologies.

Scan runs and custom scan requests keep short-lived execution history, recovery metadata, and campaign progress. Queued or running requests and campaigns can be canceled through the API or CLI; canceled requests cannot be marked succeeded by a late-finishing worker step. Completed scan runs and scan requests are pruned by default after 72 hours because durable security evidence lives in findings, Nuclei results, reports, services, technologies, and scope records.

Change events are intentionally strict. The default `ZERO_CHANGE_EVENT_ENTITIES=candidate_finding,nuclei_result` avoids storing high-volume inventory history for every subdomain, service, or technology observation. Set it to `all` only when you explicitly need full audit history and have enough database storage.

Inactive inventory cleanup removes inactive scope assets, subdomains, services, technology observations, and passive technology/CVE rows. The default `ZERO_DELETE_INACTIVE_INVENTORY=true`, `ZERO_INACTIVE_RETENTION_HOURS=0`, and `ZERO_INACTIVE_RETENTION_SCANS=0` deletes inactive operational rows immediately during cleanup. HTTP services linked to Nuclei results or candidate findings are preserved for evidence integrity.

Cleanup runs in bounded batches via `ZERO_CLEANUP_BATCH_SIZE` to avoid large Supabase transactions. If a database already grew because of deleted rows or old change-event history, `zero run cleanup --compact-storage` can run `VACUUM FULL ANALYZE` on large operational tables, and `zero run cleanup --compact-change-events` can rewrite `zero_change_events` after pruning disallowed event types. Use these during quiet maintenance windows.

## Supabase Notes

Zero talks directly to Postgres with `pgx` because batch ingestion is simpler and faster through SQL than through Supabase REST.

Keep service-role keys backend-only. Do not expose database credentials in browser clients or public dashboards.
