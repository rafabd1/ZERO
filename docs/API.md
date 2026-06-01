# API Design

Zero needs an authenticated API so Discord and operator tools can retrieve the latest state without querying Supabase directly.

## Authentication

Use a backend-only bearer token:

```http
Authorization: Bearer <ZERO_API_TOKEN>
```

Never expose Supabase service-role keys to clients.

## Initial Endpoints

```text
GET /healthz
GET /v1/programs
GET /v1/assets
GET /v1/services
GET /v1/technologies
GET /v1/technology-vulnerabilities
GET /v1/nuclei-results
GET /v1/findings
GET /v1/stats
GET /v1/scans/latest
GET /v1/scan-requests
POST /v1/scan-requests
GET /v1/changes?since=...
GET /v1/notifications/discord
GET /v1/programs/{program_id}/latest-scan
GET /v1/programs/{program_id}/stats
GET /v1/programs/{program_id}/changes?since=...
GET /v1/programs/{program_id}/assets
GET /v1/programs/{program_id}/services
GET /v1/programs/{program_id}/technologies
GET /v1/programs/{program_id}/technology-vulnerabilities
GET /v1/programs/{program_id}/nuclei-results
GET /v1/programs/{program_id}/findings?status=new
GET /v1/reports/latest
```

Hot list endpoints accept pagination/filter query parameters:

- `limit`: max rows, capped at 1000.
- `offset`: row offset.
- `since`: timestamp lower bound.
- `severity`: supported on findings, Nuclei results, and reports.
- `status`: supported on findings.
- `min_confidence`: supported on findings.
- `template_id`: supported on Nuclei results.
- `q`: host/URL search on services.

Current implementation includes `GET /healthz`, `GET /v1/programs`, `GET /v1/assets`, `GET /v1/services`, `GET /v1/technologies`, `GET /v1/technology-vulnerabilities`, `GET /v1/nuclei-results`, and `GET /v1/findings`.
Current implementation also includes `GET /v1/stats`, `GET /v1/reports`, `GET /v1/reports/latest`, `GET /v1/scans/latest`, `GET /v1/scan-requests`, `POST /v1/scan-requests`, `GET /v1/changes?since=...`, `GET /v1/notifications/discord`, `GET /v1/programs/{program_id}/latest-scan`, `GET /v1/programs/{program_id}/stats`, `GET /v1/programs/{program_id}/changes?since=...`, `GET /v1/programs/{program_id}/assets`, `GET /v1/programs/{program_id}/services`, `GET /v1/programs/{program_id}/technologies`, `GET /v1/programs/{program_id}/technology-vulnerabilities`, `GET /v1/programs/{program_id}/nuclei-results`, and `GET /v1/programs/{program_id}/findings?status=new`.

The `since` query parameter accepts a Postgres-compatible timestamp and returns events with `occurred_at` greater than that value.

Asset and service responses include `last_scan_run_id` when the entity was produced or refreshed by a task. Nuclei results, reports, and change events expose `scan_run_id`.

Examples:

```http
GET /v1/findings?status=new&severity=critical&min_confidence=90&limit=25
GET /v1/nuclei-results?template_id=CVE-2025-20362&limit=50
GET /v1/services?q=vpn&since=2026-06-01T00:00:00Z
GET /v1/stats
GET /v1/programs/00000000-0000-0000-0000-000000000000/stats
```

Create a queued custom scan request:

```http
POST /v1/scan-requests
Authorization: Bearer <ZERO_API_TOKEN>
Content-Type: application/json

{
  "program_id": "00000000-0000-0000-0000-000000000000",
  "name": "targeted-cve-check",
  "run_after": "30m",
  "params": {
    "ProgramID": "00000000-0000-0000-0000-000000000000",
    "SkipSync": true,
    "NucleiFromCVEs": true,
    "NucleiCVELimit": 20,
    "NucleiLimit": 50
  }
}
```

## Notification Flow

1. Scan finishes.
2. Zero reads new `zero_candidate_findings` and `zero_change_events`.
3. Report generator creates a deduped summary from new Nuclei-backed findings and eligible passive CVE candidates.
4. Discord worker sends only unseen reports, routing confirmed reports to the validated webhook and passive-only reports to the passive webhook.
5. `zero_discord_notifications` stores delivery status and dedupe key.
