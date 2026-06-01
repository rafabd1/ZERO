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
GET /v1/scans/latest
GET /v1/scan-requests
GET /v1/changes?since=...
GET /v1/notifications/discord
GET /v1/programs/{program_id}/latest-scan
GET /v1/programs/{program_id}/changes?since=...
GET /v1/programs/{program_id}/assets
GET /v1/programs/{program_id}/services
GET /v1/programs/{program_id}/technologies
GET /v1/programs/{program_id}/technology-vulnerabilities
GET /v1/programs/{program_id}/nuclei-results
GET /v1/programs/{program_id}/findings?status=new
GET /v1/reports/latest
```

Responses should be paginated. Findings and Nuclei results should support filters for severity, confidence, status, and time range.

Current implementation includes `GET /healthz`, `GET /v1/programs`, `GET /v1/assets`, `GET /v1/services`, `GET /v1/technologies`, `GET /v1/technology-vulnerabilities`, `GET /v1/nuclei-results`, and `GET /v1/findings`.
Current implementation also includes `GET /v1/reports`, `GET /v1/reports/latest`, `GET /v1/scans/latest`, `GET /v1/scan-requests`, `GET /v1/changes?since=...`, `GET /v1/notifications/discord`, `GET /v1/programs/{program_id}/latest-scan`, `GET /v1/programs/{program_id}/changes?since=...`, `GET /v1/programs/{program_id}/assets`, `GET /v1/programs/{program_id}/services`, `GET /v1/programs/{program_id}/technologies`, `GET /v1/programs/{program_id}/technology-vulnerabilities`, `GET /v1/programs/{program_id}/nuclei-results`, and `GET /v1/programs/{program_id}/findings?status=new`.

The `since` query parameter accepts a Postgres-compatible timestamp and returns events with `occurred_at` greater than that value.

Asset and service responses include `last_scan_run_id` when the entity was produced or refreshed by a task. Nuclei results, reports, and change events expose `scan_run_id`.

## Notification Flow

1. Scan finishes.
2. Zero reads new `zero_candidate_findings` and `zero_change_events`.
3. Report generator creates a deduped summary from new Nuclei-backed findings.
4. Discord worker sends only unseen reports.
5. `zero_discord_notifications` stores delivery status and dedupe key.
