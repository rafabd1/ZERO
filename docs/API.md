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
GET /v1/programs/{program_id}/latest-scan
GET /v1/programs/{program_id}/changes?since_scan_id=...
GET /v1/programs/{program_id}/assets
GET /v1/programs/{program_id}/services
GET /v1/programs/{program_id}/nuclei-results
GET /v1/programs/{program_id}/findings?status=new
GET /v1/reports/latest
```

Responses should be paginated. Findings and Nuclei results should support filters for severity, confidence, status, and time range.

## Notification Flow

1. Scan finishes.
2. Zero reads new `zero_candidate_findings` and `zero_change_events`.
3. Report generator creates a deduped summary.
4. Discord worker sends only unseen findings.
5. `zero_discord_notifications` stores delivery status and dedupe key.
