# API

The API is a read and orchestration surface for dashboards and operator tools. It should be protected with a backend bearer token.

```http
Authorization: Bearer <ZERO_API_TOKEN>
```

Never expose Supabase service-role keys to browsers or public clients.

## Common Reads

```text
GET /healthz
GET /v1/stats
GET /v1/programs
GET /v1/scans/latest
GET /v1/scan-requests
GET /v1/scan-campaigns
GET /v1/findings
GET /v1/reports/latest
GET /v1/changes?since=...
GET /v1/programs/{program_id}/stats
GET /v1/programs/{program_id}/latest-scan
GET /v1/programs/{program_id}/services
GET /v1/programs/{program_id}/technologies
GET /v1/programs/{program_id}/nuclei-results
GET /v1/programs/{program_id}/findings
```

List endpoints commonly accept:

- `limit`
- `offset`
- `since`
- `severity`
- `status`
- `min_confidence`
- `template_id`
- `q`

## Queue One Program

```http
POST /v1/scan-requests
Authorization: Bearer <ZERO_API_TOKEN>
Content-Type: application/json

{
  "program_id": "00000000-0000-0000-0000-000000000000",
  "name": "targeted-template-check",
  "run_after": "30m",
  "params": {
    "ProgramID": "00000000-0000-0000-0000-000000000000",
    "SkipSync": true,
    "NucleiTemplate": "/work/templates/custom.yaml",
    "NucleiTechFilter": "product-name",
    "NucleiTechMaxAge": "2h",
    "NucleiHeaders": [
      "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36",
      "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language: en-US,en;q=0.9"
    ],
    "NucleiRateLimit": 40,
    "NucleiConcurrency": 10,
    "NucleiLimit": 50
  }
}
```

## Queue A Campaign

```http
POST /v1/scan-requests
Authorization: Bearer <ZERO_API_TOKEN>
Content-Type: application/json

{
  "all_programs": true,
  "name": "custom-technology-sweep",
  "run_after": "now",
  "parallelism": 8,
  "limit": 0,
  "due_only": false,
  "params": {
    "SkipSync": true,
    "HTTPXBatchSize": 50,
    "HTTPXBatchTimeout": "5m",
    "WebanalyzeApps": "/work/custom-technologies.json",
    "WebanalyzeWorkers": 4,
    "NucleiTemplate": "/work/templates/custom",
    "NucleiForce": true,
    "NucleiTechFilter": "product-name",
    "NucleiTechMaxAge": "2h",
    "NucleiSeverity": "medium,high,critical",
    "NucleiHeaders": [
      "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36"
    ],
    "NucleiRateLimit": 40,
    "NucleiConcurrency": 10
  }
}
```

The response includes a campaign id. Track progress with:

```text
GET /v1/scan-campaigns
GET /v1/scan-requests
```

Campaigns are durable. If the worker restarts, running child requests are requeued and completed child requests stay completed.

## Reports And Notifications

Report generation deduplicates findings before notification. Discord delivery stores delivery state so successful notifications are not sent twice.

Confirmed reports can be routed to `ZERO_DISCORD_VALIDATED_WEBHOOK_URL`; passive/unconfirmed reports can be routed to `ZERO_DISCORD_PASSIVE_WEBHOOK_URL`.
