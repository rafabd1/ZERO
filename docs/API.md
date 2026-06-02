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
    "ReuseActiveServices": true,
    "NucleiTemplate": "/work/templates/custom.yaml",
    "NucleiTechFilter": "product-name",
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
    "ReuseActiveServices": true,
    "WebanalyzeApps": "/work/custom-technologies.json",
    "WebanalyzeAppFiles": [
      "/work/another-custom-technologies.json"
    ],
    "WebanalyzeProbePaths": [
      "/admin/",
      "/api/version"
    ],
    "DisablePassiveFingerprintReports": false,
    "WebanalyzeWorkers": 4,
    "WebanalyzeBatch": 50,
    "WebanalyzeBatchTimeout": "10m",
    "NucleiTemplate": "/work/templates/custom",
    "NucleiTemplates": [
      "/work/templates/extra-check.yaml"
    ],
    "NucleiForce": true,
    "NucleiTechFilter": "product-name",
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

Custom campaign parallelism is independent from `ZERO_TARGET_PARALLELISM`. The worker adds capacity from active campaigns, so two campaigns with `parallelism: 8` can use up to 16 custom scan workers if the host has capacity.

When a request or campaign runs `httpx` and/or Webanalyze before Nuclei, Zero automatically keeps `NucleiTechFilter` tied to fresh fingerprints from that run. Use `NucleiTechMaxAge` only for requests that skip fingerprinting and intentionally gate Nuclei from existing database observations.

Set `ReuseActiveServices: true` to skip fresh `dnsx/httpx` probing and load active HTTP services already present in the database. This is meant for back-to-back focused campaigns where the alive inventory was recently refreshed. In this mode, `DNSX*` and `HTTPX*` params are intentionally ignored.

## Cancel Work

```http
POST /v1/scan-requests/{request_id}/cancel
Authorization: Bearer <ZERO_API_TOKEN>
```

```http
POST /v1/scan-campaigns/{campaign_id}/cancel
Authorization: Bearer <ZERO_API_TOKEN>
```

`DELETE` aliases are also available for both endpoints. Canceling a campaign marks queued and running child requests as canceled. A tool already running in a child process may finish its current step, but the request cannot be marked succeeded afterward.

## Reports And Notifications

Report generation deduplicates findings before notification. Discord delivery stores delivery state so successful notifications are not sent twice.

Confirmed reports can be routed to `ZERO_DISCORD_VALIDATED_WEBHOOK_URL`; passive/unconfirmed reports can be routed to `ZERO_DISCORD_PASSIVE_WEBHOOK_URL`.
