# API

Zero exposes a local HTTP API for dashboards, operator scripts, and external research tools. It is a control-plane and read surface over the same Postgres state used by the worker: programs, scope assets, subdomains, HTTP services, technologies, scans, campaigns, Nuclei results, findings, reports, and notifications.

The API is intentionally explicit. There is no global `/v1/find` endpoint. Use the list endpoints with `q`, `program_id`, `platform`, and resource-specific filters.

## Base URL And Auth

Docker Compose exposes the API on:

```text
http://127.0.0.1:8080
```

If `ZERO_API_TOKEN` is set, every endpoint except `/healthz` requires:

```http
Authorization: Bearer <ZERO_API_TOKEN>
```

If `ZERO_API_TOKEN` is empty, local requests do not need an `Authorization` header. Do not expose the API or dashboard publicly without trusted access control.

PowerShell helper:

```powershell
$api = "http://127.0.0.1:8080"
$tokenLine = Get-Content .env | Where-Object { $_ -match '^ZERO_API_TOKEN=' } | Select-Object -First 1
$token = ""
if ($tokenLine) { $token = ($tokenLine -replace '^ZERO_API_TOKEN=', '').Trim('"') }
$headers = @{}
if ($token) { $headers.Authorization = "Bearer $token" }

Invoke-RestMethod -Headers $headers -Uri "$api/healthz"
Invoke-RestMethod -Headers $headers -Uri "$api/v1/stats"
```

curl helper:

```bash
API=http://127.0.0.1:8080
TOKEN="${ZERO_API_TOKEN:-}"
AUTH=()
if [ -n "$TOKEN" ]; then AUTH=(-H "Authorization: Bearer $TOKEN"); fi

curl -sS "${AUTH[@]}" "$API/v1/stats"
```

## Endpoint Map

Core reads:

```text
GET /healthz
GET /v1/stats
GET /v1/inventory/overview
GET /v1/programs
GET /v1/assets
GET /v1/scope-assets
GET /v1/subdomains
GET /v1/services
GET /v1/technologies
GET /v1/technology-vulnerabilities
GET /v1/vulnerabilities
GET /v1/nuclei-results
GET /v1/findings
GET /v1/reports
GET /v1/reports/latest
GET /v1/changes
GET /v1/notifications/discord
```

Scan and campaign reads:

```text
GET /v1/default-scans
GET /v1/default-scans/{cycle_id}
GET /v1/scans/latest
GET /v1/scans/{scan_id}
GET /v1/scan-runs
GET /v1/scan-requests
GET /v1/scan-campaigns
GET /v1/scan-campaigns/{campaign_id}
```

Program-scoped reads:

```text
GET /v1/programs/{program_id}/stats
GET /v1/programs/{program_id}/latest-scan
GET /v1/programs/{program_id}/assets
GET /v1/programs/{program_id}/subdomains
GET /v1/programs/{program_id}/services
GET /v1/programs/{program_id}/technologies
GET /v1/programs/{program_id}/technology-vulnerabilities
GET /v1/programs/{program_id}/nuclei-results
GET /v1/programs/{program_id}/findings
GET /v1/programs/{program_id}/reports
GET /v1/programs/{program_id}/changes
```

Mutating endpoints:

```text
POST   /v1/scan-requests
POST   /v1/scan-requests/{request_id}/cancel
DELETE /v1/scan-requests/{request_id}
POST   /v1/scan-campaigns/{campaign_id}/cancel
DELETE /v1/scan-campaigns/{campaign_id}
```

## Pagination And Filters

List endpoints return JSON arrays. Use:

- `limit`: default varies by endpoint; maximum is `1000`.
- `offset`: zero-based page offset.
- `since`: timestamp filter for records seen/created after a point.
- `q`: broad substring search. This is not a domain-aware exact search.
- `program_id`: filter global inventory endpoints to one program.
- `platform`: provider/source platform such as `h1`, `intigriti`, or `bugcrowd`.

Common performance tips:

- Prefer `program_id` once you know the program.
- Prefer `active=true` for inventory endpoints.
- Use `limit` plus `offset` for broad extraction; do not request one huge page and assume all rows were returned.
- Use `/v1/programs?compact=true` for dashboards or selectors that only need basic program metadata.
- Use exact local filtering for domain suffix checks after a `q` search, because `q=x.com` can match unrelated strings containing `x.com`.

Endpoint-specific filters:

```text
/v1/programs
  q, active, platform, program_id, compact

/v1/scope-assets and /v1/programs/{id}/assets
  q, active, in_scope, eligible_for_bounty, asset_type, platform, since

/v1/subdomains and /v1/programs/{id}/subdomains
  q, active, resolves, platform, since

/v1/services and /v1/programs/{id}/services
  q, active, status_code, platform, since

/v1/technologies and /v1/programs/{id}/technologies
  q, active, source, versioned, platform, since

/v1/nuclei-results and /v1/programs/{id}/nuclei-results
  q, severity, template_id, platform, since

/v1/findings and /v1/programs/{id}/findings
  q, status, severity, min_confidence, platform, since

/v1/reports and /v1/programs/{id}/reports
  q, severity, include_body, platform, since

/v1/scan-runs and /v1/scans/latest
  q, run_type, status, program_id, platform, since

/v1/scan-requests
  q, status, campaign_id, program_id, platform, since

/v1/scan-campaigns
  q, status, since

/v1/changes and /v1/programs/{id}/changes
  q, entity_type, change_type, since
```

## Finding Programs And Assets

Find likely programs:

```powershell
$programs = Invoke-RestMethod -Headers $headers -Uri "$api/v1/programs?q=x&limit=50"
$programs | Select-Object id, platform, handle, program_url, active
```

Find active services containing a domain string, then filter by real suffix locally:

```powershell
$rows = Invoke-RestMethod -Headers $headers -Uri "$api/v1/services?q=x.com&active=true&limit=1000"
$candidates = @($rows | Where-Object {
  $_.host -match '(^|\.)x\.com$' -or $_.host -match '(^|\.)twitter\.com$'
})
$candidates | Select-Object url, host, status_code, title, webserver, program_id, program_handle, program_platform
```

Once a program is known, use program-scoped endpoints:

```powershell
$programID = "00000000-0000-0000-0000-000000000000"
Invoke-RestMethod -Headers $headers -Uri "$api/v1/programs/$programID/stats"
Invoke-RestMethod -Headers $headers -Uri "$api/v1/programs/$programID/services?active=true&limit=1000"
Invoke-RestMethod -Headers $headers -Uri "$api/v1/programs/$programID/findings?limit=100"
```

Page through a large list:

```powershell
$all = @()
for ($offset = 0; ; $offset += 1000) {
  $page = @(Invoke-RestMethod -Headers $headers -Uri "$api/v1/services?active=true&limit=1000&offset=$offset")
  if ($page.Count -eq 0) { break }
  $all += $page
  if ($page.Count -lt 1000) { break }
}
"loaded=$($all.Count)"
```

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
    "NucleiTemplate": "/home/zero/custom-assets/custom.yaml",
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
    "WebanalyzeApps": "/home/zero/custom-assets/custom-technologies.json",
    "WebanalyzeAppFiles": [
      "/home/zero/custom-assets/another-custom-technologies.json"
    ],
    "WebanalyzeProbePaths": [
      "/admin/",
      "/api/version"
    ],
    "DisablePassiveFingerprintReports": false,
    "WebanalyzeWorkers": 4,
    "WebanalyzeBatch": 50,
    "WebanalyzeBatchTimeout": "10m",
    "NucleiTemplate": "/home/zero/custom-assets/templates",
    "NucleiTemplates": [
      "/home/zero/custom-assets/extra-check.yaml"
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
GET /v1/scan-campaigns/{campaign_id}
GET /v1/scan-requests?campaign_id={campaign_id}
```

Campaigns are durable. If the worker restarts, running child requests are requeued and completed child requests stay completed.

Custom campaign parallelism is independent from `ZERO_TARGET_PARALLELISM`. The worker adds capacity from active campaigns, so two campaigns with `parallelism: 8` can use up to 16 custom scan workers if the host has capacity.

`ZERO_SCAN_REQUEST_MAX_ACTIVE` is a safety ceiling above campaign parallelism. In Docker, the local `dbpool` PgBouncer sidecar mediates upstream Supabase sessions, so this value can be higher than the upstream pool size while `ZERO_DBPOOL_DEFAULT_POOL_SIZE` remains bounded. Without `dbpool`, keep it below the effective database pooler session limit, leaving room for the worker, API, dashboard, and operational commands.

Campaign detail responses include `running_requests` and per-request progress fields such as `progress_stage`, `progress_current`, `progress_total`, `progress_meta`, `active_http_services`, and `estimated_webanalyze_urls`. These fields are useful for broad custom path-probe campaigns where one program can expand thousands of HTTP services into tens of thousands of Webanalyze URLs.

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
