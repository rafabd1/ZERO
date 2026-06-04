# CLI Reference

Zero's CLI can run the full continuous pipeline or individual stages. This lets operators use Zero as a general-purpose campaign system for recon, technology identification, passive vulnerability intelligence, and targeted active validation.

Most commands can be run through Docker Compose:

```bash
docker compose run --rm zero <command>
```

For a running stack, the `zero` service executes the worker while one-off CLI invocations queue work, inspect state, or run specific stages.

## Command Map

```text
zero migrate up          apply database migrations
zero sync                import scope from configured platforms
zero enum                enumerate assets
zero probe               resolve and probe discovered assets
zero enrich              fingerprint technologies
zero analyze             enrich and validate vulnerability context
zero report              generate and export deduplicated reports
zero notify              send deduplicated notifications
zero run                 run, queue, cancel, and clean pipeline work
zero tools               update external tool caches
zero worker              run scheduled monitoring tasks
zero api                 run the authenticated API
```

## Scope Sync

```bash
zero sync all
zero sync h1
zero sync bugcrowd
zero sync intigriti
```

Scope sync imports programs and assets from configured providers, applies bounty/scope filters, stores in-scope and out-of-scope assets, and keeps the rest of the pipeline tied to program ownership.

Use:

- `ZERO_SCOPE_PROVIDERS=h1,bugcrowd,intigriti` to select providers.
- `ZERO_SCOPE_BOUNTY_ONLY=true` to keep bounty-eligible programs/assets.
- `ZERO_SCOPE_SYNC_MAX_AGE=24h` so the startup worker does not sync on every restart.

## Recon And Probing

```bash
zero enum subfinder --program-id <uuid> --limit 10
zero probe dnsx --program-id <uuid> --limit 1000
zero probe httpx --program-id <uuid> --limit 500
```

The recon stages are intentionally separable:

- `enum subfinder` expands only authorized wildcard roots.
- `probe dnsx` resolves discovered hostnames.
- `probe httpx` finds alive HTTP services and stores status, title, server, URL, TLS/favicons, and lightweight technology hints.

Use these stages alone when the campaign goal is inventory refresh rather than vulnerability validation.

For large inventories, tune:

```bash
zero probe dnsx --batch-size 1000 --batch-timeout 10m
zero probe httpx --timeout 4 --threads 20 --batch-size 50 --batch-timeout 5m
```

`httpx` also supports pattern budgeting to cap huge groups of near-identical tenant-like hosts:

```bash
zero probe httpx --pattern-min-group 200 --pattern-cap 120
```

## Technology Fingerprinting

```bash
zero enrich webanalyze --program-id <uuid> --limit 500
```

Webanalyze uses Wappalyzer-style definitions and stores technology observations, versions when available, source, evidence, and active/inactive state.

Custom fingerprints can be supplied for a campaign:

```bash
zero run schedule \
  --program-id <uuid> \
  --skip-sync \
  --reuse-active-services \
  --webanalyze-apps /home/zero/custom-assets/product.webanalyze.json \
  --webanalyze-probe-path /admin/ \
  --webanalyze-probe-path /api/version \
  --skip-cves \
  --skip-nuclei
```

`--webanalyze-apps` is repeatable. `--webanalyze-probe-path` is also repeatable and fingerprints additional paths derived from each alive service. This is useful when a product only exposes identifiable markers on `/admin/`, `/console/`, `/demo/`, `/api/version`, or similar paths.

Normal full fingerprints update the active technology inventory. Custom app files and path probes are treated as partial intelligence, so they can add focused observations without clearing unrelated existing technologies.

## Passive CVE Context

```bash
zero analyze cves --program-id <uuid> --limit 50
```

This stage links versioned technology observations to NVD/CVE context and marks candidates that may have matching Nuclei templates. It is passive intelligence and should not be treated as proof of exploitability.

Useful settings:

```env
ZERO_NVD_API_KEY=""
ZERO_CVE_MIN_YEAR=2018
ZERO_NVD_RETRIES=5
ZERO_NVD_RETRY_WAIT="10s"
```

Zero serializes NVD requests across concurrent workers and respects retry delays to avoid discarding scans on temporary rate limits.

## Nuclei Validation

```bash
zero analyze nuclei --program-id <uuid> --from-cves
zero analyze nuclei --program-id <uuid> --template-id CVE-YYYY-NNNN
zero analyze nuclei --program-id <uuid> --template-path /home/zero/custom-assets/check.yaml --force
```

Nuclei can validate many template families, not only CVEs:

- CVE templates;
- exposure or misconfiguration templates;
- product-specific safe checks;
- DNS and dangling-record checks;
- SSL/TCP/other protocol templates supported by Nuclei.

Target source matters:

```bash
zero analyze nuclei --target-source http-services --protocol http
zero analyze nuclei --target-source subdomains --protocol dns
zero analyze nuclei --protocol auto
```

Use `http-services` for alive URLs and technology-gated HTTP templates. Use `subdomains` for hostname/DNS templates.

For focused active validation, gate Nuclei by fingerprint:

```bash
zero analyze nuclei \
  --program-id <uuid> \
  --template-path /home/zero/custom-assets/product-check.yaml \
  --tech-filter "Example Product|ExampleProduct" \
  --force
```

If the same run performs fingerprinting first, Zero automatically keeps the filter fresh. Use `--tech-max-age` only when skipping fingerprinting and intentionally relying on existing observations.

Explicit template paths or template IDs do not inherit default `cve` tag or `medium,high,critical` severity filters. Add `--tags` or `--severity` only when you intentionally want to restrict supplied templates.

For broad campaigns, control runtime:

```bash
zero analyze nuclei \
  --rate-limit 30 \
  --concurrency 8 \
  --bulk-size 5 \
  --timeout 10 \
  --retries 1 \
  --target-batch-size 500 \
  --target-batch-timeout 20m
```

Nuclei target batching keeps large programs from consuming a whole scan timeout in a single process.

## Durable Campaigns

`zero run schedule` queues durable scan requests for the worker. This is the main interface for broad custom research.

Single program:

```bash
zero run schedule \
  --program-id <uuid> \
  --name "targeted-check" \
  --skip-sync \
  --reuse-active-services \
  --nuclei-template /home/zero/custom-assets/check.yaml \
  --nuclei-force
```

All active programs:

```bash
zero run schedule \
  --all-programs \
  --campaign-parallelism 8 \
  --campaign-limit 100 \
  --name "staged-campaign" \
  --skip-sync \
  --reuse-active-services \
  --webanalyze-apps /home/zero/custom-assets/product.webanalyze.json \
  --webanalyze-probe-path /admin/ \
  --nuclei-template /home/zero/custom-assets/check.yaml \
  --nuclei-tech-filter "Example Product" \
  --nuclei-force
```

Important campaign controls:

- `--campaign-parallelism`: number of programs this campaign may scan at once.
- `--campaign-limit`: stage broad campaigns before all-program execution.
- `--due-only`: include only programs due for their normal scan interval.
- `--run-after`: schedule for later, using a duration or RFC3339 timestamp.
- `--reuse-active-services`: skip `dnsx/httpx` and use stored active HTTP services.
- `--skip-*`: remove stages that are not needed for the research question.
- `--disable-passive-fingerprint-reports`: report only active validation results.

Custom campaign parallelism is independent from `ZERO_TARGET_PARALLELISM`, which controls default/due scans. `ZERO_SCAN_REQUEST_MAX_ACTIVE` is the safety ceiling for custom scan workers.

## Manual Runs

```bash
zero run manual --program-id <uuid> --skip-sync --reuse-active-services --skip-cves
```

`run manual` executes the same custom pipeline immediately in the current process instead of queueing it for the worker. It is useful for small smoke tests and debugging, while `run schedule` is better for durable campaigns.

## Default Pipeline

```bash
zero run due --dry-run --limit 5
zero run due --limit 10
zero run once
```

Use `run due` to execute normal program scans based on configured scan intervals. Use `--dry-run` before broad default execution.

The continuous worker runs the same planning logic on startup and by schedule:

```bash
zero worker
```

## Cancel And Cleanup

```bash
zero run cancel --request-id <scan-request-id>
zero run cancel --campaign-id <scan-campaign-id>
zero run cleanup --retention-hours 72 --retention-scans 2
```

Canceling a campaign marks queued and running child requests canceled. A tool already running may finish its current process, but the request cannot be marked succeeded afterward.

Cleanup removes stale inactive inventory while preserving services linked to findings or Nuclei evidence.

## Reports And Notifications

```bash
zero report generate --program-id <uuid>
zero report export-triage --status new --limit 100 --output triage.jsonl
zero notify discord --dry-run
zero notify discord
```

Reports deduplicate findings and separate passive/unconfirmed evidence from active Nuclei validation. Discord notifications can route validated, passive, and operational alert messages to separate webhooks.

## API And Dashboard

```bash
zero api
```

The API exposes stats, programs, scans, campaigns, findings, reports, services, technologies, and Nuclei results. It also supports queueing and canceling scan requests/campaigns.

The dashboard is a separate service in Docker Compose. It is intended for visual monitoring of programs, campaign details, scan progress, recent findings, and request cancellation.

## Tool Cache

```bash
zero tools nuclei-update
```

This updates the configured Nuclei template directory. In the worker, template updates can also be scheduled.

## File Paths For Custom Assets

For Docker Compose runs, custom private files should live in:

```text
./custom-assets
```

Reference them from queued campaigns through the container path:

```text
/home/zero/custom-assets/file.yaml
/home/zero/custom-assets/file.webanalyze.json
```

Files under `custom-assets/` are ignored by Git except public placeholders.
