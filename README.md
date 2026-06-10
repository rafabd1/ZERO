# Zero

<p align="center">
  <img src="assets/zero-banner.gif" alt="Animated ASCII ZERO wordmark" width="960">
</p>

Zero is a campaign engine for authorized recon, fingerprinting, and targeted validation across bug bounty programs and large external inventories.

It collects scope from bug bounty platforms, expands authorized assets, identifies live services and technologies, stores everything in Postgres, and lets operators launch durable research campaigns against the resulting inventory. A campaign can be broad and passive, like mapping exposed technologies across every target, or highly focused, like fingerprinting a product on known paths and validating one custom Nuclei template only where that fingerprint appears.

The point is not to run every scanner against every URL. Zero is built to answer focused research questions at scale, deduplicate evidence, survive restarts, and keep the data reusable for dashboards, manual triage, Discord notifications, and other tools.

## What Zero Is Good At

- Importing and normalizing scope from HackerOne, Bugcrowd, and Intigriti through the bbscope-based poller.
- Expanding only authorized wildcard roots with `subfinder`.
- Filtering discoveries through in-scope and out-of-scope rules before probing.
- Resolving and probing assets with `dnsx` and `httpx`.
- Identifying technologies with `httpx` intelligence and Webanalyze/Wappalyzer definitions.
- Running custom fingerprint campaigns with additional Webanalyze app files and path probes.
- Running Nuclei against HTTP services, hostnames, DNS templates, CVE templates, exposure checks, or custom validation templates.
- Combining tools or using them separately, depending on the campaign goal.
- Storing scope, assets, services, technologies, CVE context, Nuclei output, findings, reports, scan state, and campaign progress in Postgres.
- Reusing stored inventory for later scans so repeated campaigns do not have to redo expensive discovery every time.
- Monitoring campaigns through a local dashboard and an authenticated API.

## How It Works

The default worker pipeline is:

```text
scope sync -> subfinder -> dnsx -> httpx -> Webanalyze -> passive CVE context -> Nuclei -> report -> notify
```

Custom campaigns can run the full pipeline or skip stages:

- Recon only: sync scope, enumerate, resolve, probe, and store live assets.
- Fingerprint only: run Webanalyze and custom path probes against active services.
- Passive research: map technologies and CVE context without active validation.
- Targeted validation: run Nuclei only where a technology, title, banner, or custom fingerprint matches.
- Nuclei-only: run a safe template or template directory directly against selected HTTP services or scoped hostnames.
- DNS/takeover style checks: run Nuclei against stored subdomains instead of HTTP URLs.

Because every stage writes structured state to Postgres, Zero's output can be queried by the dashboard/API or reused by external tooling.

## Quick Start

```bash
cp .env.example .env
```

Set at least:

```env
ZERO_DATABASE_URL="postgres://postgres:password@db.project-ref.supabase.co:5432/postgres?sslmode=require"
ZERO_API_TOKEN=""
ZERO_SCOPE_PROVIDERS="h1"
ZERO_H1_USERNAME=""
ZERO_H1_TOKEN=""
```

Then start:

```bash
docker compose --profile tools run --rm migrate
docker compose up -d zero api dashboard
```

Open the dashboard:

```text
http://127.0.0.1:8090
```

The `zero` service runs the continuous worker, `api` exposes authenticated reads and orchestration endpoints, and `dashboard` provides a local visual interface for programs, campaigns, scans, findings, and progress.

## First Checks

Use small limits before broad execution:

```bash
docker compose run --rm zero sync all
docker compose run --rm zero run due --dry-run --limit 5
docker compose run --rm zero enum subfinder --limit 2
docker compose run --rm zero probe dnsx --limit 50
docker compose run --rm zero probe httpx --limit 50
docker compose run --rm zero enrich webanalyze --limit 50
docker compose run --rm zero notify discord --dry-run
```

The worker is self-starting by default. On startup it runs migration, recovery, a daily scope-sync guard, and due-program planning.

## Example Campaigns

Run a broad fingerprint campaign against recently discovered active services:

```bash
docker compose run --rm zero run schedule \
  --all-programs \
  --campaign-parallelism 8 \
  --name "product-fingerprint-sweep" \
  --skip-sync \
  --reuse-active-services \
  --webanalyze-apps /home/zero/custom-assets/product.webanalyze.json \
  --webanalyze-probe-path /admin/ \
  --webanalyze-probe-path /api/version \
  --skip-cves \
  --skip-nuclei
```

Run focused fingerprinting and then validate only matching assets with Nuclei:

```bash
docker compose run --rm zero run schedule \
  --all-programs \
  --campaign-parallelism 8 \
  --name "product-validation-sweep" \
  --skip-sync \
  --reuse-active-services \
  --webanalyze-apps /home/zero/custom-assets/product.webanalyze.json \
  --webanalyze-probe-path /admin/ \
  --webanalyze-batch-size 50 \
  --webanalyze-batch-timeout 10m \
  --nuclei-template /home/zero/custom-assets/product-check.yaml \
  --nuclei-tech-filter "Example Product|ExampleProduct" \
  --nuclei-force \
  --nuclei-rate-limit 30 \
  --nuclei-concurrency 8 \
  --nuclei-target-batch-size 500 \
  --nuclei-target-batch-timeout 20m
```

Run a DNS-oriented Nuclei campaign against scoped hostnames:

```bash
docker compose run --rm zero run schedule \
  --all-programs \
  --campaign-parallelism 8 \
  --campaign-limit 100 \
  --name "dns-template-stage" \
  --skip-sync \
  --skip-enum \
  --skip-probe \
  --skip-enrich \
  --skip-cves \
  --nuclei-force \
  --nuclei-target-source subdomains \
  --nuclei-protocol dns \
  --nuclei-template /home/zero/custom-assets/dns-check.yaml
```

Campaigns are durable. They create one parent campaign and one child request per selected program. If the worker restarts, interrupted requests are recovered and completed children stay completed.

## CLI At A Glance

```text
zero sync all                 import provider scope
zero enum subfinder           enumerate authorized wildcard roots
zero probe dnsx               resolve discovered hostnames
zero probe httpx              find alive HTTP services and collect httpx intel
zero enrich webanalyze        detect technologies with Webanalyze definitions
zero analyze cves             enrich versioned technologies with passive CVE context
zero analyze nuclei           run Nuclei against selected target sources
zero report generate          generate deduplicated reports
zero notify discord           send new report notifications
zero run schedule             queue durable custom campaigns
zero run cancel               cancel queued or running work
zero run cleanup              prune operational state and stale inventory
zero worker                   run the continuous scheduler/worker
zero api                      run the authenticated API
```

See [CLI Reference](docs/CLI.md) for the full operator surface and recipes.

## Scope Safety

Zero is designed for authorized testing.

- `subfinder` receives only authorized wildcard roots.
- Exact domain and URL assets are probed exactly; they are not expanded into child subdomains.
- Out-of-scope assets override broad in-scope wildcards.
- Non-bounty assets are treated as out-of-scope when provider data exposes that distinction.
- Passive technology/CVE matches are labeled as potential intelligence unless active evidence confirms them.

## Documentation

- [CLI Reference](docs/CLI.md): command surface, stage-by-stage usage, and campaign patterns.
- [Custom Campaigns](docs/CUSTOM_CAMPAIGNS.md): targeted scan recipes, custom Webanalyze files, path probes, and Nuclei templates.
- [Architecture](docs/ARCHITECTURE.md): services, state model, recovery, and campaign execution.
- [Operations](docs/OPERATIONS.md): setup, schedules, tuning, cleanup, and notifications.
- [API](docs/API.md): endpoint map, query recipes, filters, pagination, and scan orchestration examples.
- [Database](docs/DATABASE.md): state tables and deduplication rules.
- [Nuclei](docs/NUCLEI.md): validation policy and template selection.
- [Tools](docs/TOOLS.md): external tool roles and configuration notes.

## Status

Zero is an early operational project. Use it only against assets you are authorized to test.
