# Architecture

Zero is a stateful campaign system. Every scan step reads from and writes to Postgres so recon, fingerprinting, passive intelligence, active validation, reporting, and dashboard views can share one durable inventory.

```mermaid
flowchart LR
  S["Scope providers"] --> DB["Postgres/Supabase"]
  DB --> SF["subfinder"]
  SF --> DB
  DB --> DNS["dnsx"]
  DNS --> DB
  DB --> HX["httpx"]
  HX --> DB
  DB --> WA["Webanalyze"]
  WA --> DB
  DB --> CVE["Passive CVE context"]
  CVE --> DB
  DB --> NUC["Nuclei validation"]
  NUC --> DB
  DB --> REP["Deduped reports"]
  REP --> API["API"]
  REP --> DIS["Discord"]
  API --> DASH["Dashboard"]
```

## Main Services

- `zero`: the continuous worker and CLI for sync, recon, enrichment, validation, reporting, and custom campaign queueing.
- `api`: authenticated read and orchestration API for dashboards, integrations, and operator tools.
- `dashboard`: local UI for visual monitoring of programs, campaigns, scans, progress, and findings.
- `migrate`: one-shot migration service used with the Compose `tools` profile.

## Core Tables

- `zero_programs`: bug bounty programs and scan cadence.
- `zero_scope_assets`: in-scope and out-of-scope assets.
- `zero_subdomains`: discovered hostnames.
- `zero_http_services`: alive URLs and `httpx` fingerprints.
- `zero_technology_observations`: technology names, versions, and sources.
- `zero_vulnerability_records`: CVE/advisory/template records.
- `zero_technology_vulnerability_matches`: passive CVE context linked to technologies.
- `zero_nuclei_results`: active validation output.
- `zero_candidate_findings`: deduplicated finding candidates.
- `zero_scan_runs`: execution history for individual steps.
- `zero_scan_requests` and `zero_scan_campaigns`: durable custom scan work.
- `zero_reports`: generated report artifacts.

Every asset and result is linked back to a program. This matters because the same hostname can appear in multiple programs with different scope rules.

## Execution Model

Continuous runs scan due programs based on `scan_interval_hours`. Custom campaigns create durable scan requests and are consumed by a worker pool. Default/due scans use `ZERO_TARGET_PARALLELISM`; custom campaigns use their own campaign-level parallelism so focused work can run independently of the default schedule.

The default per-program flow is:

```text
scope-safe enumeration -> DNS resolution -> HTTP probing -> technology enrichment -> passive CVE context -> Nuclei validation -> report -> notify
```

`httpx` and Webanalyze provide target intelligence. Passive CVE matches provide prioritization context. Nuclei provides active validation when a relevant template is selected.

Custom campaigns can intentionally use only part of the pipeline. For example, a campaign can refresh recon only, run custom fingerprinting without Nuclei, run Nuclei directly against active HTTP services, or use Nuclei DNS templates against stored subdomains. This is why Postgres is the source of truth: results from one campaign can seed the next campaign or external tools.

## Recovery

On startup, the worker:

1. marks interrupted scan runs with recovery metadata;
2. requeues interrupted custom scan requests;
3. refreshes campaign counters;
4. resumes normal scheduled work.

Completed child requests stay completed, so campaigns survive container restarts without starting from scratch.
