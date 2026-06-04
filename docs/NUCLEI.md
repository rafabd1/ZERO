# Nuclei

Zero uses Nuclei as an active validation layer, not as the only source of target intelligence. It can validate CVEs, exposures, misconfigurations, DNS conditions, dangling records, SSL/TCP checks, and product-specific custom templates.

## Policy

For broad runs, start with:

- alive URLs only;
- CVE-tagged, technology-gated, or explicit templates;
- `medium,high,critical` severities;
- configured request headers that look like normal browser traffic;
- target batching for large programs;
- JSONL output stored in `zero_nuclei_results`.

Nuclei is strongest when a relevant template exists and produces vulnerability-specific evidence. If no template exists, Zero can still keep passive CVE context, but it should be reported as potential/unconfirmed.

## Default Role Split

- `httpx`: alive checks and lightweight fingerprints.
- Webanalyze: broader technology and version observations.
- Passive CVE context: prioritization from versioned technologies.
- Nuclei: active validation when a relevant template is selected.

## Focused Validation

```bash
docker compose run --rm zero analyze nuclei \
  --limit 25 \
  --template-id CVE-YYYY-NNNN \
  --header "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36" \
  --rate-limit 40 \
  --concurrency 10 \
  --timeout 10
```

Custom path:

```bash
docker compose run --rm zero analyze nuclei \
  --template-path /home/zero/custom-assets/custom.yaml \
  --severity high,critical \
  --rate-limit 40 \
  --concurrency 10
```

Campaigns can pass the same Nuclei options through `zero run schedule`.

Explicit template paths or template IDs do not inherit Zero's default `cve` tag or `medium,high,critical` severity filters. Add `--tags` or `--severity` only when you intentionally want to restrict the supplied templates.

Target source and protocol:

```bash
docker compose run --rm zero analyze nuclei \
  --target-source http-services \
  --protocol http \
  --template-path /home/zero/custom-assets/http-check.yaml
```

```bash
docker compose run --rm zero analyze nuclei \
  --target-source subdomains \
  --protocol dns \
  --template-path /home/zero/custom-assets/dns-check.yaml
```

Use `--protocol auto` when a template directory mixes protocols and Nuclei should infer them.

Technology-gated validation:

```bash
docker compose run --rm zero analyze nuclei \
  --tech-filter "product-name" \
  --tech-max-age 2h \
  --template-path /home/zero/custom-assets/custom.yaml \
  --severity high,critical
```

`--tech-filter` matches active technology observations, `httpx` technology names, titles, and server banners. In full custom campaigns that run `httpx` and/or Webanalyze immediately before Nuclei, Zero automatically applies a freshness window to keep the gate tied to that run. `--tech-max-age` is mainly useful when you skip fingerprinting and intentionally want to validate against recent database observations. Custom Webanalyze app files are partial by design and do not deactivate the normal full fingerprint inventory.

## Request Profile

Set `ZERO_NUCLEI_HEADERS` to pass browser-like headers to every Nuclei HTTP request. Headers are separated with `|`:

```env
ZERO_NUCLEI_HEADERS="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36|Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8|Accept-Language: en-US,en;q=0.9"
```

Custom scans can override the global profile with repeated `--nuclei-header` flags or `NucleiHeaders` in scan-request JSON.

Optional campaign knobs:

- `ZERO_NUCLEI_PROXY` / `--nuclei-proxy`
- `ZERO_NUCLEI_SCAN_STRATEGY` / `--nuclei-scan-strategy`
- `ZERO_NUCLEI_MAX_HOST_ERROR` / `--nuclei-max-host-error`

## Runtime Batching

Large programs can contain thousands of alive services. Zero runs Nuclei in target batches so one large program does not consume the whole step timeout in a single process.

Defaults:

```env
ZERO_NUCLEI_TARGET_BATCH_SIZE=500
ZERO_NUCLEI_TARGET_BATCH_TIMEOUT="20m"
```

Per-run override:

```bash
docker compose run --rm zero analyze nuclei \
  --target-batch-size 500 \
  --target-batch-timeout 20m
```

Batch stats are stored in `scan_runs.stats` as `batches`, `completed_batches`, `target_batch_size`, and `target_batch_timeout`.

## WAF Diagnostics

Zero can optionally run a small pre/post probe around Nuclei to classify active validation as potentially blocked. This is disabled by default because it is operational context, not vulnerability evidence. It does not change Nuclei rate, concurrency, templates, or target coverage.

```env
ZERO_NUCLEI_WAF_DETECT=false
ZERO_NUCLEI_WAF_SAMPLE_SIZE=8
ZERO_NUCLEI_WAF_PROBE_TIMEOUT=5
```

Set `ZERO_NUCLEI_WAF_DETECT=true` for investigative campaigns where blocked validation is suspected. The diagnostic is stored in `scan_runs.stats.waf_diagnostic` when enabled and Nuclei returns no results or fails. High-confidence cases also emit an operational alert.

Common reasons:

- `post_scan_blocking_increased`: the sampled URLs became more blocked after Nuclei.
- `post_scan_waf_indicators_increased`: WAF-like headers/body indicators increased after Nuclei.
- `nuclei_timeout_with_blocked_probe`: Nuclei timed out and the probe observed blocked responses.
- `baseline_waf_like_responses`: the target already looked WAF-protected before validation, so lack of Nuclei confirmation should be treated as inconclusive.

## Stored Evidence

Each result stores:

- program id;
- service id when matched to a known HTTP service;
- scan run id;
- template id;
- matched URL;
- severity;
- CVEs and tags;
- evidence hash;
- raw JSON output.

Stable evidence hashes prevent duplicate findings across reruns.
