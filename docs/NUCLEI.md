# Nuclei

Zero uses Nuclei as an active validation layer, not as the only source of target intelligence.

## Policy

For broad runs, start with:

- alive URLs only;
- CVE-tagged or explicit templates;
- `medium,high,critical` severities;
- configured request headers that look like normal browser traffic;
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
  --template-path ./templates/custom.yaml \
  --severity high,critical \
  --rate-limit 40 \
  --concurrency 10
```

Campaigns can pass the same Nuclei options through `zero run schedule`.

Technology-gated validation:

```bash
docker compose run --rm zero analyze nuclei \
  --tech-filter "product-name" \
  --tech-max-age 2h \
  --template-path ./templates/custom.yaml \
  --severity high,critical
```

`--tech-filter` matches active technology observations, `httpx` technology names, titles, and server banners. `--tech-max-age` makes the gate freshness-aware, which is useful for campaigns where `httpx` and Webanalyze run immediately before Nuclei. Custom Webanalyze app files are partial by design and do not deactivate the normal full fingerprint inventory.

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

## WAF Diagnostics

Zero can run a small pre/post probe around Nuclei to classify active validation as potentially blocked. This does not change Nuclei rate, concurrency, templates, or target coverage.

```env
ZERO_NUCLEI_WAF_DETECT=true
ZERO_NUCLEI_WAF_SAMPLE_SIZE=8
ZERO_NUCLEI_WAF_PROBE_TIMEOUT=5
```

The diagnostic is stored in `scan_runs.stats.waf_diagnostic` when Nuclei returns no results or fails. High-confidence cases also emit an operational alert.

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
