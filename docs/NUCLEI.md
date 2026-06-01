# Nuclei Validation

Nuclei is part of Zero as a confidence validator, not as the primary source of target intelligence.

## Default Policy

Run only against alive URLs already discovered by `httpx`.

Default filters:

- Template IDs from passive CVE matches when available
- Severities: `medium,high,critical`
- Exclude low/info by default
- Keep rate limits moderate
- Store JSONL output structurally in `zero_nuclei_results`

Recommended starting command shape:

```bash
nuclei -l urls.txt \
  -j \
  -duc \
  -ni \
  -pt http \
  -id CVE-2025-20362,CVE-2021-41773 \
  -severity medium,high,critical \
  -rate-limit 80 \
  -c 20 \
  -bs 5 \
  -retries 1 \
  -timeout 8 \
  -or \
  -ot
```

These are starting values, not a promise that every target tolerates them. Per-program overrides should be supported later.

## Why This Matters

Nuclei depends on templates. It is strong when a relevant template exists and weak for CVEs without templates or with fragile product/version detection. Zero should therefore:

1. Use `httpx` for alive checks and fingerprints.
2. Use Webanalyze/Wappalyzer definitions to improve technology and version coverage.
3. Use passive CVE/KEV/advisory matching for prioritization.
4. Use Nuclei to validate known probeable CVEs.
5. Report only new, deduplicated hits with enough evidence.

Passive matching is not just a free-text lookup. NVD CPE evidence and version ranges are preferred when present; keyword matching is kept as lower-confidence fallback. Only active Nuclei hits become candidate findings.

## Stored Fields

Each Nuclei result is linked to:

- `program_id`
- `http_service_id` when matched to a known service
- `scan_run_id`
- `template_id`
- `matched_at`
- `severity`
- `cves`
- `tags`
- `evidence_hash`
- raw JSON output

The unique key is `(program_id, template_id, matched_at, evidence_hash)` so reruns do not create duplicate rows.

For targeted validation after passive matching:

```bash
zero analyze cves --limit 25
zero analyze nuclei --from-cves --limit 20 --cve-limit 50
zero analyze nuclei --limit 5 --template-id CVE-2025-20362
```
