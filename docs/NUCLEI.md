# Nuclei

Zero uses Nuclei as an active validation layer, not as the only source of target intelligence.

## Policy

For broad runs, start with:

- alive URLs only;
- CVE-tagged or explicit templates;
- `medium,high,critical` severities;
- moderate rate and concurrency;
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
