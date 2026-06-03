# Custom Campaigns

Custom campaigns are for targeted vulnerability analysis across many authorized programs. The usual pattern is:

```text
select inventory -> focused fingerprint -> technology gate -> Nuclei validation -> report
```

Use a campaign when the question is specific, for example:

- Which targets expose a product or management console?
- Which targets match a newly relevant CVE template?
- Which targets have a known path, banner, HTML marker, cookie, or API response?
- Which targets should be validated with one or more custom Nuclei templates?

## File Loading

Queued campaigns are executed by the long-running `zero` worker. Custom files must be visible to that container, not only to the one-off CLI process that schedules the campaign.

By default, Docker Compose mounts:

```text
./custom-assets -> /home/zero/custom-assets
```

Place private custom Webanalyze JSON files and Nuclei YAML templates in `custom-assets/`, then reference them with container paths:

```text
/home/zero/custom-assets/product.webanalyze.json
/home/zero/custom-assets/product-cve.yaml
```

Files under `custom-assets/` are ignored by Git except the public README and `.gitkeep`.

## Choosing Parameters

Start from the least expensive inventory source that still answers the question.

Use `--reuse-active-services` when a full scan recently refreshed alive services. This skips `dnsx/httpx` and avoids repeated probing.

Use `--skip-enum` when you need fresh `httpx`/fingerprinting but do not need new subdomain discovery.

Use `--campaign-limit` for staged rollouts. A good flow is `25 -> 100 -> all programs`.

Use `--campaign-parallelism` for program-level concurrency. This is independent from `ZERO_TARGET_PARALLELISM`.

Use `--webanalyze-workers` for per-program Webanalyze URL concurrency. Total concurrent Webanalyze activity is roughly:

```text
campaign_parallelism * webanalyze_workers
```

Use `--webanalyze-batch-size` and `--webanalyze-batch-timeout` when a program has many services or many probe paths. Webanalyze batching is based on expanded URLs, and each service is expanded into:

```text
base URL + every --webanalyze-probe-path
```

For example, 250 services with 5 probe paths means up to 1500 Webanalyze URLs.

Zero defaults Webanalyze batches to 50 expanded URLs and 10 minutes per batch. `ZERO_TOOL_TIMEOUT` applies to external steps that do not have a dedicated batch timeout, such as subfinder, Nuclei, and template updates. Use a larger explicit `--webanalyze-batch-size` only after a staged run shows it is stable.

Use `--nuclei-tech-filter` to run Nuclei only on services where `httpx`, Webanalyze, title, server text, or stored technology observations match the target product.

Use `--nuclei-force` when you provide an explicit template/tag policy and do not want Nuclei selection derived from passive CVE matches.

Use `--nuclei-target-source` when the template should not run against alive HTTP URLs. The default is `http-services`. Use `subdomains` for DNS, takeover, or hostname-oriented templates.

Use `--nuclei-protocol` to control Nuclei protocol selection. The default is `http`. Use `dns` for DNS templates, or `auto` to omit `-pt` and let Nuclei infer protocols from the selected templates.

Use `--disable-passive-fingerprint-reports` when the campaign should emit only Nuclei-confirmed findings.

## Webanalyze Templates

Custom Webanalyze files follow Wappalyzer-style JSON. Keep them specific enough to avoid matching generic pages.

`--webanalyze-apps` is repeatable. Zero merges multiple custom Webanalyze JSON files for the run:

```bash
--webanalyze-apps /home/zero/custom-assets/product-a.webanalyze.json \
--webanalyze-apps /home/zero/custom-assets/product-b.webanalyze.json
```

Minimal example:

```json
{
  "technologies": {
    "Example Product": {
      "cats": ["19"],
      "html": [
        "<title>Example Product</title>",
        "Manage Example Product"
      ],
      "headers": {
        "Server": "ExampleProduct"
      },
      "cookies": {
        "ExampleSession": ""
      },
      "scripts": [
        "/example/static/"
      ],
      "website": "https://example.com/product"
    }
  },
  "categories": {
    "19": {
      "name": "Enterprise software"
    }
  }
}
```

Prefer multiple independent signals:

- title or body text that names the product;
- product-specific cookie names;
- product-specific static paths;
- product-specific response headers;
- version strings only when they are reliable.

Avoid generic terms such as `Apache`, `admin`, `portal`, or `login` unless paired with a stronger marker.

## Path Probes

Use `--webanalyze-probe-path` when the product rarely fingerprints at `/`.

Examples:

```bash
--webanalyze-probe-path /admin/
--webanalyze-probe-path /console/
--webanalyze-probe-path /api/version
--webanalyze-probe-path "/api/jolokia/search/org.example:type=Server,*"
```

Probe paths must be relative paths. Zero derives them from already alive HTTP services and ties any matches back to the original service record.

Path probes are partial fingerprints. They add focused observations but do not clear the normal technology inventory.

## Nuclei Templates

Use Nuclei for active validation, not broad discovery, unless that is the explicit campaign goal.

`--nuclei-template` is repeatable. When paired with `--nuclei-tech-filter`, Zero first selects only services whose latest fingerprint/title/server/banner/technology observations match the filter, then runs the configured Nuclei templates on that reduced target set.

When `--nuclei-template` or `--nuclei-template-id` is provided, Zero treats that as an explicit template allowlist and does not apply the default `cve` tag or `medium,high,critical` severity filters. Add `--nuclei-tags` or `--nuclei-severity` only when you intentionally want to further restrict the supplied templates.

Nuclei templates do not need to be CVE templates. Exposure, misconfiguration, takeover, DNS, SSL, and product-specific safe validation templates are supported. Choose the matching target source:

- `http-services`: alive HTTP URLs from `zero_http_services`; supports technology filtering.
- `subdomains`: scoped active FQDNs from `zero_subdomains`; intended for DNS/hostname templates and does not support technology filtering.

Minimal HTTP template shape:

```yaml
id: example-product-exposure

info:
  name: Example Product Exposure Check
  author: zero
  severity: medium
  tags: exposure,example

http:
  - method: GET
    path:
      - "{{BaseURL}}/api/version"

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "Example Product"
```

For CVE validation, include CVE metadata when appropriate:

```yaml
info:
  classification:
    cve-id: CVE-YYYY-NNNN
  severity: high
  tags: cve,cveYYYY,example
```

Keep templates safe and bounded:

- prefer `GET`/read-only probes when possible;
- avoid state-changing requests unless the campaign explicitly requires them;
- make matchers specific enough to avoid generic 200 responses;
- set `--nuclei-rate-limit`, `--nuclei-concurrency`, `--nuclei-bulk-size`, `--nuclei-timeout`, and `--nuclei-retries` explicitly for broad campaigns.

Minimal DNS template shape:

```yaml
id: example-dangling-cname

info:
  name: Example Dangling DNS Check
  author: zero
  severity: medium
  tags: dns,takeover,exposure

dns:
  - name: "{{FQDN}}"
    type: CNAME

    matchers:
      - type: word
        words:
          - "example-decommissioned-provider.net"
```

## Scenario Examples

### Focused CVE Sweep Against Fresh Inventory

Use this after a recent full run:

```bash
docker compose run --rm zero run schedule \
  --all-programs \
  --campaign-parallelism 8 \
  --name "example-product-cve-sweep" \
  --skip-sync \
  --reuse-active-services \
  --webanalyze-apps /home/zero/custom-assets/example-product.webanalyze.json \
  --webanalyze-probe-path /admin/ \
  --webanalyze-probe-path /api/version \
  --webanalyze-workers 4 \
  --webanalyze-batch-size 50 \
  --webanalyze-batch-timeout 10m \
  --nuclei-template /home/zero/custom-assets/example-product-cve.yaml \
  --nuclei-template /home/zero/custom-assets/example-product-exposure.yaml \
  --nuclei-tech-filter "Example Product|ExampleProduct" \
  --nuclei-force \
  --nuclei-rate-limit 30 \
  --nuclei-concurrency 8 \
  --nuclei-bulk-size 5 \
  --nuclei-timeout 10 \
  --nuclei-retries 1
```

### Discovery Plus Fingerprint

Use this when the alive inventory may be stale:

```bash
docker compose run --rm zero run schedule \
  --all-programs \
  --campaign-parallelism 4 \
  --campaign-limit 100 \
  --name "example-product-discovery-stage" \
  --skip-sync \
  --httpx-timeout 4 \
  --httpx-threads 20 \
  --httpx-batch-size 50 \
  --httpx-batch-timeout 5m \
  --webanalyze-apps /home/zero/custom-assets/example-product.webanalyze.json \
  --webanalyze-probe-path /console/ \
  --webanalyze-workers 3 \
  --webanalyze-batch-size 50 \
  --webanalyze-batch-timeout 10m \
  --nuclei-template /home/zero/custom-assets/example-product-check.yaml \
  --nuclei-tech-filter "Example Product" \
  --nuclei-rate-limit 20 \
  --nuclei-concurrency 5
```

### Fingerprint-Only Triage

Use this when you only want potential leads and do not have a validation template yet:

```bash
docker compose run --rm zero run schedule \
  --all-programs \
  --campaign-parallelism 8 \
  --name "example-product-fingerprint-only" \
  --skip-sync \
  --reuse-active-services \
  --webanalyze-apps /home/zero/custom-assets/example-product.webanalyze.json \
  --webanalyze-probe-path /admin/ \
  --skip-cves \
  --skip-nuclei
```

### DNS or Dangling-Record Campaign

Use this for templates that should run against scoped hostnames instead of alive HTTP URLs:

```bash
docker compose run --rm zero run schedule \
  --all-programs \
  --campaign-parallelism 8 \
  --campaign-limit 100 \
  --name "dangling-dns-stage" \
  --skip-sync \
  --skip-enum \
  --skip-probe \
  --skip-enrich \
  --skip-cves \
  --nuclei-force \
  --nuclei-target-source subdomains \
  --nuclei-protocol dns \
  --nuclei-template /home/zero/custom-assets/dangling-dns.yaml \
  --nuclei-rate-limit 50 \
  --nuclei-concurrency 10 \
  --nuclei-timeout 8 \
  --nuclei-retries 1
```

If a template mixes protocols or should select protocol internally, use:

```bash
--nuclei-protocol auto
```

Because this uses custom fingerprinting, Zero can emit potential/unconfirmed fingerprint reports. Add `--disable-passive-fingerprint-reports` if you only want database observations.

### Nuclei-Only Validation

Use this when the template itself is safe, specific, and suitable for all active services:

```bash
docker compose run --rm zero run schedule \
  --all-programs \
  --campaign-parallelism 4 \
  --name "example-nuclei-only" \
  --skip-sync \
  --reuse-active-services \
  --skip-enrich \
  --skip-cves \
  --nuclei-template /home/zero/custom-assets/example-safe-check.yaml \
  --nuclei-force \
  --nuclei-rate-limit 20 \
  --nuclei-concurrency 5
```

Only use this for narrow, low-noise templates. For product-specific checks, prefer fingerprint gating first.
