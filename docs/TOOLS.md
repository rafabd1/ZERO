# Tools

Zero wraps proven external tools and stores their output in a program-scoped database model. Each tool can be used as part of the normal pipeline or selected independently in a custom campaign.

## Scope

- `bbscope`: platform scope polling and normalization for HackerOne, Bugcrowd, and Intigriti.

## Enumeration

- `subfinder`: passive subdomain discovery for authorized wildcard roots.
- `dnsx`: DNS resolution filtering before HTTP probing.

Zero does not collapse scoped subdomains to broader provider roots. Exact scoped hosts are probed exactly and are not used as enumeration roots.

## Probing And Fingerprinting

- `httpx`: alive checks, status code, title, webserver, TLS, favicon, and lightweight technology data.
- `webanalyze`: Wappalyzer-style technology detection, including versions when detectable.

Custom Webanalyze technology files can be passed per manual run or campaign with repeatable `--webanalyze-apps`. For queued campaigns, put private files in `custom-assets/` and reference them through `/home/zero/custom-assets/...` so the worker container can read them.

Use `--webanalyze-probe-path` to fingerprint additional paths on each alive service. This lets a campaign identify products that do not reveal themselves on `/` but do expose stable markers on paths such as `/admin/`, `/console/`, `/demo/`, or `/api/version`.

## Validation

- `nuclei`: active validation for selected templates, CVE IDs, tags, or custom template paths.

Nuclei is not limited to CVE validation. Zero can run exposure, misconfiguration, DNS, dangling-record, SSL/TCP, and product-specific custom templates, provided the target source and protocol are configured correctly.

For broad campaigns, prefer focused templates over broad generic scanning. `dnsx`, `httpx`, Webanalyze, and Nuclei target execution have dedicated batch controls. `ZERO_TOOL_TIMEOUT` bounds external steps that do not have a dedicated batch timeout.

Custom Nuclei templates can be passed with repeatable `--nuclei-template` and should also live in `custom-assets/` for local Docker Compose runs. See [Custom Campaigns](CUSTOM_CAMPAIGNS.md) for safe template structure and campaign recipes.

Use:

- `--nuclei-target-source http-services` for alive HTTP URLs;
- `--nuclei-target-source subdomains` for hostname/DNS templates;
- `--nuclei-protocol auto` when Nuclei should infer protocols from mixed templates;
- `--nuclei-tech-filter` when a focused HTTP template should run only on assets whose stored fingerprint/title/banner matches the intended technology.

## Optional Provider Keys

Subfinder performs better with provider keys. Docker runs can generate the private provider config from `.env`:

```env
ZERO_SUBFINDER_SHODAN_API_KEY=""
ZERO_SUBFINDER_BEVIGIL_API_KEY=""
ZERO_SUBFINDER_VIRUSTOTAL_API_KEY=""
ZERO_SUBFINDER_SECURITYTRAILS_API_KEY=""
```

Do not commit real provider configs or API keys.
