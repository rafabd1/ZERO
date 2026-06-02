# Tools

Zero wraps proven external tools and stores their output in a program-scoped database model.

## Scope

- `bbscope`: platform scope polling and normalization.

## Enumeration

- `subfinder`: passive subdomain discovery for authorized wildcard roots.
- `dnsx`: DNS resolution filtering before HTTP probing.

Zero does not collapse scoped subdomains to broader provider roots. Exact scoped hosts are probed exactly and are not used as enumeration roots.

## Probing And Fingerprinting

- `httpx`: alive checks, status code, title, webserver, TLS, favicon, and lightweight technology data.
- `webanalyze`: Wappalyzer-style technology detection, including versions when detectable.

Custom Webanalyze technology files can be passed per manual run or campaign with repeatable `--webanalyze-apps`. For queued campaigns, put private files in `custom-assets/` and reference them through `/home/zero/custom-assets/...` so the worker container can read them.

## Validation

- `nuclei`: active validation for selected templates, CVE IDs, tags, or custom template paths.

For broad campaigns, prefer focused templates over broad generic scanning. `dnsx`, `httpx`, and Webanalyze have dedicated batch timeouts; `ZERO_TOOL_TIMEOUT` bounds the remaining external steps such as subfinder, Nuclei, and template updates.

Custom Nuclei templates can be passed with repeatable `--nuclei-template` and should also live in `custom-assets/` for local Docker Compose runs. See [Custom Campaigns](CUSTOM_CAMPAIGNS.md) for safe template structure and campaign recipes.

## Optional Provider Keys

Subfinder performs better with provider keys. Docker runs can generate the private provider config from `.env`:

```env
ZERO_SUBFINDER_SHODAN_API_KEY=""
ZERO_SUBFINDER_BEVIGIL_API_KEY=""
ZERO_SUBFINDER_VIRUSTOTAL_API_KEY=""
ZERO_SUBFINDER_SECURITYTRAILS_API_KEY=""
```

Do not commit real provider configs or API keys.
