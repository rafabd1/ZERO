# Tooling Choices

## Scope

- `bbscope`: reliable platform API polling and normalization for bug bounty scopes.

## Enumeration

- `subfinder`: passive subdomain discovery. It is low-noise and appropriate for daily runs.
- `dnsx`: recommended next step to validate DNS resolution and reduce stale passive results.

Zero feeds `subfinder` only with active in-scope wildcard roots. It does not pass exact URL hosts or collapse scoped subdomains to a broader eTLD+1.

Recommended Subfinder provider sources for the initial private setup:

```text
shodan,bevigil,virustotal,securitytrails
```

Recommended conservative provider rate limits:

```text
shodan=1/s,virustotal=4/m,securitytrails=1/s,bevigil=1/s
```

## Probing and Fingerprinting

- `httpx`: first-pass alive check and fingerprint source. Use JSON output with tech detection, title, status code, webserver, TLS, and favicon hash.
- `nuclei`: final active validation layer for CVE candidates and known exposures. Zero should not use it as a noisy general scanner by default.

`httpx` receives sanitized probe targets after scope filtering: discovered wildcard subdomains plus exact URL/domain hosts from the scope table.

Recommended default:

```bash
nuclei -l urls.txt \
  -jsonl \
  -tags cve \
  -severity medium,high,critical \
  -rate-limit 80 \
  -c 20 \
  -retries 1 \
  -timeout 8
```

The exact flags can evolve with testing, but the principle should remain: CVE-tagged templates, severity above low, moderate concurrency, deduped JSONL output, and per-program attribution.

## CVE Validation

Zero does not emit passive CVE findings from `httpx` fingerprints. Fingerprints are stored as target intelligence for operator context and later Proteus/Codex triage.

Reportable CVE candidates come from Nuclei results. Confidence is based on Nuclei evidence quality and severity, not on a passive keyword match against CVE databases.

## Role Split

`httpx` is intel collection. It answers "what is alive and what does it look like?".

`nuclei` is validation. It answers "does a known probe produce vulnerability-specific evidence?".

Reports are generated from new Nuclei-backed findings only. The `httpx` observations remain useful because they explain what the target looked like when the validation happened.
