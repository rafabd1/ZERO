# Tooling Choices

## Scope

- `bbscope`: reliable platform API polling and normalization for bug bounty scopes.

## Enumeration

- `subfinder`: passive subdomain discovery. It is low-noise and appropriate for daily runs.
- `dnsx`: recommended next step to validate DNS resolution and reduce stale passive results.

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

## CVE Intelligence

Recommended sources:

- CISA KEV for known exploited vulnerabilities.
- NVD for CVE metadata and CVSS.
- OSV for package ecosystems where package identity/version is available.
- Nuclei template metadata for practical HTTP detection hints.

Matching rule of thumb:

- Version-confirmed technology plus affected range: high confidence.
- Product-only fingerprint with no version: observation or low confidence.
- Nuclei positive result: high confidence only if the request/response evidence is meaningful and target behavior is in scope.

## Role Split

`httpx` is intel collection. It answers "what is alive and what does it look like?".

`nuclei` is validation. It answers "does a known probe produce vulnerability-specific evidence?".

The passive CVE matcher should use `httpx` observations to prioritize likely vulnerable products. Nuclei should then be used to raise confidence where a relevant template exists.
