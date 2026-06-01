# Local Lab

The lab is a small controlled target for proving the passive-intel-to-validation flow without touching bug bounty scope.

Start the lab service and seed it into Zero:

```bash
docker compose -f docker-compose.lab.yml up -d
docker compose --profile tools run --rm migrate
docker compose run --rm zero dev seed-lab --url http://lab-apache --tech "Apache HTTP Server" --version 2.4.49
```

Then run the focused flow:

```bash
docker compose run --rm zero analyze cves --limit 1
docker compose run --rm zero analyze nuclei --from-cves --limit 1 --cve-limit 5
```

The lab seed inserts a program, an in-scope URL asset, an HTTP service, and a versioned technology observation. Passive CVE matching should create `zero_technology_vulnerability_matches`; active findings still depend on the installed Nuclei templates and whether a matching template is probeable for the lab service.
