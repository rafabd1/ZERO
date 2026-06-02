# Custom Assets

Place private campaign assets here when running Zero locally:

- custom Webanalyze/Wappalyzer technology JSON files
- custom Nuclei YAML templates
- small campaign-specific helper files

This directory is mounted read-only into the `zero` and `api` containers at:

```text
/home/zero/custom-assets
```

Do not commit private target logic or sensitive templates. The repository tracks this README only; other files in this directory are ignored by Git.
