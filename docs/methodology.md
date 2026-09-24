# Methodology: Website Technology Detector

## Detection

Each signature in `rules/signatures.yaml` has rules that match one part of the snapshot:

| `where` | Subject |
|---|---|
| `header:<name>` | response header value |
| `meta:<name>` | `<meta name/property>` content (e.g. `generator`) |
| `cookie` | cookie names (values are never stored) |
| `script` | URLs of scripts, stylesheets, links, iframes and images |
| `html` | the page markup |
| `url` | the final URL |

A named `version` capture group supplies the version. The first rule that yields a version wins.

## Findings

| Rule | Severity | Confidence |
|---|---|---|
| `web-eol-*` end-of-life component | runtime high · framework medium · library low | high |
| vulnerable front-end library (OSV) | medium; high with ≥ 3 advisories | medium: versions come from URLs |
| `stale-copyright` (≥ 3 years old) | low | low: it is only an indicator |

## Limitations

Only the front page is analysed. Server-side technologies that leave no trace in headers, cookies or markup cannot be seen.
