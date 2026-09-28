# CLAUDE.md

Guidance for Claude Code when working in this repository.

## What this is

`zap-clean-report` is a public npm package that turns an OWASP ZAP JSON export into a single
HTML report that non-security readers (managers, stakeholders) can follow. Zero runtime
dependencies, Node 16+.

## Layout

| Path | Role |
|---|---|
| `src/report.js` | The whole generator: parses ZAP JSON, builds the HTML, CSS and inline script. Exports `generateReport(raw, { title, brand })` |
| `bin/cli.js` | CLI: argument parsing, logo file to data URI, accent validation, output file naming |
| `examples/` | `zap-api-sample.json` and `zap-web-sample.json`, the fixtures every change is checked against |
| `.github/workflows/ci.yml` | Generates a report from the API sample on Node 18, 20 and 22 |
| `.github/workflows/publish.yml` | Publishes to npm on a `v*` tag (or manual dispatch) |

## Commands

```bash
npm test                                             # generates test-report.html from the API sample
node bin/cli.js examples/zap-web-sample.json -o out.html
```

There is no unit suite. After a change, generate a report from both samples and open them in a
browser, including a phone-width view (the layout must work at 390px with no sideways scroll)
and print preview (all findings expand for print).

## Design

The visual design mirrors the clean report in the HydraX `exchange-generic-zap-security-tester`
repo (`common/scripts/generate-report.ps1`), ported without its company branding and without
the pipeline-only sections (pre-scan checks, fix ownership, Jira export, coverage matrix).

- Keep the package brand-neutral. Branding comes only from `brand` options (`--brand`,
  `--logo`, `--accent`, `--footer`); never hardcode a company name, logo or colour scheme.
- The accent colour is interpolated into a `<style>` block, so it must stay restricted to a
  hex value (checked in both the CLI and `safeAccent` in `report.js`).
- The accent drives derived shades through `color-mix()`; severity colours are fixed.
- Web fonts load from Google Fonts with system fallbacks; everything else stays inline so the
  report is still one file.

## Releasing

1. Bump `version` in `package.json` (semver: new options or a redesign is a minor bump).
2. Merge to `main`, then push a `v<version>` tag; `publish.yml` runs `npm publish --provenance`.

## Writing rules

- No em dashes anywhere: code, comments, report copy, README, commit messages. ZAP's own text
  is passed through `removeEmDash` before it reaches the report.
- Comments only for a non-obvious why, one line where possible.
- Report copy is for a non-technical reader: if they would not understand a string, rewrite it.
- Commits and PRs: no Claude co-author trailer and no "Generated with Claude Code" line.
