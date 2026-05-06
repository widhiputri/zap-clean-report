# zap-clean-report

Generate clean, non-technical HTML security reports from OWASP ZAP JSON output.

Built for teams who need to share scan results with developers, managers, and stakeholders who are not security specialists. Findings are written in plain English, grouped by severity, and the output is a single self-contained HTML file with no external dependencies.

## Features

- Single self-contained HTML file (no CDN, no internet required to open)
- Plain English descriptions for common vulnerability types
- Findings grouped and filterable by risk level (High, Medium, Low, Informational)
- OWASP Top 10 category badges per finding
- CWE reference badges with clickable links
- Systemic finding detection
- Collapsible finding details with affected URL list
- Print-ready layout with all sections expanded automatically
- Auto-generated filename based on target hostname and UTC timestamp
- Zero runtime dependencies

## Install

```bash
npm install -g zap-clean-report
```

Or run without installing:

```bash
npx zap-clean-report zap-output.json
```

## Usage

```bash
zap-clean-report <input.json> [options]
```

### Options

| Option | Description |
|---|---|
| `--output, -o <file>` | Output file path (overrides auto-generated name) |
| `--title <text>` | Report title (default: Security Scan Report) |
| `--help, -h` | Show help |

### Examples

```bash
# Basic usage - auto-generates filename
zap-clean-report zap-output.json

# Custom output path
zap-clean-report zap-output.json --output report.html

# Custom title (appears in the report header)
zap-clean-report zap-output.json --title "My App - Sprint 22"
```

### Auto-generated filename format

```
<hostname>-<UTC timestamp>-security-report.html
```

Example: `app.example.com-20260504164752-security-report.html`

## Programmatic usage

```js
const { generateReport } = require('zap-clean-report');
const fs = require('fs');

const raw = JSON.parse(fs.readFileSync('zap-output.json', 'utf8'));
const html = generateReport(raw, { title: 'My App - Security Scan' });
fs.writeFileSync('report.html', html);
```

## Input format

Accepts the standard JSON export from OWASP ZAP. To generate it:

1. Run your ZAP scan
2. Go to **Report > Generate Report** and select JSON format, or use the ZAP CLI with `--format json`

Sample JSON files for testing are available in the [`examples/`](examples/) folder.

## Requirements

Node.js 16 or later.

## License

MIT
