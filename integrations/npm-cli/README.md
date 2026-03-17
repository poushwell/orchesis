# orchesis-scan

MCP security scanner CLI.

## Install
npx orchesis-scan

## Usage
npx orchesis-scan                    # auto-detect config
npx orchesis-scan --config mcp.json  # specific file
npx orchesis-scan --format json      # JSON output
npx orchesis-scan --fail-on critical # only fail on critical
npx orchesis-scan --severity high    # show only high/critical findings
npx orchesis-scan --fix              # print remediation tips for each finding
npx orchesis-scan --output report.json  # save filtered report to JSON

## New flags

- `--severity <low|medium|high|critical>`: filter findings by minimum severity
- `--fix`: print `🔧 Remediation:` lines under each finding
- `--output <path>`: save scanner output report as JSON

Examples:

```bash
npx orchesis-scan --severity critical --fail-on critical
npx orchesis-scan --severity high --fix
npx orchesis-scan --severity medium --output ./report.json
```
