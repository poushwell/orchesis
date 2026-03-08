# Orchesis Security Scan - GitHub Action

Automatically scan MCP server configs, AI agent skills, and policy files for security vulnerabilities on every PR.

## Quick Start

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: poushwell/orchesis/github-action@main
        with:
          fail-on: high
```

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `scan-path` | `.` | Path to scan (file or directory) |
| `scan-type` | `auto` | `mcp`, `skill`, `policy`, or `auto` |
| `fail-on` | `high` | Min severity to fail: `critical`, `high`, `medium`, `low`, `none` |
| `config-path` |  | Path to specific MCP config file |
| `format` | `text` | Output: `text`, `json`, `sarif` |
| `orchesis-version` | `latest` | Orchesis version to install |

## Outputs

| Output | Description |
|--------|-------------|
| `score` | Security score 0-100 |
| `findings-count` | Total findings |
| `critical-count` | Critical findings |
| `high-count` | High findings |
| `exit-code` | `0=pass`, `1=fail`, `2=error` |
| `report-path` | Path to generated report file |

## Examples

### Block PRs with critical findings

```yaml
- uses: poushwell/orchesis/github-action@main
  with:
    fail-on: critical
```

### Scan specific MCP config

```yaml
- uses: poushwell/orchesis/github-action@main
  with:
    config-path: .cursor/mcp.json
    fail-on: high
```

### Weekly security audit

```yaml
name: Weekly Security Audit
on:
  schedule:
    - cron: "0 9 * * 1" # Every Monday at 9am

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: poushwell/orchesis/github-action@main
        with:
          fail-on: none
          format: json
```

### Use outputs in workflow

```yaml
- uses: poushwell/orchesis/github-action@main
  id: scan
  with:
    fail-on: none

- name: Comment on PR
  if: github.event_name == 'pull_request'
  uses: actions/github-script@v7
  with:
    script: |
      github.rest.issues.createComment({
        owner: context.repo.owner,
        repo: context.repo.repo,
        issue_number: context.issue.number,
        body: `Security Score: ${{ steps.scan.outputs.score }}/100\nFindings: ${{ steps.scan.outputs.findings-count }}`
      })
```

## What it scans

- **MCP Configs:** hardcoded secrets, shell injection, unencrypted transport, overprivileged access, missing version pinning, known vulnerable packages
- **Skills:** credential exfiltration, command injection, prompt injection patterns
- **Policies:** missing required sections, weak defaults, overpermissive rules

## Privacy

All analysis runs inside the GitHub Actions runner. No data is sent to external servers.

## Built by

[Orchesis](https://github.com/poushwell/orchesis) - Open-source AI agent control plane.
