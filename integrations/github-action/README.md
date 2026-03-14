# Orchesis MCP Security Scan Action

Scan your MCP configuration for security vulnerabilities in CI.

## Usage

```yaml
- uses: poushwell/orchesis@main
  with:
    config-path: '.cursor/mcp.json'
    fail-on: 'high'
```

## Inputs
| Input | Default | Description |
|-------|---------|-------------|
| config-path | auto | Path to MCP config |
| min-severity | low | Minimum severity to show |
| fail-on | high | Fail if findings at this level |
| output-format | text | text or sarif |

## Outputs
- `risk-score` — 0-100
- `findings-count` — total findings
- `critical-count` — critical findings only
