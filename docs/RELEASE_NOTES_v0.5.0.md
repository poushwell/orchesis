# Orchesis v0.5.0 Release Notes

## Highlights

- **MCP Scanner doubled**: 49 → 113 checks across 9 categories
- **OWASP MCP Top 10**: 9/10 categories now covered
- **Zero dependencies**: Core is pure stdlib, everything else optional
- **4,912+ tests passing**: Up from 4,377 at start of sprint

## Security

- SSRF protection on X-Orchesis-Upstream
- Event bus secret redaction
- Dashboard XSS escape
- Content-Length DoS cap (413 on oversized requests)
- Auto-generated resume tokens
- Fail-closed on invalid policy files

## New Features

- CVE database for known vulnerable MCP packages
- IDE config scanning (Cursor, Claude Code, Paperclip, OpenClaw)
- A2A protocol security scanning
- `orchesis dashboard` CLI command
- `orchesis[all]` install extra
- `orchesis verify` expanded to 15 checks
- OpenClaw + Paperclip presets with 6 detection patterns
- Evidence Ledger buffered writes (100 events, 5s flush)

## Performance

- Memory caps: CostTracker 10K, Behavioral 1K agents, Loop 10K sessions
- Connection pool overflow protection
- Exponential backoff + jitter on upstream retries

## Breaking Changes

- Default proxy port: 8100 → 8080
- Default client port: 8090 → 8080
- Python requirement: ≥3.10 (was ≥3.12)
- Invalid policy files now raise ConfigError (was silent {})

## Install

```bash
pip install orchesis           # core (zero deps)
pip install orchesis[server]   # with FastAPI/uvicorn
pip install orchesis[all]      # everything
```
