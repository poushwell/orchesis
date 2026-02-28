# Orchesis — Agent Runtime Governance Layer

[![CI](https://img.shields.io/badge/CI-pending-lightgrey)](#)
[![PyPI](https://img.shields.io/badge/PyPI-pending-lightgrey)](#)
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)](#license)

Policy-based verification proxy for AI agent tool calls.

## What it does

Orchesis sits between AI agents and their tools.  
Every tool call passes through a policy engine that decides ALLOW or DENY.  
All decisions are logged with cryptographic signatures for audit.

## Quick Demo

```bash
pip install orchesis
orchesis init
orchesis verify request.json --policy policy.yaml
orchesis audit
```

Agent demo (condensed real output):
- `analyze_sales_data`: 3 ALLOW
- `dangerous_cleanup`: 2 DENY (`file_access`, `sql_restriction`)
- `budget_burn`: 2 DENY (`budget_limit`)
- `rate_limited_spam`: 100 ALLOW then 100 DENY (`rate_limit`)
- `untrusted_agent_attempt`: 2 DENY (`context_rules`)

## Architecture

```text
Agent -> Orchesis evaluate() -> ALLOW -> Tool executes
                           -> DENY  -> Agent receives block + reason
```

## Policy Rules

- `file_access`: path prefix allow/deny
- `sql_restriction`: blocked SQL operations
- `budget_limit`: per-call and daily cost caps
- `rate_limit`: sliding window per tool
- `regex_match`: pattern-based blocking
- `context_rules`: per-agent permissions
- `composite`: AND/OR rule combinations

## MCP Proxy Integration

Use Orchesis as MCP interceptor with real clients:
- Cursor config: `examples/cursor_mcp_config.json`
- Claude Code config: `examples/claude_code_mcp_config.json`
- Production policy template: `examples/production_policy.yaml`

## Agent Harness

```bash
orchesis-agent run analyze_sales_data --policy policy.yaml --tasks agent_tasks.yaml
```

## Security

- Ed25519 signed audit trail
- 30 adversarial tests (path traversal, SQL bypass, cost manipulation, and more)
- Formal threat model: `docs/THREAT_MODEL.md`

## Docker

```bash
docker compose up -d
```

## CI/CD

GitHub Actions workflows for lint, tests, and publish.

## Install

```bash
pip install orchesis
```

## License

MIT
