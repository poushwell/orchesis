# Orchesis — Agent Runtime Governance Layer

![Tests](https://github.com/YOUR_USERNAME/orchesis/actions/workflows/ci.yml/badge.svg)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![Version](https://img.shields.io/badge/version-0.5.0-orange)

> Policy-based verification for AI agent tool calls.  
> Deterministic. Fail-closed. Framework-agnostic.

## Why Orchesis

AI agents can execute powerful tools, but most systems still lack runtime guardrails between planner and execution. Recent industry reports show that incident rates remain high in agent-enabled environments, with many organizations reporting policy and data-access violations. Orchesis enforces explicit policy at runtime between agent and tool call, so risky actions are blocked before execution.

## Quick Start

```bash
pip install orchesis
orchesis init
orchesis verify examples/request.json --policy examples/policy.yaml
```

## Docker

```bash
# Clone and start
git clone https://github.com/YOUR_USERNAME/orchesis.git
cd orchesis
cp .env.example .env
docker compose up -d

# API available at http://localhost:8080
# MCP proxy at http://localhost:9000
```

## 30-Second Demo

Real behavior from the included demo flows:

- `cursor` (`operator`): full access to assigned tools inside policy limits
- `untrusted_bot` (`intern`): read-only behavior, write/delete attempts denied
- `blocked_agent` (`blocked`): all tool calls denied at identity check
- `rate_limit` rule: first 100 allowed, then hard block with explicit reason

## Architecture

```text
Agent -> Orchesis evaluate() -> ALLOW -> Tool executes
                           \-> DENY  -> Agent blocked + reason logged

Control API <-> Policy Store <-> Enforcement Nodes
     |
     +-> Agent Registry (trust tiers)
```

## Core Features

### Policy Engine

- YAML-based declarative rules
- 7 rule types: `file_access`, `sql_restriction`, `budget_limit`, `rate_limit`, `regex_match`, `context_rules`, `composite`
- Deterministic evaluation order
- Fail-closed guarantees

### Agent Identity & Trust Tiers

- 5 trust levels: `BLOCKED` -> `INTERN` -> `ASSISTANT` -> `OPERATOR` -> `PRINCIPAL`
- Capability-based tool access
- Per-agent rate limits and budgets

### Security

- 14 known attack patterns in regression corpus
- Synthetic fuzzer with 7 attack categories
- 7 mutation strategies for corpus evolution
- 9 formal runtime invariants
- Ed25519 signed audit trail
- Adversarial hardening for path traversal, SQL injection, cost manipulation, identity spoofing, and regex evasion

### Observability

- Structured telemetry (`DecisionEvent`)
- OpenTelemetry-compatible span export
- Prometheus metrics endpoint
- Webhook notifications with optional HMAC signing
- Event bus with pub/sub subscribers
- Debug mode with full evaluation trace

### Governance

- Policy versioning with rollback
- HTTP Control API with token auth
- Remote policy management endpoints
- Audit query engine with anomaly detection
- Forensic timeline per agent
- Deterministic replay engine
- Reliability report generation

### Integration

```python
from orchesis.client import OrchesisClient

client = OrchesisClient("http://localhost:8080", api_token="orch_sk_...")

if client.is_allowed("read_file", params={"path": "/data/report.csv"}):
    # proceed
    ...
```

## MCP Proxy

Ready-to-use MCP proxy examples:

- Cursor config: `examples/cursor_mcp_config.json`
- Claude Code config: `examples/claude_code_mcp_config.json`
- Production policy baseline: `examples/production_policy.yaml`

## CLI Reference

| Command | Description |
|---------|-------------|
| `orchesis init` | Initialize project |
| `orchesis verify` | Evaluate request against policy |
| `orchesis validate` | Check policy syntax |
| `orchesis audit` | Query decision logs |
| `orchesis agents` | List registered agents |
| `orchesis fuzz` | Run synthetic fuzzer |
| `orchesis scenarios` | Run adversarial scenarios |
| `orchesis mutate` | Run mutation engine |
| `orchesis invariants` | Verify runtime invariants |
| `orchesis replay` | Deterministic replay |
| `orchesis forensic` | Agent timeline investigation |
| `orchesis corpus` | Manage attack corpus |
| `orchesis serve` | Start Control API |
| `orchesis reliability-report` | Generate reliability report |
| `orchesis policy-history` | View policy versions |
| `orchesis rollback` | Rollback to previous policy |

## Testing

```bash
pytest                                    # 364 tests
orchesis fuzz --policy policy.yaml        # synthetic fuzzer
orchesis invariants --policy policy.yaml  # formal invariants
orchesis scenarios --policy policy.yaml   # adversarial scenarios
```

## Project Status

Orchesis is in active development. Current: v0.5.0 (Beta).

| Metric | Value |
|--------|-------|
| Tests | 364 |
| Attack corpus | 14 entries |
| Formal invariants | 9 |
| Rule types | 7 built-in + plugin system |
| Trust tiers | 5 (BLOCKED -> PRINCIPAL) |
| API endpoints | 14 |
| CLI commands | 18 |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [docs/SECURITY.md](docs/SECURITY.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

To report a vulnerability, see SECURITY.md.

## License

MIT
