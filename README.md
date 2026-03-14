# Orchesis

**AI Agent Control Plane — transparent HTTP proxy for security, cost optimization, and reliability.**

[![Tests](https://github.com/poushwell/orchesis/actions/workflows/test.yml/badge.svg)](https://github.com/poushwell/orchesis/actions/workflows/test.yml)
[![Python](https://img.shields.io/badge/python-3.12+-blue)]()
[![License](https://img.shields.io/badge/license-MIT-green)]()
[![Dependencies](https://img.shields.io/badge/dependencies-zero-orange)]()

One line between your AI agents and their LLM APIs. No code changes. No SDK. No vendor lock-in.

---

## What it does

Orchesis sits between AI agents (OpenClaw, CrewAI, LangChain, any HTTP client) and LLM providers (OpenAI, Anthropic, Google). Every request passes through a 17-phase pipeline:

**Security:** Prompt injection detection, credential leak prevention, tool abuse blocking, threat intelligence (25 signatures across 10 categories)

**Cost:** Context compression (80-90% token reduction), semantic caching, intelligent model routing (Thompson Sampling), budget enforcement

**Reliability:** Loop detection, auto-healing (6 recovery actions), circuit breakers, agent behavioral analysis (MAST compliance)

**Observability:** Real-time dashboard, Flow X-Ray request tracing, Agent Reliability Score, session recording + replay

## Quick Start

### Try the demo (no setup needed)

```bash
pip install orchesis
orchesis demo
# Open http://localhost:8080/dashboard
```

### Run with Docker

```bash
git clone https://github.com/poushwell/orchesis
cd orchesis
docker-compose up
# Configure your agent: set LLM base URL to http://localhost:8080
```

### Install from PyPI

```bash
pip install orchesis
orchesis proxy --config orchesis.yaml
```

### Minimal config (`orchesis.yaml`)

```yaml
proxy:
  host: "0.0.0.0"
  port: 8080
upstream:
  url: "https://api.openai.com"
security:
  enabled: true
budget:
  daily_limit_usd: 10.0
dashboard:
  enabled: true
```

One config change in your agent — set the base URL to `http://localhost:8080` — and everything routes through Orchesis. Zero code changes.

## Dashboard

[SCREENSHOT PLACEHOLDER - will add actual screenshot]

Three numbers at a glance: **Threats Blocked** | **Money Saved** | **Fleet Health**

Tabs: Security | Cost | Agents | Flow X-Ray | Compliance | Approvals

### Demo mode

```bash
orchesis demo --port 8080
```

Launches dashboard with realistic sample data. No API keys needed. Try it before you commit.

## Why not [alternative]?

| | Orchesis | Galileo Agent Control ($68M) | DashClaw | Helicone |
|---|---------|-----|----------|---------|
| Approach | Transparent proxy | Decorator (code changes) | SDK (code changes) | Logging proxy |
| Security | 17-phase adaptive detection | Basic guardrails | Policy rules | None |
| Cost optimization | Context compression + routing | None | Token tracking | Logging only |
| Dependencies | Zero (Python stdlib) | Multiple | Next.js + Postgres | Cloud service |
| Self-hosted | Yes | Partial | Yes | No (acquired) |
| Price | Free (MIT) | Enterprise pricing | Free (MIT) | Was free, now Mintlify |

## Architecture

Agent -> Orchesis Proxy -> LLM Provider  
|  
17-phase pipeline:  
parse -> experiment -> flow_xray -> cascade -> circuit_breaker ->  
loop_detection -> behavioral -> mast_request -> auto_healing ->  
budget -> policy -> threat_intel -> model_router -> secrets ->  
context -> upstream(+semantic_cache) -> post_upstream -> send  
|  
Dashboard (localhost:8080/dashboard)

## Key metrics

- **2,637** tests passing
- **17** pipeline phases
- **25** threat signatures across 10 categories
- **8/14** MAST failure modes covered
- **8/10** OWASP Agentic AI risks covered
- **6** auto-healing actions
- **0** external dependencies

## Security coverage

**OWASP Agentic AI Top 10:** ASI-01 through ASI-08 covered (80%)  
**MAST (UC Berkeley):** 11/14 failure modes detected (78.6%)  
**EU AI Act:** Audit trail + incident reporting ready  
**NIST AI RMF:** Govern + Measure covered

## OpenClaw preset

Optimized configuration for OpenClaw users:

```bash
orchesis proxy --config config/orchesis_openclaw.yaml
```

Includes: cron context detection, system prompt deduplication, tool call loop detection, MCP security scanning patterns.

## API

```
GET  /stats                          # Proxy statistics
GET  /api/dashboard/overview         # Dashboard metrics
GET  /api/v1/agents                  # Discovered agents
GET  /api/v1/agents/{id}             # Agent details
GET  /api/v1/agents/summary          # Fleet summary
GET  /api/v1/tools                   # Tool policies
GET  /api/v1/approvals               # Pending approvals
POST /api/v1/approvals/{id}/approve  # Approve action
POST /api/v1/approvals/{id}/deny     # Deny action
GET  /sessions                       # Recorded sessions
GET  /sessions/{id}                  # Session details
```

## Configuration

Full reference: [docs/configuration.md](docs/configuration.md)

Key sections:
- `proxy` — host, port, max_workers, connection pool
- `upstream` — LLM provider URL, API key passthrough
- `security` — threat detection, secrets filtering, MAST compliance
- `budget` — daily/monthly limits, per-model limits, alerts
- `cascade` — model routing rules, fallback chains
- `recording` — session capture, storage, retention
- `dashboard` — enable/disable, auth

## Contributing

PRs welcome. Please:
1. Fork the repo
2. Create a feature branch
3. Write tests (we have 2,637, keep the bar high)
4. Run `python -m pytest tests/ -x -q`
5. Open a PR

## License

MIT

---

Built by [Pavel](https://github.com/poushwell) | [orchesis.io](https://orchesis.io)

