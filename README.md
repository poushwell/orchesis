# 🛡️ Orchesis

**AI Agent Control Plane — Transparent HTTP proxy for security, cost, and reliability**

[![Tests](https://github.com/poushwell/orchesis/actions/workflows/ci.yml/badge.svg)](https://github.com/poushwell/orchesis/actions)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-1900%2B%20passing-brightgreen)]()

Change your AI agent's base URL. Get security scanning, cost optimization,
failure detection, and full observability. Zero code changes. Zero dependencies.

## The Problem

AI agents make autonomous API calls with no oversight. A single misconfigured agent can burn $3,600 overnight on heartbeat loops, leak secrets through tool calls, or spiral into infinite retry cycles. Existing solutions require SDK integration or code changes. Orchesis sits between your agent and the LLM API — transparent, non-invasive, instant.

## Quick Start

```bash
pip install orchesis
orchesis proxy --target https://api.openai.com
# Point your agent's base URL to http://localhost:8080
# Open http://localhost:8080/dashboard
```

Or with the demo (no API key needed):

```bash
git clone https://github.com/poushwell/orchesis
cd orchesis && pip install -e .
python demo/try_orchesis.py
```

## What It Does

| Security | Cost | Reliability | Observability |
|----------|------|-------------|---------------|
| 25 threat signatures | Semantic cache (118x speedup) | Circuit breaker | Dashboard (8 tabs) |
| Prompt injection blocking | Adaptive cascade routing | Loop detection | Flow X-Ray |
| PII/secret scanning | Budget enforcement | Heartbeat storm protection | Agent DNA profiling |
| Session risk scoring | Spend rate anomaly detection | Auto-recovery | OWASP/NIST compliance |

## Key Numbers

- **1900+ tests** — battle-tested with 4 rounds of fuzzing
- **17-phase pipeline** — parse to send, sub-millisecond overhead
- **25 threat signatures** — OWASP ASI Top 10 mapped
- **0 external dependencies** — stdlib Python only
- **8 stress-test scenarios** — 50 concurrent agents, 30-min memory stability, adversarial load

## Architecture

Orchesis processes every request through a 17-phase pipeline. Each phase is independent, configurable via `policy.yaml`, and adds `<1ms` overhead in the proxy path. Unlike SDK-based solutions, deployment is transparent: agents continue speaking standard OpenAI-compatible HTTP APIs.

```text
Agent -> Orchesis Proxy -> LLM API
         |- parse
         |- security (threat_intel, PII, secrets)
         |- cost (cache, cascade, budget)
         |- reliability (loops, circuit_breaker, flow_xray)
         '- observability (dashboard, OTel, alerts)
```

## Dashboard Screenshots

> Screenshots from live testing with gpt-4o-mini: [Shield](docs/screenshots/shield.png) | [Threats](docs/screenshots/threats.png) | [Flow X-Ray](docs/screenshots/flow.png) | [Compliance](docs/screenshots/compliance.png)

## Configuration

```yaml
target: https://api.openai.com
budgets:
  daily: 50.0
threat_intel:
  enabled: true
semantic_cache:
  enabled: true
session_risk:
  enabled: true
  warn_threshold: 30
  block_threshold: 60
```

## Integrations

- MCP Server — Security checks inside your AI agent (`mcp-server/`)
- GitHub Action — CI/CD security gate (`github-action/`)
- OpenClaw — Heartbeat protection, spend-rate anomaly (`integrations/openclaw/`)
- Telegram Alerts — Real-time notifications on threats
- OTel/Prometheus — Export metrics to your stack

## Stress Test Results

| Scenario | Result | Key Metric |
|----------|--------|------------|
| 50 concurrent agents | ✅ | avg 93ms overhead |
| Sustained 1000 req/min | ✅ | p99 201ms, 0 errors |
| Memory stability 30min | ✅ | 0.00MB growth |
| Adversarial under load | ✅ | 0 false positives |
| Cascade failure recovery | ✅ | 99.0% recovery rate |
| Heartbeat storm (1000/sec) | ✅ | 996 blocked, 4 allowed |
| Budget race conditions | ✅ | 0 overspend |
| Policy hot-reload | ✅ | 0 dropped requests |

## Compliance

| Framework | Coverage |
|-----------|----------|
| OWASP LLM Top 10 | 90% |
| NIST AI RMF | 100% |

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and browse [good first issues](https://github.com/poushwell/orchesis/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22).

## License

MIT

## Footer

[Documentation](docs/) | [API Reference](docs/API_REFERENCE.md) | [Discord](https://discord.gg/) | [Twitter](https://x.com/)
