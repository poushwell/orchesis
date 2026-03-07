# Orchesis — AI Agent Control Plane

> Open-source proxy that makes AI agents secure, cost-efficient, and reliable in production.

## Why Orchesis?

- 40–95% of AI agent pilots fail in production
- One line of config, zero code changes
- Security + Cost + Effectiveness in one proxy

## Quickstart

See the quick start commands below.

## Quick Start (3 commands)

```bash
pip install orchesis
orchesis init
orchesis proxy --port 8080
orchesis serve --policy policy.yaml
```

## Features

### Security

- **Threat Intelligence** — 25 built-in signatures (prompt injection, command injection, data exfiltration, memory poisoning)
- Secret/PII scanning
- Loop detection + Circuit breaker
- Compliance (9 frameworks: OWASP, NIST, SOC2, HIPAA, EU AI Act…)

### Cost Optimization

- **Adaptive Model Cascade** — auto-route by complexity
- **Semantic Cache** — SimHash + Jaccard, no vector DB
- **Context Engine** — dedup, trim, compress
- Budget limits + cost tracking

### Effectiveness (unique — no competitor has this)

- **A/B Testing Framework** — live model comparison
- **Task Completion Tracking** — success rate intelligence
- **Agent DNA** — behavioral fingerprinting + drift detection
- **Flow X-Ray** — conversation topology + 10 pattern detectors
- **Time Machine** — session replay + what-if analysis

## Dashboard

Single-page embedded dashboard with 8 tabs:

- **Shield Overview** — status pulse, metrics, cost timeline, circuit breaker, budget, events
- **Agents** — Agent DNA table
- **Sessions** — Time Machine sessions
- **Flow X-Ray** — conversation topology, patterns
- **Experiments** — A/B testing, task success rate, correlations
- **Threats** — threat intel stats, top threats, signatures
- **Cache** — semantic cache + context engine stats
- **Compliance** — OWASP/NIST coverage, findings

## Architecture

One transparent proxy, 17 phases:

```
parse → experiment → flow_xray → cascade → circuit_breaker → loop →
behavioral → budget → policy → threat_intel → model_router →
secrets → context → semantic_cache → upstream → post_upstream → send
```

## Documentation

- [Quick Start](docs/QUICKSTART.md)
- [Architecture](docs/ARCHITECTURE.md)
- [API Reference](docs/API_REFERENCE.md)
- [Policy Reference](docs/POLICY_REFERENCE.md)

## Project Stats

- 800+ tests passing
- CI on Python 3.11 and 3.12

## Integrations

- OpenAI-compatible clients
- Anthropic-compatible clients
- OTLP-compatible observability backends

## Comparison

| Feature | Orchesis | Lasso | Lunar | LangSmith |
|---------|----------|-------|-------|-----------|
| Open source | ✅ | ❌ | ❌ | ❌ |
| Zero deps | ✅ | ❌ | ❌ | ❌ |
| A/B Testing | ✅ | ❌ | ❌ | ❌ |
| Flow X-Ray | ✅ | ❌ | ❌ | ❌ |
| Semantic Cache | ✅ | ❌ | ❌ | ❌ |
| Compliance (9fw) | ✅ | ❌ | ❌ | ❌ |

## License

MIT
