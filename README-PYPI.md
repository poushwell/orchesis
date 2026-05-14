# Orchesis

**See everything your AI agents do.**

**Runtime Gateway for AI Agents** — block threats, cut token waste, monitor your fleet. One config change.

PyPI · **tests-4%2C912%2B** · MIT · Python 3.10+ · MCP checks 113

**Full README** (banner, pipeline diagram, badges): [github.com/poushwell/orchesis/blob/main/README.md](https://github.com/poushwell/orchesis/blob/main/README.md)

---

## What is Orchesis?

Orchesis is an open-source HTTP proxy that sits between your AI agents and their LLM providers (OpenAI, Anthropic, Google, Mistral). One config change — set `base_url` to `localhost:8080` — and every request passes through a **17-phase security pipeline**. No SDK integration. No code changes. No vendor lock-in.

- **Security** — Injection detection (96% explicit, 0 false positives), credential blocking, Crystal Alert
- **Cost** — Context compression (80-90% savings), loop detection at call #3, per-request budget enforcement
- **Reliability** — Auto-healing, cascade failure shield, 6 recovery actions, 450x faster than heartbeat checks
- **Observability** — Real-time dashboard, fleet correlation, independent audit log

Works with OpenClaw, CrewAI, LangChain, LangGraph, AutoGen, OpenAI Agents SDK, Google ADK, and any agent that speaks OpenAI-compatible API.

---

## Install

```bash
pip install orchesis
```

Optional extras: `pip install orchesis[yaml]` · `pip install orchesis[integrations]` · `pip install orchesis[server]` · `pip install orchesis[all]` (bundles common optional deps).

## One line change

```python
# Before:
client = OpenAI(base_url="https://api.openai.com/v1")

# After — 17 security phases now active:
client = OpenAI(base_url="http://localhost:8080/v1")
```

```bash
orchesis verify
orchesis scan --mcp
orchesis dashboard   # opens dashboard URL (default port 8081; see docs)
```

---

## Why proxy, not SDK?

|  | SDK / callbacks | Static analysis | Generic gateway | **Orchesis proxy** |
|---|:---:|:---:|:---:|:---:|
| Sees | One agent, one session | Code at rest | Metrics and logs | **Everything, cross-agent** |
| Code changes | Required | Required | Required | **None** |
| Fleet correlation | No | No | Partial | **Yes** |
| Real-time detection | Partial | No | No | **Yes** |
| Formal security proofs | No | No | No | **Yes** |
| Published detection limits | No | No | No | **Yes** |
| Zero code changes | No | No | No | **Yes** |
| Open source (MIT) | varies | some | No | **Yes** |
| Self-hosted | No | No | No | **Yes** |
| No telemetry | No | No | No | **Yes** |

---

## MCP Security Scanner

Scan MCP configs in browser or CLI. **52 checks across 6 categories:** supply chain, credentials, Docker, permissions, network, cross-server.

```bash
npx orchesis-scan
# or
orchesis scan --mcp
```

[Web scanner](https://orchesis.ai/scan)

---

## Features (summary)

- **17-phase security pipeline** — Injection Shield, Crystal Alert, credential blocking, tool abuse
- **Cost control** — Context compression, loop detection, Thompson routing, per-request budgets
- **Auto-healing** — Six recovery strategies, cascade shield, circuit breaker
- **Dashboard** — Local UI; fleet correlation
- **Agent Autopsy** — Post-incident replay and audit trail
- **`orchesis verify`** — Pre-flight checks for config and environment

---

## By the numbers

| Metric | Value |
|---|---|
| Pipeline phases | 17 |
| Proxy overhead | < 3ms (measured) |
| Token savings | 80-90% (context compression) |
| Injection detection | 96% explicit, 0 false positives |
| Threat signatures | 33+ across 10 categories |
| MCP checks | 52 across 6 categories |
| MAST coverage | 78.6% (11/14 failure modes) |
| OWASP coverage | 80% (8/10 risks) |
| Tests passing | 4,813+ |
| Modules | ~309 |
| Dependencies | 0 (stdlib only) |

Core install has **no required** third-party dependencies; YAML, HTTP client, and server stacks are **optional extras**.

---

## Documentation

- [Quick Start](https://github.com/poushwell/orchesis/blob/main/QUICK_START.md)
- [Configuration](https://github.com/poushwell/orchesis/blob/main/docs/CONFIG.md)
- [Pipeline](https://github.com/poushwell/orchesis/blob/main/docs/PIPELINE.md)
- [Dashboard](https://github.com/poushwell/orchesis/blob/main/docs/DASHBOARD.md)
- [Website](https://orchesis.ai) · [MCP Scanner](https://orchesis.ai/scan) · [Scorecard](https://orchesis.ai/scorecard) · [Blog](https://orchesis.ai/blog)

---

## Contributing & license

Contributions welcome — [CONTRIBUTING.md](https://github.com/poushwell/orchesis/blob/main/CONTRIBUTING.md).

[MIT License](https://github.com/poushwell/orchesis/blob/main/LICENSE).
