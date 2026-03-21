# 🛡️ Orchesis

**See everything your AI agents do.**

Runtime Gateway for AI Agents — block threats, cut token waste, monitor your fleet. One config change.

[![PyPI](https://img.shields.io/pypi/v/orchesis)](https://pypi.org/project/orchesis/)
[![Tests](https://img.shields.io/badge/tests-4%2C670%2B-brightgreen)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)]()

[Website](https://orchesis.ai) · [Docs](QUICK_START.md) · [MCP Scanner](https://orchesis.ai/scan) · [Scorecard](https://orchesis.ai/scorecard) · [Blog](https://orchesis.ai/blog)


## What is Orchesis?

Your AI agent made 122 API calls. Its built-in loop detector caught zero. Detection was ON. All thresholds configured. ([Issue #34574](https://github.com/all-hands-ai/openclaw/issues/34574))

Orchesis is an open-source HTTP proxy that sits between your AI agents and their LLM providers (OpenAI, Anthropic, Google, Mistral). One config change — set `base_url` to `localhost:8080` — and every request passes through a **17-phase security pipeline**. No SDK integration. No code changes. No vendor lock-in.

- **Security** — Injection detection (96% explicit, 0 false positives), credential blocking, Crystal Alert
- **Cost** — Context compression (80-90% savings), loop detection at call #3, per-request budget enforcement
- **Reliability** — Auto-healing, cascade failure shield, 6 recovery actions, 450x faster than heartbeat checks
- **Observability** — Real-time dashboard, fleet correlation, independent audit log

Works with OpenClaw, Paperclip, CrewAI, LangChain, AutoGen, Google ADK, and any agent that speaks OpenAI-compatible API.

**Why this exists:** 390,000+ OpenClaw instances online. 20% of the skill marketplace was malicious. Budget tracking reports $0.00 for entire Codex fleets. The tools watching your agents are watching from inside the compromised context.


## Quickstart

### Install

```bash
pip install orchesis
```

### Use — one line change

```python
# Before:
client = OpenAI(base_url="https://api.openai.com/v1")

# After — 17 security phases now active:
client = OpenAI(base_url="http://localhost:8080/v1")
```

```bash
# Or with curl:
curl http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{"model":"gpt-4","messages":[{"role":"user","content":"Hello"}]}'
```

### Verify your setup

```bash
orchesis verify
```

### Scan MCP configs

```bash
npx orchesis-scan           # npm CLI, zero install
orchesis scan --mcp         # Python CLI
```

### Dashboard

```bash
orchesis dashboard          # opens at localhost:8081
```


## How it works

```
┌──────────────┐     ┌─────────────────────────────┐     ┌──────────────┐
│  AI Agents   │     │       Orchesis Proxy         │     │LLM Providers │
│              │     │       localhost:8080          │     │              │
│  OpenClaw    │────▶│                               │────▶│  OpenAI      │
│  Paperclip   │     │  Security     (phases 1-8)    │     │  Anthropic   │
│  CrewAI      │     │  Context      (phases 9-11)   │     │  Google      │
│  LangChain   │     │  Threat Intel (phases 12-14)  │     │  Mistral     │
│  Any agent   │     │  Cost         (phases 15-16)  │     │  Ollama      │
│              │     │  Observability (phase 17)     │     │  Any compat. │
└──────────────┘     │                               │     └──────────────┘
                     │  < 3ms overhead               │
                     │  0 code changes required      │
                     └─────────────────────────────┘
```

### Why proxy, not SDK?

| | SDK / callbacks | Static analysis | **Orchesis proxy** |
|---|---|---|---|
| Sees | One agent, one session | Code at rest | **Everything, cross-agent** |
| Code changes | Required | Required | **None** |
| Fleet correlation | No | No | **Yes** |
| Real-time | Partial | No | **Yes** |


## Features

### 🔒 17-Phase Security Pipeline

Adaptive detection across 8 security phases. Injection Shield (33+ signatures, 96% explicit detection, 0 false positives), Crystal Alert (behavioral anomaly), credential blocking, tool abuse detection. We publish what we can't detect: semantic injection is a proven structural limit at 0%.

### 💰 Cost Control

Context compression saves 80-90% tokens in growing-context sessions. Loop detection fires at call #3 — saves $55-150 per incident. 450x faster than heartbeat-based orchestrators. Thompson Sampling model routing. Per-request budget enforcement.

### 🔧 Auto-Healing

6 recovery strategies. Cascade Failure Shield. Model fallback. Context reset. Circuit breaker fires at call #3, not at next heartbeat.

### 📊 Dashboard

Real-time local dashboard. 8 tabs: Shield, Agents, Sessions, Flow X-Ray, Experiments, Threats, Cache, Compliance. Fleet-level correlation: which agent did what, and why it cost so much.

### 🔍 MCP Security Scanner

52 checks across 6 categories: supply chain, credentials, Docker, permissions, network, cross-server. Runs in browser or CLI. [Try it →](https://orchesis.ai/scan)

### 🏢 Fleet Monitoring (Overwatch)

Cross-agent correlation. Per-agent cost attribution. Independent audit log outside your orchestrator's data store. Detects cost discrepancies ($0.00 Codex bug, timeout gaps, self-reported vs actual).

### 🔬 Agent Autopsy

Post-incident investigation. Session replay. Decision chain reconstruction. Evidence-grade audit trail. "What killed your AI agent?" — answered.

### ✅ orchesis verify

One-command security audit of your agent setup. Checks config, connectivity, pipeline health, known vulnerabilities. First command every new user runs.


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
| Tests passing | 4,670+ |
| Modules | ~120 |
| Dependencies | 0 (stdlib only) |
| License | MIT |

Optional extras: `pip install orchesis[yaml]` for YAML config, `pip install orchesis[all]` for integrations.


## Works with

**AI Agents & Orchestrators:**
OpenClaw · **Paperclip** · CrewAI · LangChain · LangGraph · AutoGen · OpenAI Agents SDK · Google ADK · Any OpenAI-compat agent

**LLM Providers:**
OpenAI · Anthropic · Google Gemini · Mistral · Ollama · Any OpenAI-compatible API

If your agent calls an LLM via HTTP — Orchesis works with it.


## How Orchesis compares

| | Generic Gateway | LLM Router | Agent Platform | **Orchesis** |
|---|---|---|---|---|
| Understands MCP/A2A | ✗ | ✗ | ✗ | **✓** |
| 17-phase security | ✗ | ✗ | ✗ | **✓** |
| Fleet correlation | ✗ | ✗ | partial | **✓** |
| Formal security proofs | ✗ | ✗ | ✗ | **✓** |
| Honest limits published | ✗ | ✗ | ✗ | **✓** |
| Zero code changes | ✗ | ✗ | ✗ | **✓** |
| Open source (MIT) | varies | some | ✗ | **✓** |
| Self-hosted | ✗ | ✗ | ✗ | **✓** |
| No telemetry | ✗ | ✗ | ✗ | **✓** |


## Research

Orchesis security properties are backed by formal proofs:

- **3 impossibility theorems** — what NO monitor can detect
- **2 necessity results** — what ONLY a proxy can detect
- **25 formal results** total — published, peer-reviewable

Key results:
- Information loss at proxy layer is bounded (C_obs ≈ 0.57 of total agent state)
- Per-request checks don't compose: Safe + Safe ≠ Safe (k_crit = 20 for credential exfiltration)
- Pattern-based detection degrades under optimization pressure ($0.70 to evade single-parameter rules)
- Semantic injection is undetectable by any finite regex set (proven structural limit)
- One poisoned task cascades to 13 agents in 10 minutes (Cascading Injection Theorem)

We also publish what Orchesis **cannot** see: internal reasoning chains, cross-session memory, sub-process spawning, encrypted tool payloads, semantic injection (0% detection). Transparency builds trust.

📄 [Read the research →](https://orchesis.ai/blog/proxy-vs-decorator)


## Documentation

- [Quick Start](QUICK_START.md) — Install and run in 60 seconds
- [Configuration Guide](docs/configuration.md) — All config options
- [Pipeline Reference](docs/pipeline.md) — 17 phases explained
- [Dashboard Guide](docs/dashboard.md) — Using the local dashboard
- [MCP Scanner](https://orchesis.ai/scan) — Web-based config scanner
- [Security Scorecard](https://orchesis.ai/scorecard) — Assess your stack
- [Blog](https://orchesis.ai/blog) — Articles and research


## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Priority areas:
- Injection Shield patterns (new attack categories)
- Agent framework adapters (Paperclip, Google ADK)
- Dashboard improvements
- Documentation and examples


## License

MIT License. See [LICENSE](LICENSE) for details.

---

*Works whether AI wins or loses.*

