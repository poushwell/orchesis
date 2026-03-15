<div align="center">
  <img src="docs/banner.svg" alt="Orchesis" />
</div>

<div align="center">

[![PyPI](https://img.shields.io/pypi/v/orchesis?color=purple&label=PyPI)](https://pypi.org/project/orchesis/)
[![Tests](https://img.shields.io/badge/tests-2738%20passing-brightgreen)](https://github.com/poushwell/orchesis)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Stars](https://img.shields.io/github/stars/poushwell/orchesis?style=social)](https://github.com/poushwell/orchesis)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](https://github.com/poushwell/orchesis)

</div>

**Orchesis** is a transparent HTTP proxy between AI agents
and LLM APIs. Every request passes through a 17-phase
detection pipeline. Zero dependencies. MIT license.
AI Agent -> [Orchesis: 17 phases] -> LLM Provider (OpenAI, Anthropic...)

<div align="center">

[![Get Started](https://img.shields.io/badge/Get%20Started-8B5CF6?style=for-the-badge)](https://orchesis.io/docs)
[![MCP Scanner](https://img.shields.io/badge/MCP%20Scanner-Free-00FF41?style=for-the-badge)](https://orchesis.io/scan)
[![Website](https://img.shields.io/badge/Website-orchesis.io-white?style=for-the-badge)](https://orchesis.io)

</div>

## Installation
```bash
# Core (zero dependencies)
pip install orchesis

# With integrations (Slack, Telegram, webhooks)
pip install orchesis[integrations]

orchesis quickstart --preset openclaw
```

**One line change:**
```python
# Before:
client = OpenAI(base_url="https://api.openai.com/v1")

# After:
client = OpenAI(base_url="http://localhost:8080/v1")
# ↑ 17 security phases now active
```

## How it works
```mermaid
graph LR
    A[AI Agent<br/>OpenClaw/CrewAI/LangChain] -->|HTTP request| B
    B[Orchesis Proxy<br/>17-phase pipeline<br/>localhost:8080] -->|filtered request| C
    C[LLM Provider<br/>OpenAI/Anthropic/Google]
    B --> D[Dashboard<br/>Metrics & Alerts]
```

## What Orchesis does

| | Security | Cost | Reliability | Observability |
|---|---|---|---|---|
| | 17-phase detection. Prompt injection, credential leaks, tool abuse. 25 signatures. | Context compression 80-90%. Semantic cache. Thompson Sampling routing. | Auto-healing. Circuit breakers. Loop detection. 6 recovery actions. | Real-time dashboard. Flow X-Ray. Agent Reliability Score. |

## By the numbers

| Metric | Value |
|--------|-------|
| Pipeline phases | 17 |
| Threat signatures | 25 across 10 categories |
| Token savings | 80-90% |
| MAST coverage | 78.6% |
| OWASP coverage | 80% |
| Auto-heal actions | 6 |
| Tests passing | 2,738 |
| Dependencies | **0** (stdlib only) |

## Free MCP Security Scanner

Check your MCP configuration for security issues:

**[→ orchesis.io/scan](https://orchesis.io/scan)**

Or via CLI:
```bash
orchesis audit-openclaw
```

---

<div align="center">

**[Website](https://orchesis.io)** ·
**[Documentation](https://orchesis.io/docs)** ·
**[MCP Scanner](https://orchesis.io/scan)** ·
**[Blog](https://orchesis.io/blog)**

MIT License · Built with ❤️ and zero dependencies

</div>

