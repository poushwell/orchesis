![Orchesis](https://raw.githubusercontent.com/poushwell/orchesis/main/docs/banner-light.png)

[![PyPI](https://img.shields.io/pypi/v/orchesis?color=7c3aed&label=PyPI)](https://pypi.org/project/orchesis/)
[![Tests](https://img.shields.io/badge/tests-2969%20passing-22c55e)](https://github.com/poushwell/orchesis)
![License](https://img.shields.io/badge/license-MIT-blue)
[![Stars](https://img.shields.io/github/stars/poushwell/orchesis?style=flat&color=7c3aed)](https://github.com/poushwell/orchesis)
![Dependencies](https://img.shields.io/badge/dependencies-0-green)

Orchesis is a transparent HTTP proxy for AI agents. Every request passes through
a 17-phase detection pipeline before reaching the LLM provider.
Zero dependencies. MIT license.

SDK sees one agent. Static analysis sees code. Observability sees metrics.
Proxy sees everything, in real time, without code changes.

## Installation

    pip install orchesis

## With integrations

    pip install orchesis[integrations]

## One line change

Before:

    client = OpenAI(base_url="https://api.openai.com/v1")

After:

    client = OpenAI(base_url="http://localhost:8080/v1")
    # 17 security phases now active

## Why proxy, not SDK?

| Approach | What it sees | Code changes |
|----------|-------------|--------------|
| SDK/callbacks (LangSmith, LangChain) | One agent, one session | Required |
| Static analysis (Snyk, Semgrep) | Code at rest | Required |
| Observability (Datadog, Helicone) | Metrics and logs | Required |
| Orchesis proxy | All agents, all requests, cross-session | None |

The proxy layer sees what SDK cannot: cross-agent patterns, fleet-level anomalies,
duplicate context across providers.

## What Orchesis does

**Security:** 17-phase detection. Prompt injection, credential leaks, tool abuse. 25 signatures.

**Cost:** Semantic cache. Budget enforcement. Token Yield tracking. MVE result: 0.8% overhead, 12x context growth detected.

**Reliability:** Auto-healing. Circuit breakers. Loop detection. 6 recovery actions.

**Observability:** Real-time dashboard. Flow X-Ray. Agent Reliability Score.

## By the numbers

| Metric | Value |
|--------|-------|
| Pipeline phases | 17 |
| Threat signatures | 25 across 10 categories |
| Proxy overhead | 0.8% measured |
| Context collapse | 12x growth caught |
| MAST coverage | 78.6% |
| OWASP coverage | 80% |
| Tests passing | 2,969 |
| Dependencies | 0 (stdlib only) |

## Free MCP Security Scanner

We scanned 900+ MCP configurations on GitHub. 75% had at least one security issue:
hardcoded credentials, overpermissioned tools, missing input validation.

Run the scanner on your own configs:

    npx orchesis-scan

Or visit: https://orchesis.io/scan

52 security checks across 10 categories. No data sent to external servers.

---

[Website](https://orchesis.io) | [Documentation](https://orchesis.io/docs) | [MCP Scanner](https://orchesis.io/scan) | [GitHub](https://github.com/poushwell/orchesis) | [Blog](https://orchesis.io/blog)

MIT License. Built with zero dependencies.
