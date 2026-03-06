# Architecture

## Overview

Orchesis is a transparent HTTP proxy that sits between AI agents and LLM providers. Every request passes through a 17-phase pipeline before reaching the upstream.

## Request flow

```text
AI Agent / MCP Client
        |
        v
   Orchesis Proxy
        |
        v
   17-phase pipeline
        |
  +-----+------------------------------+
  |                                    |
ALLOW                                DENY
  |                                    |
Upstream (OpenAI/Anthropic)      Block + reason
  |                                    |
  +-------------> Telemetry/Event Bus <+
                    |      |      |
                  JSONL  Metrics  Dashboard
                    |
                  Replay/Audit
```

## 17-phase pipeline

Phases execute in order. Early phases can short-circuit (e.g., circuit breaker open).

1. **parse** — Parse request body, extract tool/model/params
2. **experiment** — A/B experiment assignment (if enabled)
3. **flow_xray** — Record conversation topology
4. **cascade** — Adaptive model cascade (route by complexity)
5. **circuit_breaker** — Fail-fast on upstream errors
6. **loop** — Loop detection (exact + fuzzy)
7. **behavioral** — Agent DNA fingerprinting
8. **budget** — Cost limits (daily, per-session)
9. **policy** — YAML policy evaluation (tool_access, rules)
10. **threat_intel** — 25 built-in threat signatures
11. **model_router** — Model override / routing
12. **secrets** — Secret scanner (API keys, tokens)
13. **context** — Context engine (dedup, trim)
14. **semantic_cache** — SimHash + Jaccard cache lookup
15. **upstream** — Forward to LLM provider
16. **post_upstream** — Store cache, record metrics
17. **send** — Stream/return response

## Key components

- **Policy engine** — YAML-based tool allowlist/denylist, rules, budgets
- **Threat matcher** — Prompt injection, command injection, data exfiltration, memory poisoning
- **Semantic cache** — No vector DB; SimHash + Jaccard similarity
- **Context engine** — Dedup, trim, sliding window, token budget
- **Experiment manager** — A/B testing, task completion tracking
- **Flow analyzer** — Conversation topology, pattern detection

## State management

- Sliding-window rate limits
- Per-agent and per-session isolation
- Budget spend tracking (24h)
- Persistent JSONL state (optional)

## Telemetry

- `DecisionEvent` for every evaluation
- JSONL audit sink
- Prometheus metrics
- Dashboard polling (`/stats`, `/api/dashboard/*`)
