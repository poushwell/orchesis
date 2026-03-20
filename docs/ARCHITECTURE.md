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

## Recent modules (A-T sprint)

- **Context Router** (`context_router`) — strategy classification per request task type
- **Cost Optimizer** (`cost_optimizer`) — dedup, whitespace trim, tool-result compression, assistant-turn pruning
- **Adaptive Detection v2** (`adaptive_detection_v2`) — 5-layer detector with confidence and calibration
- **Intent Classifier** (`intent_classifier`) — intent + risk inference for inbound prompts
- **Response Analyzer** (`response_analyzer`) — leakage, hallucination signals, quality scoring
- **Tool Call Analyzer** (`tool_call_analyzer`) — risk scoring and session-level tool usage insights
- **Anomaly Predictor** (`anomaly_predictor`) — trend-based early warning and prediction history
- **Policy Optimizer** (`policy_optimizer`) — suggested rate-limit/cache/budget tuning from traffic
- **Cache Warmer** (`cache_warmer`) — pre-populates semantic cache from frequent request patterns
- **Agent Graph** (`agent_graph`) — collaboration map (nodes/edges/clusters/stats)
- **Geo Intel** (`geo_intel`) — SSRF-oriented IP classification (private/loopback/link-local/public)

## Research modules (Y + pipeline sprint)

- **PAR Reasoning** (`par_reasoning`) — T5 theorem implementation for proxy abductive diagnosis
- **Criticality Control** (`criticality_control`) — LQR Ψ∈[0.4,0.6]
- **MRAC Controller** (`mrac_controller`) — adaptive gain scheduling per agent
- **Keystone Agent** (`keystone_agent`) — trophic cascade and systemic influence analysis
- **Carnot Efficiency** (`carnot_efficiency`) — theoretical task-efficiency ceiling
- **Red Queen Dynamics** (`red_queen`) — adversarial co-evolution tracking
- **Kolmogorov Importance** (`kolmogorov_importance`) — UCI-K duality heuristics
- **Context Crystallinity** (`core/nlce_pipeline`) — gas/liquid/crystal phase transitions via Ψ
- **HGT Protocol** (`hgt_protocol`) — horizontal transfer stub for future fleet activation
- **IACS Coherence** (`discourse_coherence`) — 0.40×FC + 0.35×EC + 0.25×HC score decomposition

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
