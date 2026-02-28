# Architecture

## System components

```text
AI Agent / MCP Client
        |
        v
  Proxy or Control API
        |
        v
     evaluate()
        |
  +-----+------------------------------+
  |                                    |
ALLOW                                DENY
  |                                    |
Tool execution                    Block + reason
  |                                    |
  +-------------> Telemetry/Event Bus <+
                    |      |      |
                  JSONL  Metrics  Webhooks
                    |
                  Replay/Audit
```

## Data flow

1. Request arrives with tool, params, cost, and optional agent/session context.
2. Identity tier checks run first.
3. Rule pipeline executes in deterministic order.
4. Decision is returned (`ALLOW`/`DENY`) and telemetry event is emitted.
5. State tracker updates counters and budgets for allowed calls.

## Evaluation pipeline

Fixed order:

1. `identity_check`
2. `budget_limit`
3. `rate_limit`
4. `file_access`
5. `sql_restriction`
6. `regex_match`
7. `context_rules`
8. `composite`

## State management

- Sliding-window rate limits
- Per-agent and per-session isolation
- Budget spend tracking (24h)
- Persistent JSONL state (optional)

## Telemetry pipeline

- `DecisionEvent` emitted for every evaluation
- JSONL audit sink for forensics
- Prometheus metrics aggregation
- OTel-compatible span export (`traces.jsonl`)
- Replay engine for deterministic verification

## Event bus architecture

- Central pub/sub bus fan-outs events to multiple subscribers
- Built-in emitters: JSONL, metrics, webhooks, OTel
- Subscribers can be filtered and dynamically reconfigured
