# Trust Tiers

## Model Overview

Orchesis assigns every agent a trust tier and enforces capabilities before rule evaluation.  
If an agent is unknown, Orchesis uses `default_trust_tier` from policy (or `intern` by default).

## Capability ladder

| Tier | Intent | Default capabilities |
|---|---|---|
| `blocked` | emergency quarantine | none |
| `intern` | read-only workflows | `read` |
| `assistant` | limited write workflows | `read`, `write` |
| `operator` | operational tooling | `read`, `write`, `delete`, `execute` |
| `principal` | full administrative authority | `read`, `write`, `delete`, `execute`, `admin` |

## Per-agent overrides

You can override limits for specific agents:

- `max_cost_per_call`
- `daily_budget`
- `rate_limit_per_minute`
- `allowed_tools`
- `denied_tools`

Example:

```yaml
agents:
  - id: data_bot
    name: Data Bot
    trust_tier: assistant
    max_cost_per_call: 0.5
    daily_budget: 20.0
    rate_limit_per_minute: 30
```

## Default tier behavior

If no explicit `agents` entry is found for `context.agent`:

1. Resolve to `default_trust_tier` when set
2. Fallback to `intern`
3. Enforce capability checks and tier constraints as usual

## Tier examples

- `blocked`: deny everything, including read-only requests
- `intern`: allow `read_file`, deny `write_file` and destructive SQL
- `assistant`: allow reads and controlled writes under policy rules
- `operator`: full operational tools, still subject to policy limits
- `principal`: bypasses tier capability constraints but still audited
