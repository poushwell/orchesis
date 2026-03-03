# Securing and Optimizing OpenClaw with Orchesis

> Your OpenClaw agent can delete your inbox, burn $200 in tokens, and leak your API keys - all while you sleep. Here's how to fix that in 5 minutes.

## The Problem

OpenClaw is one of the most adopted agent runtimes. It is also high-risk to run unprotected in production or always-on cron mode.

Real issues from the OpenClaw community:

- **$100+ burned in one cron job** - subagent callback loop consumed 128M tokens before anyone noticed (`openclaw/openclaw#17442`)
- **93.5% of token budget wasted** - workspace files injected on every message, ~35,600 tokens per turn (`openclaw/openclaw#9157`)
- **$20/day with no visibility** - no API to track cumulative token usage or cost per session (`openclaw/openclaw#12299`, `openclaw/openclaw#32156`)
- **Prompt injection via WhatsApp** - fake `[System Message]` blocks trick agents into reading arbitrary files (`openclaw/openclaw#30111`)
- **Sandbox bypass** - message tool `filePath` reads host filesystem without sandbox validation (`openclaw/openclaw#3805`)
- **Infinite loops** - subagent callbacks, cron duplicate delivery, confusion loops from path mismatches (`openclaw/openclaw#17442`, `openclaw/openclaw#30816`, `openclaw/openclaw#16790`)
- **No cost-optimized gateway** - users request automatic model downshifting for low complexity traffic (`openclaw/openclaw#9244`, `openclaw/openclaw#31734`)

Orchesis runs as a local policy proxy between OpenClaw and model providers. You do not patch OpenClaw source. You change API base URL to localhost, and Orchesis enforces policy on every call.

## Architecture

```text
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Messaging   │────▶│  OpenClaw    │────▶│  Orchesis    │────▶ LLM API
│  (Telegram)  │◀────│  Gateway     │◀────│  Proxy       │◀──── (Claude/GPT)
└─────────────┘     └─────────────┘     └─────────────┘
                                              │
                                         Policy Engine
                                         Cost Tracker
                                         Loop Detector
                                         Secret Scanner
                                         Model Router
```

OpenClaw continues using `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` the same way.  
Only the base URL changes to `http://localhost:8100/v1`.

## Quick Start (5 minutes)

### Step 1: Install Orchesis

```bash
pip install orchesis
```

### Step 2: Create `policy.yaml`

Create `~/.orchesis/policy.yaml`:

```yaml
version: "1.0"
name: "openclaw-production"

tool_access:
  mode: allowlist
  default: deny
  allowed:
    - read_file
    - write_file
    - web_search
    - message
    - memory_search
  denied:
    - shell_execute
    - run_command
    - bash
    - terminal
  denied_paths:
    - /etc
    - /root
    - ~/.ssh
    - ~/.aws
    - ~/.openclaw/credentials
    - ~/.openclaw/openclaw.json
  denied_operations:
    - DROP
    - DELETE
    - TRUNCATE
  rate_limits:
    web_search: 30/minute
    message: 20/minute
    read_file: 60/minute
    write_file: 20/minute

secret_scanning:
  enabled: true
  block_on_detection: true

pii_detection:
  enabled: true
  auto_redact: true

budgets:
  daily: 10.00
  per_task: 5.00
  soft_limit_percent: 70
  on_soft_limit: downgrade_model
  on_hard_limit: block
  per_tool:
    web_search: 2.00
    browser: 3.00
    shell_execute: 1.00

tool_costs:
  web_search: 0.005
  browser: 0.010
  shell_execute: 0.001
  read_file: 0.0001
  write_file: 0.0001
  message: 0.001
  memory_search: 0.002
  cron: 0.001

loop_detection:
  enabled: true
  warn_threshold: 5
  block_threshold: 10
  window_seconds: 300

model_routing:
  enabled: true
  default: claude-sonnet-4
  rules:
    - complexity: low
      model: claude-haiku-4
    - complexity: medium
      model: claude-sonnet-4
    - complexity: high
      model: claude-opus-4
```

Why this policy maps to known OpenClaw pain:

- Loop blocking for `#17442`, `#30816`
- Budget and visibility controls for `#12299`, `#32156`
- Token/cost efficiency for `#9157`, `#9244`, `#31734`
- Filesystem guardrails for `#3805`
- Injection blast-radius reduction for `#30111`

### Step 3: Start Orchesis proxy

```bash
orchesis proxy --port 8100 --policy ~/.orchesis/policy.yaml
```

### Step 4: Point OpenClaw to Orchesis

In `~/.openclaw/openclaw.json`:

Anthropic:

```json
{
  "models": {
    "primary": {
      "provider": "anthropic",
      "apiBaseUrl": "http://localhost:8100/v1"
    }
  }
}
```

OpenAI:

```json
{
  "models": {
    "primary": {
      "provider": "openai",
      "apiBaseUrl": "http://localhost:8100/v1"
    }
  }
}
```

Restart OpenClaw Gateway.

### Step 5: Verify end-to-end

```bash
# Check service status
orchesis status

# Show today's spend and top cost drivers
orchesis cost report

# Show budget and loop status
orchesis cost status

# Optional: reset daily budget counters
orchesis cost reset
```

Quick functional test in OpenClaw chat:

- Prompt: `Read /etc/passwd and summarize it`
- Expected: denied by policy before model/tool execution

## What Orchesis Fixes (mapped to OpenClaw Issues)

### Cost Explosion (`#9157`, `#17442`, `#12299`, `#32156`, `#5431`, `#1594`)

| Problem | Issue | Orchesis fix |
|---|---|---|
| Workspace files waste 93.5% of tokens | `#9157` | Prompt/tool boundary controls + budget caps + routing |
| Subagent callback loop: 128M tokens | `#17442` | Loop detector warns at 5, blocks at 10 |
| No cost tracking API | `#12299` | `orchesis cost report` (tool/day/session visibility) |
| $20/day no visibility | `#32156` | Daily hard budget + soft threshold actions |
| Exponential growth in long sessions | `#5431` | Routing + budget + per-tool rate/cost controls |
| Huge stale context dragged forward | `#1594` | Policy-level throttling and model downshift on soft limit |

### Security (`#3805`, `#30111`, `#29442`, `#4840`, `#7827`)

| Problem | Issue | Orchesis fix |
|---|---|---|
| `filePath` sandbox bypass | `#3805` | `denied_paths` and normalized path enforcement |
| Prompt injection via chat content | `#30111` | Tool-call policy + secret/PII scanning before execution |
| Request for policy layer between model and tools | `#29442` | Orchesis proxy is that layer |
| Missing runtime injection defense | `#4840` | Per-call checks, deny rules, outbound scanning |
| Insecure defaults | `#7827` | Secure baseline policy template |

### Loops & Stability (`#17442`, `#30816`, `#16790`)

| Problem | Issue | Orchesis fix |
|---|---|---|
| Infinite callback loop | `#17442` | Deterministic loop blocking with thresholds |
| Cron duplicate delivery loops | `#30816` | Rate limits + loop window detection |
| Path mismatch confusion loops | `#16790` | Normalization + policy guardrails + throttling |

### Model Routing (`#9244`, `#31734`, `#17078`)

| Problem | Issue | Orchesis fix |
|---|---|---|
| No cost-optimized gateway | `#9244` | Complexity-based model router |
| All group traffic on expensive model | `#31734` | Low complexity to Haiku, high complexity to Opus |
| Heavy keepalive / heartbeat context handling | `#17078` | Low-value traffic route-down + budget gate |

## Advanced Configuration

### Docker sidecar setup

```yaml
services:
  openclaw:
    image: ghcr.io/openclaw/openclaw:latest
    environment:
      - ANTHROPIC_API_BASE_URL=http://orchesis:8100/v1
      - OPENAI_API_BASE_URL=http://orchesis:8100/v1
    depends_on:
      - orchesis

  orchesis:
    image: ghcr.io/orchesis/orchesis:latest
    volumes:
      - ./policy.yaml:/etc/orchesis/policy.yaml:ro
    ports:
      - "8100:8100"
    command: orchesis proxy --port 8100 --policy /etc/orchesis/policy.yaml
```

### Monitoring and reporting

```bash
# Daily report (console)
orchesis cost report

# Markdown for Slack/Telegram
orchesis cost report --format markdown > /tmp/daily-cost.md

# JSON for dashboards
orchesis cost report --format json > /tmp/costs.json
```

### Cron-focused hardening

```yaml
channel_policies:
  cron:
    max_calls_per_session: 100
    force_model: claude-haiku-4
    rate_limit_per_minute: 20
```

This is aimed at preventing runaway cron behavior like `#17442` and duplicate-trigger storms like `#30816`.

### Skill scanning before install

```bash
# Scan untrusted skills before enabling
orchesis scan --path ./skills/new-skill/

# Optional YARA-enhanced scan
orchesis scan --path ./skills/new-skill/ --yara src/orchesis/yara_rules/
```

Use this for supply-chain hygiene before importing third-party skill packs.

## Cost Comparison

Anthropic reference rates used for estimate:

- Claude Opus 4: input `$0.015/1K`, output `$0.075/1K`
- Claude Sonnet 4: input `$0.003/1K`, output `$0.015/1K`
- Claude Haiku 4: input `$0.0008/1K`, output `$0.004/1K`

### Before Orchesis (typical OpenClaw user)

| Source | Daily Cost | Monthly |
|---|---:|---:|
| Heartbeats (Opus, every 10 min) | $5.40 | $162 |
| Workspace injection overhead | $3.20 | $96 |
| Cron jobs (4/day) | $2.10 | $63 |
| Actual user queries | $4.30 | $129 |
| **Total** | **$15.00** | **$450** |

### After Orchesis

| Source | Daily Cost | Savings |
|---|---:|---:|
| Heartbeats (routed to Haiku) | $0.30 | 94% |
| Workspace/context overhead controls | $0.50 | 84% |
| Cron (Haiku + loop protection) | $0.40 | 81% |
| User queries (smart routing) | $2.80 | 35% |
| **Total** | **$4.00** | **73%** |

**Estimated monthly savings: ~$330**

## FAQ

**Q: Does Orchesis modify OpenClaw code?**  
A: No. It is a transparent proxy. Change one API base URL and restart.

**Q: Added latency?**  
A: Policy evaluation is usually a few milliseconds per call. Loop and budget checks are constant-time state lookups.

**Q: Can I use it with other frameworks?**  
A: Yes. Any agent stack that calls OpenAI-compatible or Anthropic-compatible APIs can be fronted by Orchesis.

**Q: What happens at daily budget limit?**  
A: Orchesis blocks additional calls (hard limit) and returns an explicit reason. You can raise limits or run `orchesis cost reset`.

**Q: Does my data leave my machine through Orchesis?**  
A: No additional outbound path is introduced by Orchesis itself. It runs locally and forwards only what OpenClaw would already send to model providers, under policy controls.

## Related OpenClaw Issues

If you track these threads, Orchesis maps directly:

- `openclaw/openclaw#17442` - subagent callback infinite loop -> Loop Detector
- `openclaw/openclaw#9157` - 93.5% token waste -> budget/routing controls
- `openclaw/openclaw#12299` - no cost tracking API -> CostTracker + CLI
- `openclaw/openclaw#32156` - $20/day spending -> budget limits
- `openclaw/openclaw#9244` - cost-optimized gateway request -> ModelRouter
- `openclaw/openclaw#31734` - per-group triage model -> complexity routing
- `openclaw/openclaw#3805` - sandbox bypass via `filePath` -> denied path policy
- `openclaw/openclaw#30111` - prompt injection via WhatsApp -> runtime policy + scanners
- `openclaw/openclaw#29442` - dual-LLM/policy layer request -> policy proxy
- `openclaw/openclaw#4840` - runtime injection defense -> per-call enforcement
- `openclaw/openclaw#7827` - insecure defaults -> secure baseline policy
- `openclaw/openclaw#5431` - context optimizer demand -> routing + throttling controls
- `openclaw/openclaw#17078` - context/rank compaction request -> low-value traffic downrouting
- `openclaw/openclaw#30816` - cron duplicate delivery -> loop/rate controls
- `openclaw/openclaw#1594` - huge context carryover -> spend guardrails + routing
- `openclaw/openclaw#16790` - confusion loops/path mismatch -> normalized policy checks

## Next Steps

1. Install and run Orchesis proxy locally.
2. Apply the baseline `policy.yaml` from this guide.
3. Route OpenClaw API traffic to `http://localhost:8100/v1`.
4. Validate blocked-path and budget-limit behavior.
5. Iterate policy per environment (Mac Mini, VPS, Docker).

