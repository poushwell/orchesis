# Configuration reference

Orchesis loads a **policy** file (YAML or JSON) via `load_policy()` in `src/orchesis/config.py`. Every key below is validated or defaulted during that load. Values shown are the **effective defaults** after normalization unless noted.

There is **no** single top-level `security:` block in the policy schema. Injection-related behavior is split across **`threat_intel`**, **`adaptive_detection`**, **`adaptive_detection_v2`**, and runtime phases in `proxy.py` (see [PIPELINE.md](PIPELINE.md)).

---

## `proxy`

Used by `LLMHTTPProxy` / `orchesis proxy` for listen address, body limits, upstream bases, pooling, and streaming.

| Key | Default (if omitted) | Notes |
|-----|----------------------|--------|
| `host` | *(unset in default stub)* | CLI `--host` or policy `proxy.host`; CLI uses `127.0.0.1` when absent. |
| `port` | *(unset in default stub)* | CLI default **8100** when not in policy. |
| `timeout` | *(unset)* | CLI default **300.0** seconds. |
| `cors` | *(unset)* | Coerced to bool if present. |
| `ssrf_allow_private` | `false` | When `false`, upstream host resolution treats private IPs as SSRF risk (see proxy SSRF logic). |
| `max_workers` | `200` (`DEFAULT_PROXY_MAX_WORKERS`) | Must be &gt; 0. |
| `max_body_size_bytes` | `10485760` | Must be &gt; 0. |
| `upstream` | `{}` | Optional `anthropic` / `openai` URL strings. |
| `connection_pool` | see below | |
| `streaming` | see below | |

### `proxy.connection_pool`

| Key | Default |
|-----|---------|
| `max_per_host` | `10` |
| `max_total` | `50` |
| `idle_timeout` | `60` |
| `connection_timeout` | `30` |
| `retry_on_connection_error` | `true` |
| `max_retries` | `2` |
| `upstream_retry_base_delay_seconds` | `0.1` |
| `upstream_retry_max_delay_seconds` | `2.0` |

### `proxy.streaming`

| Key | Default |
|-----|---------|
| `enabled` | `true` |
| `buffer_size` | `4096` |
| `max_accumulated_events` | `10000` |

---

## Threat and anomaly detection (no `security:` root)

### `threat_intel`

Normalized only if present. If missing, no `threat_intel` key is added.

| Key | Default |
|-----|---------|
| `enabled` | `false` |
| `default_action` | `warn` (`block` \| `warn` \| `log` \| `quarantine`) |
| `severity_actions` | `{}` |
| `custom_signatures` | `[]` |
| `disabled_threats` | `[]` |
| `max_matches_per_request` | `10` |

### `adaptive_detection`

Read by `LLMHTTPProxy` when `adaptive_detection` is a dict and `enabled` is true. Sub-keys are consumed by `AdaptiveDetector` in `src/orchesis/adaptive_detector.py` (e.g. `detectors`, `weights`, `thresholds`, `actions`, nested `entropy` / `structural` / `ngram` / `session_risk` dicts). Defaults inside that class include score bands `low`/`medium`/`high`/`critical` and default actions per band.

### `adaptive_detection_v2`

When a dict with `enabled: true`, enables `AdaptiveDetectionV2`. Optional `confidence_threshold` defaults to **0.62** in the proxy constructor.

### `injection_protocol`

If a dict is present, `ContextInjectionProtocol` is constructed (not gated on `enabled`). Keys used in `src/orchesis/injection_protocol.py`: `strategy` (default `adaptive`), `quality_threshold` (default `0.6`), `max_tokens` (default `500`) for injection budget.

---

## `loop_detection`

Defaults when the whole section is missing:

| Key | Default |
|-----|---------|
| `enabled` | `false` |
| `exact` | `threshold: 5`, `window_seconds: 120`, `action: warn` |
| `fuzzy` | `threshold: 8`, `window_seconds: 300`, `action: block` |
| `content_loop` | `enabled: false`, `window_seconds: 300`, `max_identical: 5`, `cooldown_seconds: 300`, `hash_prefix_len: 256` |
| `on_detect` | `notify/log/max_cost_saved: true` |
| `similarity_check` | `true` |
| `openclaw_reset_commands` | `["/start", "/new", "/reset"]` |

Legacy compatibility fields `warn_threshold`, `block_threshold`, `window_seconds` are derived from `exact` / `fuzzy` after normalization.

---

## `budgets` (daily / soft limits / spend rate)

Normalized in `_normalize_cost_controls`. There is **no** `per_request` field handled in `_normalize_cost_controls` or in `CostTracker.check_budget()`; daily enforcement in the budget phase uses `budgets.daily` via `check_budget()`.

| Key | Default / behavior |
|-----|---------------------|
| `daily` | Optional float; invalid values dropped. |
| `per_tool` | Map of tool → float limits; tracked in `check_budget` → `per_tool_status`. |
| `per_task` | Optional float. |
| `soft_limit_percent` | `80` |
| `on_soft_limit` | `notify` (`notify` \| `downgrade_model` \| `throttle` \| `block`) |
| `on_hard_limit` | `block` (`block` \| `notify`) |
| `spend_rate` | `enabled: false`, `windows` default `[{seconds:300,max_spend:2},{seconds:3600,max_spend:5}]`, `spike_multiplier: 5`, `pause_seconds: 300`, `heartbeat_cost_threshold: 0.10` |

---

## `kill_switch`

| Key | Default |
|-----|---------|
| `enabled` | `false` |
| `resume_token` | `orchesis-resume-2024` (`DEFAULT_RESUME_TOKEN`) |
| `auto_triggers` | `cost_multiplier: 5`, `secrets_threshold: 3`, `loops_threshold: 5` |

If `enabled: true` and `resume_token` is still the default placeholder, the loader **replaces** it with `secrets.token_urlsafe(32)` and logs an info message.

---

## `semantic_cache`

Only normalized when the key exists. Typical fields after normalization:

| Key | Default |
|-----|---------|
| `enabled` | `false` |
| `max_entries` | `1000` (clamped to `1..100000`) |
| `ttl_seconds` | `600` |
| `simhash_threshold` | `8` |
| `jaccard_threshold` | `0.6` |
| `min_content_length` | `20` |
| `max_content_length` | `50000` |
| `cacheable_models` | `[]` |
| `exclude_tool_calls` | `true` |
| `track_savings` | `true` |
| `similarity_threshold` | `0.85` |
| `exact_match_only` | `false` |

---

## `cascade`

| Key | Default |
|-----|---------|
| `enabled` | `false` |
| `levels` | `{}` (per-level `action`, `model` from allow-list, `max_tokens`) |
| `auto_escalate` | `enabled/on_error/on_low_confidence: true` |
| `cache` | `enabled: true`, `ttl_seconds: 300`, `max_entries: 1000` |
| `respect_client_tokens` | `false` |

---

## `alerts`

| Key | Default |
|-----|---------|
| `enabled` | `false` |
| `telegram.bot_token` / `chat_id` | `""` |
| `webhook.url` | `""` |
| `webhook.headers` | `{}` |
| `notify_on` | `["threat_blocked", "budget_exceeded", "circuit_open"]` |
| `min_severity` | `warning` (`info` \| `warning` \| `critical`) |
| `cooldown_seconds` | `60` |
| `max_per_hour` | `20` |
| `daily_digest_enabled` | `false` |
| `daily_digest_hour` | `9` |

---

## Other sections applied by `load_policy()`

These are normalized in the same load pass (see `_normalize_*` call order in `config.py`): `policy_paths` / `tool_access` rate limits, `cost_controls`, `circuit_breaker`, `behavioral_fingerprint`, `recording`, `flow_xray`, `experiments`, `task_tracking`, `compliance`, `session_risk`, `context_engine`, `otel_export`, `capabilities`, `default_action`, `model_routing`, etc.

<!-- TODO: verify — document every nested key for `context_engine`, `otel_export`, and `capabilities` in the same detail level as above if you need exhaustive reference. -->

---

## Example `policy.yaml`

```yaml
# Minimal proxy + budgets; extend with features you enable in code paths.
proxy:
  host: "127.0.0.1"
  port: 8080
  max_body_size_bytes: 10485760
  ssrf_allow_private: false
  upstream:
    openai: "https://api.openai.com"
    anthropic: "https://api.anthropic.com"
  connection_pool:
    max_total: 50
    max_per_host: 10
    upstream_retry_base_delay_seconds: 0.1
    upstream_retry_max_delay_seconds: 2.0

budgets:
  daily: 50.0
  soft_limit_percent: 80
  on_soft_limit: notify
  on_hard_limit: block

loop_detection:
  enabled: true
  exact:
    threshold: 5
    window_seconds: 120
    action: warn
  fuzzy:
    threshold: 8
    window_seconds: 300
    action: block
  openclaw_reset_commands: ["/start", "/new", "/reset"]

kill_switch:
  enabled: false
  # If enabled: true and token omitted/default, a random resume_token is generated.
  resume_token: "change-me"

threat_intel:
  enabled: true
  default_action: warn
  max_matches_per_request: 10

semantic_cache:
  enabled: false
  max_entries: 1000
  ttl_seconds: 600

cascade:
  enabled: false

alerts:
  enabled: false
```

For more examples, see files under `config/` in the repository.
