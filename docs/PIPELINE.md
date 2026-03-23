# LLM proxy pipeline

This document describes the **request handler pipeline** in `LLMHTTPProxy` (`src/orchesis/proxy.py`). Marketing copy sometimes refers to “17 phases”; in code there are **17 named phases** wrapped in `_run_phase_span`, plus **`_phase_parse`** before them and **`_phase_send_response`** after them.

Phases may be **skipped** when a fast-path decision lists them in `skip_phases` (see `_compute_fast_path_skip_phases`); mandatory phases are never skipped.

---

## Text flow

```
HTTP request
    → _phase_parse
    → experiment → flow_xray_record → cascade
    → circuit_breaker → loop_detection → behavioral → adaptive_detection
    → mast_request → auto_healing → budget → policy → threat_intel
    → model_router → secrets → context → upstream → post_upstream
    → _phase_send_response
```

---

## Conceptual groups (README-style)

These groups are **approximate**; some phases span multiple concerns (e.g. `threat_intel` also runs adaptive v2 and session risk evaluation).

| Group | Phases |
|-------|--------|
| Security-ish | `circuit_breaker`, `loop_detection`, `behavioral`, `adaptive_detection`, `mast_request`, `auto_healing`, `policy`, `secrets`, parts of `threat_intel` |
| Context / cost prep | `experiment`, `flow_xray_record`, `cascade`, `budget`, `model_router`, `context` |
| Threat / policy | `policy`, `threat_intel` |
| Upstream | `upstream`, `post_upstream` |
| I/O | `parse`, `send_response` |

---

## Phase reference

### 0. `_phase_parse`

- Reads `Content-Length`, rejects oversized bodies (`proxy.max_body_size_bytes`), parses JSON body, builds `parsed_req`, resolves session id from headers.
- **Configurable:** `proxy.max_body_size_bytes`, body must be JSON object.

### 1. `experiment` — `_phase_experiment`

- If `ExperimentManager` is configured, assigns A/B variant; may override `model` and set `X-Orchesis-Experiment` / `X-Orchesis-Variant` headers.
- **Configurable:** `experiments` policy section (manager wired from policy in proxy `__init__`).

### 2. `flow_xray_record` — `_phase_flow_xray_record`

- Records request into flow analyzer when enabled.
- **Configurable:** `flow_xray` (e.g. `enabled`, `max_sessions`, pattern toggles).

### 3. `cascade` — `_phase_cascade`

- Cascade router classification, optional cache hit short-circuit (still runs loop detection on cache path), may send response early.
- **Configurable:** `cascade` (levels, cache, `respect_client_tokens`, etc.).

### 4. `circuit_breaker` — `_phase_circuit_breaker`

- Blocks with configured fallback status/body when the breaker is open; sets `X-Orchesis-Circuit`.
- **Configurable:** `circuit_breaker` (`error_threshold`, `window_seconds`, `cooldown_seconds`, `fallback_status`, `fallback_message`, …).

### 5. `loop_detection` — `_phase_loop_detection`

- Main loop detector + content-loop detector; OpenClaw reset commands clear history; may block (429) or set loop warning headers; may interact with kill switch.
- **Configurable:** `loop_detection` (`exact`, `fuzzy`, `content_loop`, `openclaw_reset_commands`, …).

### 6. `behavioral` — `_phase_behavioral`

- Behavioral fingerprint / anomaly detection; may block; sets behavior headers when anomalous.
- **Configurable:** `behavioral_fingerprint`.

### 7. `adaptive_detection` — `_phase_adaptive_detection`

- `AdaptiveDetector` scoring; may block (429) or warn; integrates with session risk / community client when configured.
- **Configurable:** `adaptive_detection` (detector toggles, weights, thresholds, actions).

### 8. `mast_request` — `_phase_mast_request`

- MAST request checks; critical findings can block (403) unless auto-healing handles them.
- **Configurable:** `mast`.

### 9. `auto_healing` — `_phase_auto_healing`

- May rewrite `ctx.body` based on MAST / adaptive signals when `AutoHealer` is enabled.
- **Configurable:** `auto_healing`.

### 10. `budget` — `_phase_budget`

- Daily budget via `CostTracker.check_budget`; spend-rate detector; may block or trigger kill switch on cost auto-triggers.
- **Configurable:** `budgets` / `kill_switch.auto_triggers`.

### 11. `policy` — `_phase_policy`

- Per tool call: `ToolPolicyEngine` and `evaluate()` for capabilities; blocks, approval flow (202), or warns.
- **Configurable:** `capabilities`, `default_action`, related policy structures.

### 12. `threat_intel` — `_phase_threat_intel`

- Threat matcher scan; optional `AdaptiveDetectionV2`; session risk evaluation may block (429); applies actions on matches (e.g. block → 403 JSON).
- **Configurable:** `threat_intel`, `adaptive_detection_v2`, `session_risk`.

### 13. `model_router` — `_phase_model_router`

- Heartbeat cheap-model routing, complexity router, Thompson router / Thompson sampling, context router classification.
- **Configurable:** `model_routing`, `thompson_router`, `thompson_sampling`, and related policy keys read in `LLMHTTPProxy.__init__`.

### 14. `secrets` — `_phase_secrets`

- Outbound secret pattern scan on request content; may block or activate kill switch.
- **Configurable:** kill switch / scanning flags wired in proxy init (`_scan_outbound`, etc.).

### 15. `context` — `_phase_context`

- Large chain: injection protocol, apoptosis, context strategy router, context optimizer, cost optimizer, UCI compression, context window optimizer, context budget + compression v2, then `context_engine` if enabled.
- **Configurable:** `injection_protocol`, `apoptosis`, `context_optimizer`, `cost_optimizer`, `uci_compression`, `context_window_optimizer`, `context_budget`, `context_compression_v2`, `context_engine`, `request_prioritizer`, etc.

### 16. `upstream` — `_phase_upstream`

- Plugins, semantic cache lookup/return, forwarding to provider with connection pool and retries.
- **Configurable:** `semantic_cache`, `proxy.connection_pool`, plugins.

### 17. `post_upstream` — `_phase_post_upstream`

- Response plugins, response parsing, secret checks on response, circuit breaker success/failure recording, cascade escalation retry, MAST response checks, telemetry side effects, recording, etc. (long method — see source for full branches).
- **Configurable:** cascade auto-escalate, MAST, recording, plugins.

### 18. `_phase_send_response`

- Sets final headers (`X-Orchesis-*`), writes body (non-streaming) or finalizes streaming path.

---

## Examples

**Early reject (parse):** invalid JSON → `400` with `{"error":"Invalid JSON in request body"}`.

**Loop block:** `429` with `type: loop_detected` or `content_loop_detected` depending on detector.

**Threat block:** `403` with `error: threat_detected` and threat metadata.

For exact status codes and payload shapes, refer to the corresponding `_phase_*` implementation in `proxy.py`.
