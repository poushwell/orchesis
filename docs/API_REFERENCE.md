# API Reference

Orchesis proxy exposes HTTP endpoints for the dashboard, stats, and control plane.

## Base

- **Host** — `127.0.0.1` (default) or configured host
- **Port** — `8080` (default) or `--port`
- **Auth** — None by default; add reverse proxy auth if needed

## Dashboard

| Method | Path | Description |
|--------|------|-------------|
| GET | `/dashboard` | Embedded HTML dashboard |
| GET | `/dashboard/` | Same |

## Dashboard API (JSON)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/dashboard/overview` | Shield metrics, cost timeline, events |
| GET | `/api/dashboard/agents` | Agent DNA profiles |
| GET | `/api/dashboard/timeline` | Cost timeline |

## Flow X-Ray

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/flow/sessions` | List sessions |
| GET | `/api/flow/analyze/{id}` | Session analysis |
| GET | `/api/flow/graph/{id}` | Session graph |
| GET | `/api/flow/patterns` | Pattern counts |

## Experiments (A/B testing)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/experiments` | List experiments |
| GET | `/api/experiments/{id}/results` | Experiment results |
| GET | `/api/experiments/{id}/live` | Live variant stats |
| GET | `/api/tasks/outcomes` | Task outcome distribution |
| GET | `/api/tasks/correlations` | Task correlations & insights |

## Threat Intel

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/threats` | List threat signatures |
| GET | `/api/threats/stats` | Threat stats (scans, matches, blocks) |
| GET | `/api/threats/{id}` | Single threat details |

## Stats (aggregate)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/stats` | Full stats: requests, cost, circuit_breaker, experiments, threat_intel, semantic_cache, context_engine, etc. |

## Sessions

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/sessions` | List recorded sessions |
| GET | `/sessions` | Same |
| GET | `/api/sessions/{id}/export` | Export session (.air) |

## Compliance

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/compliance/summary` | Framework coverage summary |
| GET | `/api/compliance/coverage` | Detailed coverage |
| GET | `/api/compliance/findings` | Recent findings |
| GET | `/api/compliance/report` | Export report (JSON/MD) |

## LLM proxy

| Method | Path | Description |
|--------|------|-------------|
| POST | `/v1/chat/completions` | OpenAI-compatible chat |
| POST | `/v1/completions` | OpenAI completions |
| POST | `/messages` | Anthropic Messages API |

## Error codes

- `200` — success
- `400` — invalid request
- `404` — not found (e.g., experiment/threat disabled)
- `500` — internal error

## Control API (A-T additions)

All endpoints below require `Authorization: Bearer <token>`.

### Overwatch and Teams

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/overwatch/teams` | List team summaries |
| GET | `/api/v1/overwatch/teams/{team_id}` | Team drill-down |
| POST | `/api/v1/overwatch/{agent_id}/team` | Assign agent to team |

### Agent Insights

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/agents/{agent_id}/health` | Agent health score widget payload |
| GET | `/api/v1/agents/graph` | Collaboration graph (nodes/edges) |
| GET | `/api/v1/agents/graph/stats` | Graph density/degree stats |
| GET | `/api/v1/agents/clusters` | Agent interaction clusters |

### Compliance and Evidence

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/compliance/report/{agent_id}` | Structured compliance report |
| GET | `/api/v1/compliance/report/{agent_id}/text` | Text export for audit packs |

### Context and Cache

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/context-budget/stats` | Global context budget degradation stats |
| GET | `/api/v1/context-budget/{session_id}` | Session context budget stats |
| GET | `/api/v1/cache/warm/candidates` | Ranked warming candidates |
| POST | `/api/v1/cache/warm` | Trigger cache warming |
| GET | `/api/v1/cache/warm/report` | Last warming effectiveness report |

### Benchmark and Rate Limits

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/benchmark/cases` | List benchmark dataset cases |
| GET | `/api/v1/benchmark/run/{case_id}` | Execute single benchmark case |
| POST | `/api/v1/benchmark/run-all` | Execute full benchmark suite |
| GET | `/api/v1/benchmark/results` | Latest benchmark run result |
| GET | `/api/v1/rate-limits/status` | Per-agent + global rate limit status |

### Geo and Threat Context

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/geo/classify` | Classify IP risk context |
| POST | `/api/v1/geo/scan-ssrf` | Detect SSRF attempts in payload text |

### Intent and Response Safety

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/intent/classify` | Classify single prompt intent |
| POST | `/api/v1/intent/batch` | Classify conversation messages |
| GET | `/api/v1/intent/stats` | Intent classifier aggregate stats |
| POST | `/api/v1/response/analyze` | Response safety + quality report |
| POST | `/api/v1/response/check-leakage` | Prompt-leakage indicators |
| POST | `/api/v1/response/check-hallucination` | Hallucination signals |

### Prediction and Optimization

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/predict/anomaly` | Predict near-term anomaly likelihood |
| GET | `/api/v1/predict/{agent_id}/warning` | Agent early warning signal |
| GET | `/api/v1/predict/history` | Prediction history |
| POST | `/api/v1/policy/optimize` | Generate policy optimization suggestions |
| GET | `/api/v1/policy/suggestions` | Suggested changes only |
| POST | `/api/v1/policy/apply-suggestion` | Apply selected suggestions to policy payload |
