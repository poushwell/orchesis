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
