# API Reference

Base path: `/api/v1`  
Auth: `Authorization: Bearer <token>` (except `/status`)

## Endpoints (14)

### Policy Management

1. `POST /api/v1/policy` — upload and activate policy YAML
2. `GET /api/v1/policy` — current policy and metadata
3. `GET /api/v1/policy/history` — policy version history
4. `POST /api/v1/policy/rollback` — rollback to previous version
5. `POST /api/v1/policy/validate` — validate YAML without activation

### Agent Management

6. `GET /api/v1/agents` — list registered agents
7. `GET /api/v1/agents/{agent_id}` — agent details and stats
8. `PUT /api/v1/agents/{agent_id}/tier` — update trust tier

### Status and Monitoring

9. `GET /api/v1/status` — runtime status (no auth)
10. `GET /api/v1/audit/stats` — aggregated audit stats
11. `GET /api/v1/audit/anomalies` — anomaly list
12. `GET /api/v1/audit/timeline/{agent_id}` — agent timeline
13. `GET /api/v1/reliability` — reliability report

### Evaluation

14. `POST /api/v1/evaluate` — remote policy evaluation

## Request/response examples

### `POST /api/v1/evaluate`

Request:

```json
{
  "tool": "read_file",
  "params": {"path": "/data/report.csv"},
  "cost": 0.1,
  "context": {"agent": "cursor", "session": "sess-1"},
  "debug": true
}
```

Response:

```json
{
  "allowed": true,
  "reasons": [],
  "rules_checked": ["budget_limit", "rate_limit", "file_access", "sql_restriction", "regex_match", "context_rules", "composite"],
  "evaluation_us": 42,
  "policy_version": "abc123...",
  "debug_trace": {
    "evaluation_order": ["budget_limit", "rate_limit", "file_access", "sql_restriction", "regex_match", "context_rules", "composite"]
  }
}
```

### `POST /api/v1/policy/validate`

Request:

```json
{"yaml_content": "rules: []"}
```

Response:

```json
{"valid": true, "errors": [], "warnings": []}
```

### `GET /api/v1/agents`

Response:

```json
{
  "agents": [
    {"id": "cursor", "trust_tier": "operator"}
  ],
  "default_tier": "intern"
}
```

## Error codes

- `200` success
- `400` invalid request payload or policy
- `401` unauthorized / missing token
- `404` entity not found (for example agent id)
- `500` unexpected internal error
