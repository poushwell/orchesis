# Policy Reference

## Top-level fields

- `version` (optional): policy version label
- `default_trust_tier` (optional): fallback tier for unknown agents
- `agents` (optional): explicit agent registry
- `rules` (required): ordered list of policy rules
- `webhooks` (optional): event notifications
- `api` (optional): control API config

## Rule Types (7)

### 1) `file_access`

```yaml
- name: file_access
  allowed_paths: ["/data", "/tmp"]
  denied_paths: ["/etc", "/root", "/var"]
```

### 2) `sql_restriction`

```yaml
- name: sql_restriction
  denied_operations: ["DROP", "DELETE", "TRUNCATE", "ALTER", "GRANT"]
```

### 3) `budget_limit`

```yaml
- name: budget_limit
  max_cost_per_call: 2.0
  daily_budget: 100.0
```

### 4) `rate_limit`

```yaml
- name: rate_limit
  max_requests_per_minute: 60
```

### 5) `regex_match`

```yaml
- name: command_pattern_guard
  type: regex_match
  field: params.command
  deny_patterns:
    - "(?i)rm\\s+-rf\\s+"
```

### 6) `context_rules`

```yaml
- name: context_rules
  type: context_rules
  rules:
    - agent: "untrusted_bot"
      denied_tools: ["write_file", "delete_file", "run_sql"]
```

### 7) `composite`

```yaml
- name: write_guard
  type: composite
  operator: AND
  conditions:
    - rule: file_access
    - rule: budget_limit
```

## `agents` section

Agent fields:

- `id` (required)
- `name` (required)
- `trust_tier` (`blocked|intern|assistant|operator|principal`)
- `allowed_tools` (optional list)
- `denied_tools` (optional list)
- `max_cost_per_call` (optional float)
- `daily_budget` (optional float)
- `rate_limit_per_minute` (optional int)

Example:

```yaml
default_trust_tier: intern
agents:
  - id: cursor
    name: Cursor IDE Agent
    trust_tier: operator
  - id: blocked_agent
    name: Blocked Agent
    trust_tier: blocked
```

## `webhooks` configuration

```yaml
webhooks:
  - url: "https://example.com/security/webhook"
    events: ["DENY"]
    headers:
      X-Env: prod
    timeout_seconds: 5
    retry_count: 2
    secret: "whsec_..."
```

## API token configuration

```yaml
api:
  token: "orch_sk_prod_..."
```

Control API requires `Authorization: Bearer <token>`.

## Complete `policy.yaml` example

```yaml
version: "0.5.0"
default_trust_tier: intern

api:
  token: "orch_sk_prod_..."

agents:
  - id: cursor
    name: Cursor IDE Agent
    trust_tier: operator
  - id: untrusted_bot
    name: Untrusted Bot
    trust_tier: intern
    denied_tools: ["write_file", "delete_file", "run_sql"]
  - id: blocked_agent
    name: Blocked Agent
    trust_tier: blocked

rules:
  - name: budget_limit
    max_cost_per_call: 2.0
    daily_budget: 100.0

  - name: file_access
    allowed_paths: ["/data", "/tmp"]
    denied_paths: ["/etc", "/root", "/var", "~/.ssh", "~/.aws"]

  - name: sql_restriction
    denied_operations: ["DROP", "DELETE", "TRUNCATE", "ALTER", "GRANT"]

  - name: rate_limit
    max_requests_per_minute: 100

  - name: command_pattern_guard
    type: regex_match
    field: params.command
    deny_patterns:
      - "(?i)rm\\s+-rf\\s+"
      - "(?i)chmod\\s+777\\s+"

  - name: context_limits
    type: context_rules
    rules:
      - agent: "*"
        max_cost_per_call: 2.0

  - name: write_guard
    type: composite
    operator: AND
    conditions:
      - rule: file_access
      - rule: budget_limit

webhooks:
  - url: "https://example.com/orchesis-events"
    events: ["DENY"]
    secret: "whsec_..."
```
