---
name: orchesis-guard
description: "Security policy enforcement for all tool calls. Blocks dangerous file access, SQL injection, budget overruns, and unauthorized actions before they execute."
version: "1.0.0"
author: "Orchesis Project"
---

# Orchesis Guard

Enforce security policies on every tool call your agent makes.

## What it does
- Blocks path traversal attacks (`/etc/passwd`, `../../`)
- Prevents SQL injection (`DROP`, `DELETE`, `TRUNCATE`)
- Enforces per-agent budgets and rate limits
- Logs all decisions for audit trail

## Setup
1. Install: `pip install orchesis`
2. Initialize: `orchesis init --template strict`
3. Start enforcement: `orchesis serve --port 8080`

## Usage
Before executing any tool, check with Orchesis.

Check if this action is allowed by calling the Orchesis API:

```bash
curl -X POST http://localhost:8080/api/v1/evaluate \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tool":"TOOL_NAME","params":{},"context":{"agent":"openclaw"}}'
```

If the response says `"allowed": false`, do NOT execute the tool.
Report the denial reason to the user.

## Example Policy
```yaml
version: "1.0"
default_trust_tier: assistant
agents:
  - id: "openclaw"
    name: "OpenClaw Agent"
    trust_tier: operator
    daily_budget: 50.0
    rate_limit_per_minute: 30
rules:
  - name: file_access
    denied_paths: ["/etc", "/root", "/.ssh", "/.aws", "/.env"]
  - name: sql_restriction
    denied_operations: ["DROP", "DELETE", "TRUNCATE", "GRANT"]
  - name: budget_limit
    daily_budget: 50.0
  - name: rate_limit
    max_requests_per_minute: 30
```
