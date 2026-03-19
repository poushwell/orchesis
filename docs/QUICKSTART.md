# Quick Start

Get Orchesis running in 3 commands.

## Install

```bash
pip install orchesis
```

## Initialize

```bash
orchesis init
```

Creates `policy.yaml` and starter config.

## Run the proxy

```bash
orchesis proxy --port 8080
```

Point your AI agent at `http://localhost:8080` as the LLM API base URL. Orchesis transparently proxies to OpenAI, Anthropic, or your configured upstream.

## Dashboard

Open `http://localhost:8080/dashboard` for the embedded control plane:

- Shield Overview — status, cost, circuit breaker
- Agents — behavioral DNA
- Sessions — Time Machine
- Flow X-Ray — conversation topology
- Experiments — A/B testing
- Threats — threat intel
- Cache — semantic cache + context engine
- Compliance — OWASP/NIST coverage

## 5-minute checklist

1. `pip install orchesis`
2. `orchesis init`
3. Edit `policy.yaml` (optional: add rules, budgets, threat_intel)
4. `orchesis proxy --port 8080`
5. Point your agent at `http://localhost:8080`
6. Open `/dashboard` to monitor

## Useful commands

```bash
# Check system status
orchesis status

# Create backup
orchesis backup

# Run benchmark
orchesis benchmark --run-all

# Export evidence record
orchesis evidence --session SESSION_ID

# AABB benchmark
orchesis aabb --leaderboard
orchesis aabb --run-agent AGENT_ID

# ARC certification
orchesis arc-check --agent AGENT_ID --min-score 75
orchesis arc-certify --agent AGENT_ID

# NLCE paper
orchesis nlce-paper --generate --output paper/
orchesis arxiv-validate --paper paper/

# Policy spec
orchesis spec --validate orchesis.yaml
orchesis diff policy_v1.yaml policy_v2.yaml
orchesis migrate --config orchesis.yaml

# Vibe Code Audit
orchesis vibe-audit --file app.py
```
