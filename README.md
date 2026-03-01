# 🛡️ Orchesis

AI Agent Security Runtime — Policy enforcement for autonomous AI agents

Orchesis is an open-source, agent-agnostic security runtime that enforces policies on AI agent tool calls in real time. It sits between your agent and its tools, blocking dangerous actions before they execute.

Built for the agentic AI era: OpenClaw, NanoBot, PicoClaw, ZeroClaw, LangChain, CrewAI, MCP servers — any agent that calls tools.

Show Image  
Show Image  
Show Image

## Why Orchesis

30,000+ OpenClaw instances were found exposed on the public internet with no authentication. 800+ malicious skills discovered in ClawHub stealing credentials. CVE-2026-25253 enabled one-click remote code execution. Infostealers now target AI agent config files.

AI agents have the keys to your kingdom — terminal, files, email, APIs, databases. Orchesis ensures they only do what your policy allows.

What makes Orchesis different:

- Agent-agnostic — works with any agent framework, not locked to one vendor
- Policy-as-code — YAML policies, git-friendly, reviewable, auditable
- Full lifecycle — scan → enforce → monitor → forensics → comply
- Open source — MIT license, self-hosted, your data stays yours

## Quickstart

```bash
pip install orchesis

# Scan your MCP configs for vulnerabilities
orchesis scan --mcp

# Scan a skill before installing
orchesis scan path/to/SKILL.md

# Initialize a policy
orchesis init --template strict

# Start enforcement
orchesis serve --policy policy.yaml

# Check compliance
orchesis compliance all
```

### Example: scan --mcp output

```text
$ orchesis scan --mcp

Discovered MCP configs:
  ~/.cursor/mcp.json (3 servers)
  ~/.config/claude/claude_desktop_config.json (2 servers)

Scanning ~/.cursor/mcp.json...
  [CRITICAL] binding_exposure   server "my-tools": binds to 0.0.0.0:8080
  [HIGH]     no_auth            server "db-query": no authentication configured
  [MEDIUM]   dangerous_tools    server "my-tools": shell_execute enabled

Risk Score: 85/100 (HIGH)
Recommendation: Bind to 127.0.0.1 and enable authentication immediately.
```

### Example: compliance output

```text
$ orchesis compliance all

Framework       Score   Pass  Fail  Partial
──────────────────────────────────────────
HIPAA           87.5%   7     0     1
SOC2            71.4%   5     1     1
EU AI Act       80.0%   4     0     1
NIST AI RMF     75.0%   3     1     0

Overall: 78.5%
Top recommendations:
  1. Enable pii_detector plugin
  2. Configure alert recipients
  3. Add adversarial test coverage
```

## Features

### 🔒 Policy Engine

Define what your agents can and cannot do in simple YAML:

```yaml
version: "1.0"
default_trust_tier: assistant

tool_access:
  mode: allowlist
  default: deny
  allowed:
    - read_file
    - web_search
    - send_message

agents:
  - id: "my-agent"
    trust_tier: operator
    daily_budget: 50.0
    rate_limit_per_minute: 30

rules:
  - name: file_access
    denied_paths: ["/etc", "/root", "~/.ssh", "~/.aws", ".env"]
  - name: sql_restriction
    denied_operations: ["DROP", "DELETE", "TRUNCATE"]

session_policies:
  group:
    trust_tier: intern
    tool_access:
      mode: allowlist
      allowed: ["web_search", "send_message"]
  dm:
    trust_tier: assistant
  background:
    trust_tier: intern
    budget_per_session: 0.50
```

### 🔍 Security Scanner

Static analysis for skills, MCP configs, and policies:

```bash
# Scan a skill for malicious patterns
orchesis scan skill.md

# Auto-discover and scan all MCP configs
orchesis scan --mcp

# Scan your policy for weaknesses
orchesis scan policy.yaml

# Check against known IoC database (ClawHavoc, CVE-2026-25253, etc.)
orchesis ioc scan path/to/file
```

### 🔑 Secret & PII Detection

Blocks credential leaks and PII exposure in real time:

```bash
# Detects in tool call params: API keys, tokens, passwords,
# database URLs, private keys, SSNs, credit cards, and more
# Auto-redacts sensitive data in audit logs
```

Detected patterns: OpenAI keys, Anthropic keys, AWS credentials, GitHub tokens, Stripe keys, PostgreSQL/MySQL/MongoDB URLs, JWT tokens, SSH private keys, SSNs, credit card numbers, IBANs, and 20+ more.

### 🚨 Real-Time Alerts

```yaml
# Add to policy.yaml
alerts:
  slack:
    webhook_url: "https://hooks.slack.com/services/T.../B.../xxx"
    notify_on: ["DENY", "ANOMALY"]
  telegram:
    bot_token: "123456:ABC-DEF..."
    chat_id: "-100123456789"
    notify_on: ["DENY"]
```

### 🔬 Incident Forensics

```bash
# View recent incidents
orchesis incidents --since 24h

# Generate incident report
orchesis incidents report --format md --output report.md

# Check agent risk score
orchesis incidents risk my-agent

# View attack timeline
orchesis incidents timeline --last 50
```

### ✅ Compliance Reports

```bash
# Check specific framework
orchesis compliance hipaa --output hipaa-report.md

# Check all frameworks at once
orchesis compliance all

# Supported: hipaa, soc2, eu_ai_act, nist_ai_rmf
```

### 📦 Policy Marketplace

```bash
# List available policy packs
orchesis marketplace

# Install a pack
orchesis marketplace install hipaa --merge

# Available packs: hipaa, soc2, openclaw-secure, development
```

### 🛡️ IoC Database

Known attack patterns from real incidents:

```bash
# List all known indicators of compromise
orchesis ioc list

# Scan against ClawHavoc, credential harvesters, prompt injection, etc.
orchesis ioc scan path/to/skill.md

# Get details on specific IoC
orchesis ioc info CLAWH-001
```

### 🚪 CI/CD Gate

```bash
# Use in GitHub Actions / GitLab CI
orchesis gate --policy policy.yaml --fail-on high --report gate-report.json
# Exit code 0 = PASS, 1 = FAIL, 2 = ERROR
```

GitHub Actions example:

```yaml
- name: Orchesis Security Gate
  run: |
    pip install orchesis
    orchesis gate --policy policy.yaml --fail-on high
```

## Architecture

```text
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│  AI Agent    │────▶│   Orchesis    │────▶│    Tools      │
│ (any agent)  │     │  Policy Gate  │     │ (file, shell, │
└─────────────┘     │              │     │  API, DB...)   │
                    │  ✓ Allow     │     └──────────────┘
                    │  ✗ Deny      │
                    │  ⚠ Alert     │──────▶ Slack/Telegram
                    │  📝 Log      │──────▶ decisions.jsonl
                    └──────────────┘
```

## Integrations

| Integration | Status | Description |
|---|---|---|
| OpenClaw | ✅ Ready | Skill + example policy |
| Slack | ✅ Ready | Real-time DENY/anomaly alerts |
| Telegram | ✅ Ready | Real-time DENY alerts |
| Prometheus | ✅ Ready | Metrics endpoint |
| MCP Servers | ✅ Scanner | Config vulnerability scanning |
| LangChain | 🔜 Coming | Callback handler |
| CrewAI | 🔜 Coming | Multi-agent guardrails |
| Kubernetes | 🔜 Coming | Helm chart + operator |

## Comparison

| Feature | Orchesis | SecureClaw | mcp-scan | Lakera | IronClaw |
|---|---|---|---|---|---|
| Runtime enforcement | ✅ | ❌ audit only | ❌ scan only | ✅ prompts only | ✅ single agent |
| Agent-agnostic | ✅ | ❌ OpenClaw | ❌ MCP only | ✅ | ❌ NEAR AI |
| Policy-as-code | ✅ YAML | ❌ | ❌ | ❌ | ❌ |
| Tool allowlist | ✅ | ❌ | ❌ | ❌ | ✅ |
| Compliance reports | ✅ 4 frameworks | ❌ | ❌ | ❌ | ❌ |
| Secret scanning | ✅ | ❌ | ❌ | ✅ | ✅ |
| PII detection | ✅ | ❌ | ❌ | ✅ | ❌ |
| IoC database | ✅ | ✅ | ❌ | ❌ | ❌ |
| Open source | ✅ MIT | ✅ | ✅ | ❌ | Partial |
| Self-hosted | ✅ | ✅ | ✅ | ❌ | ❌ |

## Project Stats

- 546 tests passing (unit, integration, adversarial, fuzzing)
- 4 compliance frameworks (HIPAA, SOC2, EU AI Act, NIST AI RMF)
- 4 policy marketplace packs (hipaa, soc2, openclaw-secure, development)
- 20+ secret patterns detected
- 15+ PII patterns detected
- 6 IoC categories from real-world incidents
- Zero external dependencies for core engine (stdlib only)

## Documentation

- Policy Reference — Full policy YAML syntax
- Scanner Guide — How to scan skills, MCP configs, policies
- Compliance Guide — Framework-specific guidance
- Integration Guide — Connect Orchesis to your agent
- IoC Database — Known attack patterns

## Contributing

Contributions welcome! See `CONTRIBUTING.md` for guidelines.

Priority areas:

- New policy marketplace packs (industry-specific)
- Agent framework integrations (LangChain, CrewAI, AutoGen)
- IoC database updates (new attack patterns)
- Compliance framework additions

## License

MIT License. See `LICENSE` for details.
