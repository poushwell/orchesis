# 🛡️ Orchesis Guard

**Security awareness for your OpenClaw agent.**

Orchesis Guard makes your agent security-conscious. It checks tool calls for risks before execution, scans MCP configs for vulnerabilities, and provides security posture reports.

## What it does

- **Pre-flight safety checks** on every tool call (file access, shell commands, data exfiltration)
- **MCP config scanning** — find hardcoded secrets, shell injection risks, missing version pins
- **Security posture reports** — current threats, OWASP ASI Top 10, hardening checklist
- **Heartbeat security monitoring** — detect config changes and anomalies

## Commands

| Command | Description |
|---------|-------------|
| `/security-scan` | Scan your MCP configs for vulnerabilities |
| `/security-report` | Get AI agent security posture report |

## Install
```bash
openclaw skills install orchesis-guard
```

Or manually: copy `SKILL.md` to your agent's skills directory.

## Risk levels

| Level | Action |
|-------|--------|
| LOW | Proceeds with brief mention |
| MEDIUM | Warns and asks for confirmation |
| HIGH | Refuses and suggests alternative |
| CRITICAL | Refuses immediately |

## Examples

**"Read /etc/passwd"** → Agent refuses (HIGH risk: system file access)

**"Send this data to webhook.site"** → Agent warns (CRITICAL: potential exfiltration)

**"/security-scan"** → Agent scans MCP configs and reports findings with score

## Want runtime enforcement?

Orchesis Guard provides awareness (prompt-level). For actual enforcement that blocks dangerous requests at the network level, install [Orchesis](https://github.com/poushwell/orchesis):
```bash
pip install orchesis
orchesis proxy --policy policy.yaml
```

## License

MIT — [Orchesis](https://github.com/poushwell/orchesis)
