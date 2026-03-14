# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | ✅ Current release |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email: security@orchesis.io

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment:** within 48 hours
- **Initial assessment:** within 5 business days
- **Fix timeline:** depends on severity
  - Critical: patch within 7 days
  - High: patch within 14 days
  - Medium: next minor release
  - Low: next minor release or later

### What to Expect

1. We will acknowledge your report within 48 hours
2. We will provide an initial assessment of the vulnerability
3. We will work with you on a fix and coordinate disclosure
4. We will credit you in the release notes (unless you prefer anonymity)

### Scope

The following are in scope:
- Orchesis proxy core (src/orchesis/)
- CLI commands
- Dashboard web interface
- Configuration parsing
- API endpoints

The following are NOT in scope:
- Upstream LLM provider vulnerabilities
- User misconfiguration
- Denial of service against self-hosted instances

## Security Design Principles

Orchesis is designed with security as a core principle:

1. **Zero external dependencies** — reduces supply chain attack surface to zero
2. **No network calls home** — Orchesis never contacts external servers
3. **No telemetry** — no usage data, no analytics, no tracking
4. **Local-only processing** — all data stays on user's infrastructure
5. **Secrets never logged** — API keys and credentials are filtered from all logs and recordings
6. **Python stdlib only** — no third-party packages means no dependency vulnerabilities

## Disclosure Policy

We follow coordinated disclosure. We ask that you:
- Allow us reasonable time to fix the issue before public disclosure
- Do not exploit the vulnerability beyond what is needed to demonstrate it
- Do not access or modify data belonging to others

We will not take legal action against researchers who follow this policy.

