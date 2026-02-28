## [0.2.0] - 2026-02-28

### Added
- Stateful rate limiting with sliding window
- Advanced policy rules: `regex_match`, `context_rules`, `composite`
- Agent Harness with deterministic task execution
- Production MCP configs for Cursor and Claude Code
- GitHub Actions CI/CD pipeline
- 30 adversarial security tests
- Formal `THREAT_MODEL.md`

### Changed
- `rate_limit` now fully evaluated (was `not_evaluated`)
- Engine hardened against path traversal, SQL bypass, and cost manipulation

### Fixed
- 14 security vulnerabilities (see `docs/THREAT_MODEL.md`)

## [0.1.0] - 2026-02-28

### Added
- Core policy engine with YAML configuration
- CLI: `init`, `verify`, `validate`, `audit`, `keygen`
- HTTP proxy with FastAPI middleware
- MCP stdio interceptor
- Ed25519 signed audit trail
- Docker packaging
- 51 initial tests
