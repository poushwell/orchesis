## [0.5.0] - 2026-02-28

### Added
- OpenTelemetry-compatible span export
- W3C Trace Context propagation
- Structured JSON logging (replaces print statements)
- Debug mode for `evaluate()` with full rule trace
- Python SDK client with `OrchesisClient`
- `orchesis_guard` decorator for easy integration
- 5 integration examples (basic, MCP, FastAPI, LangChain, CrewAI)
- 9 formal runtime invariants
- Comprehensive documentation suite
- PyPI-ready package metadata with release classifiers
- Policy template pack (`minimal`, `strict`, `mcp_development`, `multi_agent`)
- `orchesis new` project scaffolding command
- `orchesis doctor` environment and policy diagnostics command

### Changed
- Proxy/API operational logging now uses structured JSON format
- Debug trace is available via CLI `--debug` and API `debug: true`
- Release docs and CLI onboarding flow finalized for v0.5.0

## [0.4.0] - 2026-02-28

### Added
- Mutation engine with 7 mutation strategies
- Nightly CI fuzzer pipeline (GitHub Actions)
- Reliability Report generator (markdown + JSON)
- HTTP Control API with token auth
- Event bus with pub/sub
- Webhook notifications with HMAC signing
- Prometheus-compatible metrics endpoint
- `/health` and `/status` endpoints
- CLI: `orchesis serve`, `orchesis reliability-report`

## [0.3.1] - 2026-02-28

### Added
- Synthetic Agent Fuzzer with 7 attack categories
- 7 adversarial scenarios (escalation, budget drain, identity rotation, and others)
- Regression corpus with 14 seeded attack patterns
- Auto-generated regression tests from corpus
- Audit query engine with stats and anomaly detection
- CSV export for external analysis
- CLI: `orchesis fuzz`, `orchesis scenarios`, `orchesis corpus`, `orchesis audit --stats/--anomalies/--export`
- `THREAT_MODEL.md` v2 with formal guarantees table

## [0.3.0] - 2026-02-28

### Added
- Agent Identity Model with trust tiers (BLOCKED->PRINCIPAL)
- Capability-based tool access enforcement
- AgentRegistry loaded from policy YAML
- Per-agent overrides (cost, budget, rate limit)
- Policy versioning with rollback support
- Persistent policy history across runs
- Session-scoped state isolation
- CLI: `orchesis agents`, `policy-history`, `rollback`
- Structured telemetry with `DecisionEvent`
- Deterministic replay engine with forensic CLI
- Policy hot-reload without restart
- Buffered persistence for high-throughput

### Changed
- Evaluation order: `identity_check` runs before all policy rules
- State keys now include `session_id` for finer isolation
- Engine uses dispatch table instead of monolithic `if/elif` rule chain

### Security
- 14 adversarial vulnerabilities fixed (see `docs/THREAT_MODEL.md`)
- Path traversal, SQL bypass, and cost manipulation hardened
- Fail-closed guarantees formalized

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
