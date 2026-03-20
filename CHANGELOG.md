## [0.4.0] — 2026-03-19

### Added
- NLCE Layer 2+3: PAR reasoning, Criticality Control LQR, MRAC, HGT Protocol
- Research Tier 1-3: Carnot, Red Queen, Kolmogorov, Fitness Landscape
- Ecosystem: CASURA AISS v2.0, AABB Benchmark, ARE Framework
- Agent Autopsy MVP - post-mortem session analysis
- Orchesis SDK - Python client (stdlib only)
- System Health Report, Config Validator, Weekly Intelligence Report
- Dashboard: Autopsy modal, Research tab, Ecosystem tab
- 100+ new modules total, 250+ API endpoints

### Tests
- 4038 passing (was 3512 at v0.3.0)
- +526 new tests

## [0.6.0] - 2026-03-01

### Added
- Concurrency torture suite (5000+ concurrent, 10k evals)
- State drift detector with 5 drift types
- Atomic budget enforcement (eliminates race condition)
- Coverage-aware fuzzing with adaptive mode
- Corpus quality metrics and gap analysis
- Docker multi-stage build with non-root user
- Docker Compose (API + proxy + fuzzer services)
- Makefile with 18 targets
- Plugin system with 3 contrib plugins (PII, IP, time window)
- Policy templates (minimal, strict, MCP dev, multi-agent)
- `orchesis new` project scaffolding
- `orchesis doctor` health check
- `orchesis torture` stress test
- `orchesis drift` state drift detection
- Python SDK client with `orchesis_guard` decorator
- OpenTelemetry-compatible span export
- Structured JSON logging
- Debug mode with full evaluation trace
- GitHub templates (issues, PRs, bypass reports)
- `CONTRIBUTING.md`, `DEPLOYMENT.md`
- CI matrix (Python 3.11 + 3.12)

### Changed
- Evaluation order includes `identity_check` first
- Budget checks are atomic under concurrency
- Fuzzer tracks coverage and generates suggestions
- 10 formal invariants (was 9)
- All logging converted to structured JSON

### Fixed
- Budget race condition under concurrent access
- Policy hash computation overhead reduced
- State snapshot overhead in telemetry reduced

### Security
- 14 attack patterns in regression corpus
- 30+ adversarial tests
- 7 adversarial scenarios
- 7 mutation strategies
- Drift detection for runtime anomalies
- Torture-tested with 5000 concurrent evaluations

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

## [0.3.0] — 2026-03-18

### Added — 80+ новых модулей
- NLCE Layer 2: UCI compression, PID v2, Kalman 3×3, Context Crystallinity Ψ
- NLCE Layer 2: PAR reasoning, Criticality Control (LQR), MRAC, HGT Protocol
- Fleet Intelligence: Quorum Sensing, Byzantine Detector, Raft Context, Gossip Protocol
- Fleet Intelligence: Thompson Sampling, Vickrey Auction, Keystone Agent
- Ecosystem: CASURA (AISS v2.0), AABB Benchmark, ARE Framework
- Research: Carnot Efficiency, Red Queen, Fitness Landscape, Kolmogorov Importance
- Platform: Multi-tenant, Policy templates, Backup/restore, Migration tool
- Security: Intent Classifier, Response Analyzer, Tool Call Analyzer, Memory Tracker
- Compliance: Evidence Record, Compliance Checker, ARC Certification
- Dashboard: Dark/light theme, Keyboard shortcuts, Mobile responsive, Ecosystem tab
- API: 200+ endpoints across all subsystems
- CLI: 30+ new commands

### Fixed
- Thread safety audit: 5 race conditions fixed
- Fuzz crashes: format strings, bidi unicode, binary YAML
- Loop detection on real proxy traffic
- audit_export missing from git

### Tests
- 3847 passing (was 2969 at start of day)
- +878 new tests
- 20/20 stress tests passing

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
