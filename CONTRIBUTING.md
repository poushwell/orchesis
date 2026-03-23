# Contributing to Orchesis

Thank you for your interest in contributing to Orchesis!

## Getting Started
```bash
git clone https://github.com/poushwell/orchesis.git
cd orchesis
pip install -e ".[dev]"
pip install -e ".[all]"   # optional: YAML + HTTP client + server stack for integration tests
```

## Development Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `python -m pytest tests/ -q` (or `pytest` for full output)
5. Run linter: `ruff check src/ tests/`
6. Commit: `git commit -m "Add my feature"`
7. Push: `git push origin feature/my-feature`
8. Open a Pull Request

## Code Style

- Python 3.10+ (see `requires-python` in `pyproject.toml`)
- Follow ruff defaults (line length 100)
- Type hints on all public functions
- Docstrings on all public classes and methods

## Testing

Every PR must:
- Pass all existing tests
- Include tests for new functionality
- Maintain or improve test coverage

Full suite (quiet):

```bash
python -m pytest tests/ -q
```

Run specific test files:
```bash
pytest tests/test_engine.py -v
pytest tests/test_scanner.py -v
```

## Adding a new MCP scanner check

MCP config scanning lives in `src/orchesis/scanner.py` (for example `McpConfigScanner` and related helpers). New checks are usually implemented as:

1. A private method such as `_check_your_risk(self, name: str, server: dict, findings: list[ScanFinding]) -> None` that appends `ScanFinding` entries with `severity`, `category`, `description`, `location`, and `evidence`.
2. A call from the main `scan()` path (per-server loop or cross-server pass) so the check runs for relevant configs.

Add or extend tests under `tests/` that load fixture JSON and assert on findings (see existing `test_scanner.py` patterns).

## Adding a new proxy pipeline phase

The LLM proxy request lifecycle is orchestrated in `LLMHTTPProxy` in `src/orchesis/proxy.py`:

1. Add a `_phase_your_phase(self, ctx: _RequestContext) -> bool` method (return `False` to abort the request and send an error response from that phase).
2. Register it in the main handler after `_phase_parse`, using `_run_phase_span(ctx, "your_phase", self._phase_your_phase)` so tracing stays consistent.
3. Respect `ctx.skip_phases` / fast-path semantics if the phase is optional (see `_compute_fast_path_skip_phases` and `_fast_path_mandatory_phases`).
4. Add tests under `tests/` (often `test_proxy.py` or a focused module) covering allow/block paths and policy wiring.

Document new policy keys in `src/orchesis/config.py` if the phase needs validated configuration (`_normalize_*` in `load_policy()`).

## Adding a Plugin

1. Create `src/orchesis/contrib/your_plugin.py`
2. Add tests for the plugin behavior
3. Document configuration and usage in docs

## Priority Contribution Areas

### Policy Marketplace Packs
Create new policy packs for specific industries:
- Financial services (PCI-DSS, SOX)
- Government (FedRAMP, FISMA)
- Education (FERPA, COPPA)

Location: `src/orchesis/marketplace/packs/`  
Format: YAML (see existing packs for examples)

### Agent Framework Integrations
- LangChain callback handler
- CrewAI middleware
- AutoGen guardrails
- Vercel AI SDK middleware

### IoC Database Updates
Add new attack patterns as they're discovered:
- New malicious skill patterns
- New CVEs affecting AI agents
- New infostealer targeting patterns

Location: `src/orchesis/contrib/ioc_database.py`

### Compliance Frameworks
Add checks for additional frameworks:
- PCI-DSS
- ISO 27001
- GDPR
- CCPA

Location: `src/orchesis/compliance.py`

## Reporting Security Issues

Please report security vulnerabilities via email to security@orchesis.dev  
Do NOT open public issues for security vulnerabilities.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
