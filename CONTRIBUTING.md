# Contributing to Orchesis

Thank you for your interest in contributing to Orchesis!

## Getting Started
```bash
git clone https://github.com/orchesis-security/orchesis.git
cd orchesis
pip install -e ".[dev]"
pytest
```

## Development Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `pytest`
5. Run linter: `ruff check src/ tests/`
6. Commit: `git commit -m "Add my feature"`
7. Push: `git push origin feature/my-feature`
8. Open a Pull Request

## Code Style

- Python 3.11+
- Follow ruff defaults (line length 100)
- Type hints on all public functions
- Docstrings on all public classes and methods

## Testing

Every PR must:
- Pass all existing tests
- Include tests for new functionality
- Maintain or improve test coverage

Run specific test files:
```bash
pytest tests/test_engine.py -v
pytest tests/test_scanner.py -v
```

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
