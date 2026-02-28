# Contributing to Orchesis

## Getting Started
```bash
git clone https://github.com/YOUR_USERNAME/orchesis.git
cd orchesis
pip install -e .[dev]
pytest
```

## Development Workflow

1. Fork the repo
2. Create a feature branch
3. Write tests first (TDD)
4. Implement the feature
5. Run full test suite: `pytest`
6. Run linter: `ruff check .`
7. Run invariants: `orchesis invariants --policy examples/production_policy.yaml`
8. Submit PR

## Code Standards

- Python 3.11+
- Line length: 99 chars
- All new code must have tests
- No new dependencies without discussion
- Backward compatible (existing tests must pass)

## Testing
```bash
make test          # Full test suite
make fuzz          # Synthetic fuzzer
make invariants    # Formal invariants
make scenarios     # Adversarial scenarios
```

## Adding a Plugin

1. Create `src/orchesis/contrib/your_plugin.py`
2. Implement `RuleHandler` protocol
3. Add tests in `tests/test_plugins.py`
4. Document in policy reference

## Adding to Attack Corpus

Found a bypass? Great!

1. Run: `orchesis fuzz --save-bypasses`
2. Or manually create `tests/corpus/BYPASS-NNN.json`
3. Run: `orchesis corpus --generate-tests`
4. Submit PR with the corpus entry

## Reporting Security Issues

See [SECURITY.md](docs/SECURITY.md).  
Do NOT open public issues for security vulnerabilities.
