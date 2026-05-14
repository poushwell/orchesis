# PHASE0: Orchesis Core v0.1

This phase delivers a minimal local kernel for deterministic rule-based verification.
The engine works in isolation (no HTTP, no MCP, no network side effects).

## Scope

- Pure Python kernel for policy-based request verification
- YAML policy loading and validation
- Rule evaluation (`budget_limit`, `file_access`, `sql_restriction`, `rate_limit`)
- JSONL decision logging
- Click CLI commands (`init`, `verify`, `validate`, `audit`)

## Out Of Scope

- MCP integration
- HTTP/FastAPI/networking
- LLM or multi-agent behavior in kernel
- Cryptography/signing/publishing/UI

## Project Structure

```text
orchesis/
├── src/orchesis/
│   ├── __init__.py
│   ├── config.py
│   ├── engine.py
│   ├── models.py
│   ├── logger.py
│   └── cli.py
├── tests/
├── docs/PHASE0.md
├── examples/policy.yaml
├── examples/request.json
├── pyproject.toml
└── .gitignore
```

## Data Model

`Decision` contains:
- `allowed: bool`
- `reasons: list[str]`
- `rules_checked: list[str]`
- `timestamp: str` (UTC ISO8601)

## Local Setup

```bash
python -m pip install -e .[dev]
```

## CLI Usage

### 1) Initialize example files

```bash
orchesis init
```

Expected output:

```text
Created policy.yaml and request.json. Edit them, then run: orchesis verify
```

Creates in current directory:
- `policy.yaml`
- `request.json`

### 2) Validate policy

```bash
orchesis validate --policy policy.yaml
```

Expected:
- `OK` for valid policy
- list of validation errors for invalid policy (exit code `1`)

### 3) Verify request against policy

```bash
orchesis verify request.json --policy policy.yaml
```

Behavior:
- Prints `Decision` as formatted JSON
- Appends one line to `decisions.jsonl`
- Exit code `0` when decision is `ALLOW`
- Exit code `1` when decision is `DENY`

### 4) Audit decision log

```bash
orchesis audit --limit 20
orchesis audit --since 24 --limit 10
```

Output includes:
- Total ALLOW count
- Total DENY count
- Top 3 deny reasons
- Last N decisions

## Decision Log Format

Each `verify` call appends one JSON object line to `decisions.jsonl`, for example:

```json
{"timestamp":"2026-03-01T14:30:00+00:00","tool":"sql_query","decision":"DENY","reasons":["sql_restriction: DROP is denied"],"rules_checked":["budget_limit","file_access","sql_restriction"],"cost":0.1}
```

## Quality Gates

Run before moving to next phase:

```bash
ruff check .
pytest
```
