# Orchesis Production Stress Testing Suite (T1-A)

Production-grade stress suite for pre-launch hardening and article evidence.

This suite validates the proxy under:
- sustained concurrent load,
- adversarial traffic under pressure,
- memory/runtime stability,
- failure and recovery behavior.

It is self-contained (no real LLM key required): `run_all.py` starts a mock upstream and a local Orchesis proxy.

## Directory Layout

- `run_all.py` — master runner (`--quick`, `--scenario s01`)
- `scenarios/` — `s01`..`s08` scenario implementations
- `lib/mock_upstream.py` — configurable OpenAI-compatible upstream simulator
- `lib/traffic_generator.py` — concurrent traffic and attack mix driver
- `lib/metrics_collector.py` — RSS/CPU sampling
- `lib/report_generator.py` — markdown/json reports
- `results/` — generated artifacts (`report.md`, `report.json`)

## Scenarios

- `s01` 50 concurrent agents
- `s02` sustained throughput (target profile ~1000 req/min in full mode)
- `s03` memory stability over long run
- `s04` adversarial traffic under load
- `s05` cascade failure and recovery
- `s06` heartbeat storm protection
- `s07` budget race/thread-safety
- `s08` policy hot-reload under traffic

## Running

From repository root:

```bash
python stress-test/run_all.py --quick
python stress-test/run_all.py --scenario s01
python stress-test/run_all.py
```

Windows PowerShell:

```powershell
.\.venv\Scripts\python.exe stress-test/run_all.py --quick
```

## Quick vs Full Mode

- `--quick`: short smoke validation (durations reduced, local-dev friendly)
- full mode: pre-launch runtime profile (longer durations, heavier evidence)

Use quick mode for CI/dev iteration, and full mode for final launch verification.

## Report Artifacts

Generated files:
- `stress-test/results/report.md` — human-readable report
- `stress-test/results/report.json` — machine-readable payload

Report summary includes:
- scenario pass/fail status,
- key latency or resilience metric,
- per-scenario details (counts, rates, memory growth, phase breakdown),
- latency histogram (ASCII) when available.

## PASS/FAIL Interpretation

- PASS means scenario met its configured criteria in the current mode.
- FAIL means at least one criterion was not met; inspect scenario details in `report.md`/`report.json`.
- Quick criteria are intentionally practical for local environments; full-mode criteria are stricter for launch sign-off.

## Notes for T1-A Article

- Runs are deterministic enough for reproducible screenshots/tables.
- `report.json` is suitable for post-processing into charts.
- Recommended publication flow:
  1) run `--quick` locally for iteration,
  2) run full mode on target environment,
  3) publish metrics and scenario notes from `report.md`.

## Legacy Adversarial Matrix

Older framework-specific scripts (`openclaw/`, `crewai/`, `langgraph/`, `openai_agents/`, `run_all.sh`, `run_all.ps1`) are kept for compatibility, but the canonical pre-launch harness for T1-A is `run_all.py` + `scenarios/`.
