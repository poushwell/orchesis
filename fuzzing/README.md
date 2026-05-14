# Orchesis Fuzzing

Fuzzing is an automated robustness testing technique that continuously mutates inputs to exercise unexpected code paths and uncover crashes, hangs, and security bugs that normal unit tests may miss. This directory contains dedicated fuzz harnesses for Orchesis policy parsing, proxy parsing, MCP JSON-RPC handling, secret/PII scanning, and compliance logic.

## Prerequisites

- Python 3.11+ (Atheris works best on Linux)
- Install Atheris:

```bash
pip install atheris
```

Linux/WSL2 is recommended for best coverage and performance.

## Run A Single Harness

```bash
python fuzzing/fuzz_policy_yaml.py -max_total_time=60 fuzzing/seeds/policy_yaml
```

Examples:

```bash
python fuzzing/fuzz_http_proxy.py -max_total_time=60 -dict=fuzzing/dictionaries/http.dict fuzzing/seeds/http_proxy
python fuzzing/fuzz_mcp_jsonrpc.py -max_total_time=60 -dict=fuzzing/dictionaries/jsonrpc.dict fuzzing/seeds/mcp_jsonrpc
```

## Run All Harnesses

```bash
python fuzzing/fuzz_policy_yaml.py -max_total_time=30 fuzzing/seeds/policy_yaml
python fuzzing/fuzz_http_proxy.py -max_total_time=30 -dict=fuzzing/dictionaries/http.dict fuzzing/seeds/http_proxy
python fuzzing/fuzz_mcp_jsonrpc.py -max_total_time=30 -dict=fuzzing/dictionaries/jsonrpc.dict fuzzing/seeds/mcp_jsonrpc
python fuzzing/fuzz_secret_scanner.py -max_total_time=30 fuzzing/seeds/secret_scanner
python fuzzing/fuzz_pii_detector.py -max_total_time=30 fuzzing/seeds/pii_detector
python fuzzing/fuzz_compliance.py -max_total_time=30 fuzzing/seeds/compliance
```

## Reproduce A Crash

When Atheris finds a crash, it writes an artifact (`crash-*` by default). Re-run the harness with that file:

```bash
python fuzzing/fuzz_policy_yaml.py fuzzing/crashes/crash-<hash>
```

## CI Fuzzing

GitHub Actions runs nightly fuzzing via `.github/workflows/fuzz.yml` and can also be triggered manually. The workflow:

- Restores/updates per-target corpus cache
- Seeds initial corpus from `fuzzing/seeds/*`
- Runs each harness for a configurable duration
- Uploads crash artifacts
- Opens an issue automatically if a crash is found

## Add A New Harness

1. Create `fuzzing/fuzz_<target>.py` with Atheris `TestOneInput`.
2. Add target seeds under `fuzzing/seeds/<target>/`.
3. Add optional dictionary under `fuzzing/dictionaries/`.
4. Register target in `.github/workflows/fuzz.yml` matrix and seed mapping.
5. Verify locally with `-max_total_time=10`.

## Atheris Documentation

- https://github.com/google/atheris
