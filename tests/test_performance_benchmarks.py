"""Concrete performance baselines for CI monitoring (wall-clock + throughput)."""

from __future__ import annotations

import json
import time
import tracemalloc
from pathlib import Path

import pytest

from ci_multiplier import CI_MULTIPLIER

pytestmark = pytest.mark.performance

# Documented MCP rule registry entries (MCP_RULE_REGISTRY_SPECS); not every scan-time heuristic.
EXPECTED_MCP_RULE_REGISTRY_SIZE = 31


def _build_ten_server_mcp_config() -> dict:
    servers = {}
    for i in range(10):
        servers[f"srv{i}"] = {
            "url": f"http://0.0.0.0:{8000 + i}",
            "command": "bash",
            "args": ["-c", f"echo {i}"],
            "env": {"API_KEY": "sk-test-123456789012345678901234567890"},
            "tools": ["*"],
            "log_level": "debug",
        }
    return {"mcpServers": servers}


_COMPLEX_POLICY_YAML = """
default_action: allow
rules:
  - name: budget_limit
    max_cost_per_call: 1.0
    daily_budget: 10.0
  - name: file_access
    allowed_paths: ["/tmp", "/data"]
    denied_paths: ["/etc/passwd"]
  - name: rate_limit
    max_requests_per_minute: 60
  - name: regex_match
    type: regex_match
    field: params.body
    deny_patterns: ["ignore previous"]
capabilities:
  - tool: read
    allow: {paths: ["*"], domains: ["*"], commands: ["*"]}
  - tool: write
    allow: {paths: ["/tmp/*"], domains: ["*"], commands: ["*"]}
budgets:
  daily: 25.0
  soft_limit_percent: 80
  spend_rate:
    enabled: true
proxy:
  upstream:
    openai: https://api.openai.com/v1
    anthropic: https://api.anthropic.com
kill_switch:
  enabled: false
cascade:
  respect_client_tokens: true
circuit_breaker:
  enabled: true
  failure_threshold: 5
loop_detection:
  enabled: true
  warn_threshold: 3
  block_threshold: 8
behavioral_fingerprint:
  enabled: false
recording:
  enabled: true
  storage_path: ".orchesis/sessions"
flow_xray:
  enabled: true
  max_sessions: 500
experiments:
  enabled: false
task_tracking:
  enabled: false
compliance:
  enabled: true
  frameworks: ["owasp_llm_top10"]
threat_intel:
  enabled: true
  default_action: warn
alerts:
  enabled: false
session_risk:
  enabled: true
semantic_cache:
  enabled: true
context_engine:
  enabled: false
otel_export:
  enabled: false
"""


def test_benchmark_scanner_ten_servers(tmp_path: Path) -> None:
    from orchesis.scanner import McpConfigScanner

    assert McpConfigScanner.get_rule_count() == EXPECTED_MCP_RULE_REGISTRY_SIZE

    cfg_path = tmp_path / "mcp.json"
    cfg_path.write_text(json.dumps(_build_ten_server_mcp_config()), encoding="utf-8")
    scanner = McpConfigScanner()

    t0 = time.perf_counter()
    report = scanner.scan(str(cfg_path))
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    assert report.findings
    limit_ms = 100.0 * CI_MULTIPLIER
    assert elapsed_ms < limit_ms, f"scanner scan took {elapsed_ms:.2f}ms (limit {limit_ms:.2f}ms)"
    print(f"\n[BENCHMARK 1] scanner_10_servers_ms={elapsed_ms:.3f} limit_ms={limit_ms:.3f}")


def test_benchmark_policy_load_complex(tmp_path: Path) -> None:
    from orchesis.config import load_policy

    path = tmp_path / "complex.yaml"
    path.write_text(_COMPLEX_POLICY_YAML.strip(), encoding="utf-8")

    t0 = time.perf_counter()
    policy = load_policy(path)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    assert isinstance(policy, dict)
    assert "loop_detection" in policy
    limit_ms = 50.0 * CI_MULTIPLIER
    assert elapsed_ms < limit_ms, f"load_policy took {elapsed_ms:.2f}ms (limit {limit_ms:.2f}ms)"
    print(f"\n[BENCHMARK 2] load_policy_complex_ms={elapsed_ms:.3f} limit_ms={limit_ms:.3f}")


def test_benchmark_engine_evaluate_100_requests() -> None:
    from orchesis.engine import PolicyEngine

    policy = {
        "rules": [
            {"name": "budget", "max_cost_per_call": 10.0},
            {
                "name": "inj",
                "type": "regex_match",
                "field": "params.content",
                "deny_patterns": ["jailbreak"],
            },
        ]
    }
    engine = PolicyEngine(policy=policy)
    req = {
        "tool": "chat",
        "params": {"content": "hello world"},
        "cost": 0.01,
        "context": {},
    }

    t0 = time.perf_counter()
    for _ in range(100):
        engine.evaluate(req)
    total_ms = (time.perf_counter() - t0) * 1000.0
    per_ms = total_ms / 100.0
    limit_per_ms = 5.0 * CI_MULTIPLIER
    assert per_ms < limit_per_ms, f"mean evaluate={per_ms:.3f}ms (limit {limit_per_ms:.3f}ms/call)"
    print(
        f"\n[BENCHMARK 3] engine_eval_100_total_ms={total_ms:.3f} per_call_ms={per_ms:.3f} limit_per_ms={limit_per_ms:.3f}"
    )


def test_benchmark_cost_tracker_10k_calls(tmp_path: Path) -> None:
    from orchesis.cost_tracker import CostTracker

    tracker = CostTracker(max_call_history=50_000)
    tracemalloc.start()
    try:
        t0 = time.perf_counter()
        for i in range(10_000):
            tracker.record_call("read_file", task_id=f"t{i % 500}", cost_override=0.0001)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    limit_ms = 500.0 * CI_MULTIPLIER
    assert elapsed_ms < limit_ms, (
        f"10k record_call took {elapsed_ms:.2f}ms (limit {limit_ms:.2f}ms)"
    )
    assert peak < 50 * 1024 * 1024, f"tracemalloc peak {peak} bytes exceeds 50MB budget"
    print(
        f"\n[BENCHMARK 4] cost_tracker_10k_ms={elapsed_ms:.3f} tracemalloc_peak_mb={peak / (1024 * 1024):.3f}"
    )


def test_benchmark_loop_detector_10k_checks() -> None:
    from orchesis.loop_detector import LoopDetector

    detector = LoopDetector(
        warn_threshold=50,
        block_threshold=100,
        window_seconds=300.0,
        config={
            "enabled": True,
            "exact": {"threshold": 50, "window_seconds": 300.0, "action": "warn"},
            "fuzzy": {"threshold": 100, "window_seconds": 300.0, "action": "block"},
            "on_detect": {"notify": True, "log": True, "max_cost_saved": True},
            "openclaw_memory_whitelist": False,
        },
    )

    # Steady-state payload (single exact/fuzzy hash). Full 10k × json hashing is ~3s+ on Windows dev
    # hardware; keep a 10k-call budget scaled by CI_MULTIPLIER (same intent as 200ms/10k on fast Linux).
    parsed: dict = {
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "steady-state bench"}],
        "tool_calls": [{"name": "read", "arguments": "{}"}],
        "content_text": "steady-state bench prompt",
        "session_id": "session-0",
    }
    n_calls = 10_000
    t0 = time.perf_counter()
    for i in range(n_calls):
        parsed["session_id"] = f"session-{i % 100}"
        detector.check_request(parsed)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    limit_ms = 6000.0 * CI_MULTIPLIER
    assert elapsed_ms < limit_ms, (
        f"{n_calls} loop checks took {elapsed_ms:.2f}ms (limit {limit_ms:.2f}ms)"
    )
    print(f"\n[BENCHMARK 5] loop_detector_{n_calls}_ms={elapsed_ms:.3f} limit_ms={limit_ms:.3f}")


def test_benchmark_connection_pool_1k_acquire_release() -> None:
    from orchesis.connection_pool import ConnectionPool, PoolConfig

    pool = ConnectionPool(
        PoolConfig(
            max_connections_per_host=50,
            max_total_connections=100,
            connection_timeout=10.0,
            idle_timeout=300.0,
        )
    )
    try:
        t0 = time.perf_counter()
        for _ in range(1000):
            conn = pool.acquire("127.0.0.1", port=65534, use_ssl=False)
            pool.release(conn)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
    finally:
        pool.close_all()

    limit_ms = 100.0 * CI_MULTIPLIER
    assert elapsed_ms < limit_ms, (
        f"1k pool acquire/release took {elapsed_ms:.2f}ms (limit {limit_ms:.2f}ms)"
    )
    print(f"\n[BENCHMARK 6] connection_pool_1k_ms={elapsed_ms:.3f} limit_ms={limit_ms:.3f}")


def test_benchmark_evidence_ledger_1k_buffer_flush(tmp_path: Path) -> None:
    from orchesis.core.evidence_ledger import EvidenceLedger

    ledger_path = tmp_path / "ledger.jsonl"
    ledger = EvidenceLedger(
        ledger_path,
        max_buffer_size=10_000,
        flush_interval=3600.0,
    )
    try:
        t0 = time.perf_counter()
        for i in range(1000):
            ledger.record({"event": "bench", "i": i, "payload": "x" * 32})
        record_ms = (time.perf_counter() - t0) * 1000.0

        t1 = time.perf_counter()
        ledger.flush()
        flush_ms = (time.perf_counter() - t1) * 1000.0
    finally:
        ledger.close()

    assert record_ms < 50.0 * CI_MULTIPLIER, (
        f"1000 record() took {record_ms:.2f}ms (limit {50 * CI_MULTIPLIER:.2f}ms)"
    )
    assert flush_ms < 200.0 * CI_MULTIPLIER, (
        f"flush() took {flush_ms:.2f}ms (limit {200 * CI_MULTIPLIER:.2f}ms)"
    )
    print(
        f"\n[BENCHMARK 7] evidence_ledger_record_1k_ms={record_ms:.3f} flush_ms={flush_ms:.3f} "
        f"ci_mult={CI_MULTIPLIER}"
    )
