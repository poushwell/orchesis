"""Stress and edge-case tests (load, concurrency, malformed HTTP-ish inputs)."""

from __future__ import annotations

import asyncio
import json
import os
import threading
import time
import tracemalloc
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from orchesis.behavioral import BehavioralDetector
from orchesis.connection_pool import ConnectionPool, ConnectionPoolExhausted, PoolConfig
from orchesis.core.evidence_ledger import EvidenceLedger
from orchesis.cost_tracker import CostTracker
from orchesis.demo_backend import app as demo_backend
from orchesis.loop_detector import ContentLoopDetector, LoopDetector
from orchesis.proxy import create_proxy_app
from orchesis.scanner import McpConfigScanner


def _scanner_time_limit() -> float:
    return 25.0 if os.environ.get("CI") else 5.0


@pytest.mark.stress
@pytest.mark.slow
def test_stress_scanner_100_servers(tmp_path: Path) -> None:
    """Scan config with 100 MCP servers, each with several misconfigs."""
    servers: dict[str, dict] = {}
    for i in range(100):
        servers[f"server_{i}"] = {
            "command": "npx",
            "args": [
                "-y",
                "@modelcontextprotocol/server-filesystem@0.1.0",
                "/",
            ],
            "env": {
                "API_KEY": "sk-hardcoded-secret",
                "OPENAI_API_KEY": "sk-test",
            },
            "dangerouslySkipPermissions": True,
        }
    cfg = {"mcpServers": servers}
    p = tmp_path / "big_mcp.json"
    p.write_text(json.dumps(cfg), encoding="utf-8")

    tracemalloc.start()
    t0 = time.perf_counter()
    report = McpConfigScanner().scan(str(p))
    elapsed = time.perf_counter() - t0
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert elapsed < _scanner_time_limit(), f"scan too slow: {elapsed:.2f}s"
    assert len(report.findings) > 0
    assert peak < 400 * 1024 * 1024, f"peak traced memory high: {peak / 1e6:.1f} MB"


@pytest.mark.stress
@pytest.mark.slow
def test_stress_scanner_concurrent_scans(tmp_path: Path) -> None:
    """Several concurrent scans of the same config (read-only file)."""
    servers = {
        f"c{i}": {
            "command": "uvx",
            "args": ["mcp-remote"],
            "env": {"TOKEN": "secret"},
        }
        for i in range(20)
    }
    p = tmp_path / "conc.json"
    p.write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")

    errors: list[BaseException] = []

    def _run() -> int:
        try:
            r = McpConfigScanner().scan(str(p))
            return len(r.findings)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)
            return -1

    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = [pool.submit(_run) for _ in range(10)]
        counts = [f.result() for f in as_completed(futures)]

    assert not errors, errors
    assert all(c > 0 for c in counts)


@pytest.mark.stress
@pytest.mark.slow
def test_stress_cost_tracker_100k_calls() -> None:
    """Record many calls; in-memory history must stay bounded."""
    max_hist = 5000
    ct = CostTracker(max_call_history=max_hist, max_tasks=100, max_days=30)
    for i in range(100_000):
        ct.record_call("read_file", task_id=f"t{i % 50}")
    with ct._lock:  # noqa: SLF001
        assert len(ct._calls) <= max_hist


@pytest.mark.stress
@pytest.mark.slow
def test_stress_cost_tracker_concurrent() -> None:
    """Concurrent recordings remain consistent and bounded."""
    ct = CostTracker(max_call_history=2000, max_tasks=200, max_days=7)
    n_threads = 50
    per_thread = 400

    def worker() -> None:
        for i in range(per_thread):
            ct.record_call("shell_execute", task_id=f"tid-{threading.get_ident()}-{i}")

    threads = [threading.Thread(target=worker) for _ in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    with ct._lock:  # noqa: SLF001
        assert len(ct._calls) <= 2000
    assert ct.get_daily_total() > 0


@pytest.mark.stress
@pytest.mark.slow
def test_stress_loop_detector_10k_sessions() -> None:
    """Many session scopes: last-hash map must respect max_sessions."""
    max_sess = 200
    det = ContentLoopDetector(max_sessions=max_sess, window_seconds=3600, max_identical=50)
    for i in range(10_000):
        det.check(f"msg-{i}", session_id=f"sess-{i}")
    with det._lock:  # noqa: SLF001
        assert len(det._last_hash_by_session) <= max_sess


@pytest.mark.stress
@pytest.mark.slow
def test_stress_loop_detector_rapid_same_content() -> None:
    """Identical logical requests should trip exact loop detection quickly."""
    det = LoopDetector(
        config={
            "enabled": True,
            "exact": {"threshold": 3, "window_seconds": 300.0, "action": "block"},
            "fuzzy": {"threshold": 99, "window_seconds": 300.0, "action": "warn"},
        }
    )
    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "same"}],
        "tool_calls": [],
        "content_text": "same",
    }
    blocked = False
    for i in range(10):
        decision = det.check_request(payload)
        if decision.action == "block":
            blocked = True
            assert i < 9
            break
    assert blocked


@pytest.mark.stress
@pytest.mark.slow
def test_stress_behavioral_5k_agents() -> None:
    """More agents than max_agents: eviction keeps map bounded (~80% trim batches)."""
    max_agents = 200
    det = BehavioralDetector(
        {
            "enabled": True,
            "learning_window": 1,
            "error_window_size": 5,
        },
        max_agents=max_agents,
    )
    base = {"model": "m", "messages": [], "tools": [], "estimated_cost": 0.01, "headers": {}}
    for i in range(5000):
        det.check_request(f"agent-{i}", base)
    with det._lock:  # noqa: SLF001
        assert len(det._agents) <= int(max_agents * 1.2) + 5


@pytest.mark.stress
@pytest.mark.slow
def test_stress_pool_exhaust_and_recover() -> None:
    """Pool at capacity raises until a connection is released."""
    cfg = PoolConfig(
        max_connections_per_host=2,
        max_total_connections=2,
        connection_timeout=0.4,
        idle_timeout=300.0,
    )
    pool = ConnectionPool(cfg)
    a = pool.acquire("127.0.0.1", port=9, use_ssl=False)
    b = pool.acquire("127.0.0.1", port=9, use_ssl=False)
    with pytest.raises(ConnectionPoolExhausted):
        pool.acquire("127.0.0.1", port=9, use_ssl=False)
    pool.release(a, error=True)
    c = pool.acquire("127.0.0.1", port=9, use_ssl=False)
    pool.release(b, error=True)
    pool.release(c, error=True)


@pytest.mark.stress
@pytest.mark.slow
def test_stress_ledger_10k_events(tmp_path: Path) -> None:
    """Buffered ledger: records persist and chain verifies after flush."""
    path = tmp_path / "ledger.jsonl"
    led = EvidenceLedger(
        path,
        max_buffer_size=500,
        flush_interval=300.0,
    )
    for i in range(10_000):
        led.record({"kind": "stress", "i": i, "payload": "x"})
    led.flush()
    led.close()
    text = path.read_text(encoding="utf-8")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    assert len(lines) == 10_000
    led2 = EvidenceLedger(path, max_buffer_size=10, flush_interval=0.0)
    assert led2.verify_chain() is True
    led2.close()


# --- Edge cases via FastAPI TestClient (middleware must not crash) ---


@pytest.fixture
def stress_proxy_client() -> TestClient:
    policy = {"rules": [{"name": "budget_limit", "max_cost_per_call": 10.0}]}
    app = create_proxy_app(policy=policy, backend_app=demo_backend)
    return TestClient(app)


@pytest.mark.stress
@pytest.mark.slow
def test_edge_empty_request_body(stress_proxy_client: TestClient) -> None:
    r = stress_proxy_client.post(
        "/execute", content=b"", headers={"Content-Type": "application/json"}
    )
    assert r.status_code in {200, 403, 422}


@pytest.mark.stress
@pytest.mark.slow
def test_edge_binary_request_body(stress_proxy_client: TestClient) -> None:
    r = stress_proxy_client.post(
        "/execute",
        content=b"\x00\x01\xff\xfe",
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code in {200, 403, 422}


@pytest.mark.stress
@pytest.mark.slow
def test_edge_unicode_bom_in_request(stress_proxy_client: TestClient) -> None:
    body = "\ufeff" + json.dumps({"action": "run_sql", "params": {"query": "SELECT 1"}})
    r = stress_proxy_client.post(
        "/execute",
        content=body.encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code in {200, 403, 422}


@pytest.mark.stress
@pytest.mark.slow
def test_edge_null_bytes_everywhere(stress_proxy_client: TestClient) -> None:
    r = stress_proxy_client.get(
        "/data",
        headers={
            "x-orchesis-session-id": "ab\x00cd",
            "User-Agent": "x\x00y",
        },
    )
    assert r.status_code in {200, 403, 400}


@pytest.mark.stress
@pytest.mark.slow
def test_edge_extremely_long_session_id(stress_proxy_client: TestClient) -> None:
    sid = "s" * 100_000
    r = stress_proxy_client.get("/data", headers={"x-orchesis-session-id": sid})
    assert r.status_code == 200


@pytest.mark.stress
@pytest.mark.slow
def test_edge_negative_content_length(stress_proxy_client: TestClient) -> None:
    transport = httpx.ASGITransport(app=stress_proxy_client.app, raise_app_exceptions=False)

    async def _run() -> int:
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/execute",
                headers={"Content-Length": "-1", "Content-Type": "application/json"},
                content=b"{}",
            )
            return resp.status_code

    code = asyncio.run(_run())
    assert code in {200, 400, 403, 422}


@pytest.mark.stress
@pytest.mark.slow
def test_edge_zero_content_length(stress_proxy_client: TestClient) -> None:
    r = stress_proxy_client.post(
        "/execute",
        headers={"Content-Length": "0", "Content-Type": "application/json"},
        content=b'{"action":"run_sql","params":{"query":"SELECT 1"}}',
    )
    assert r.status_code in {200, 403, 422}


@pytest.mark.stress
@pytest.mark.slow
def test_edge_duplicate_headers(stress_proxy_client: TestClient) -> None:
    transport = httpx.ASGITransport(app=stress_proxy_client.app, raise_app_exceptions=False)

    async def _run() -> int:
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/data",
                headers=[
                    ("X-Custom-Repeat", "1"),
                    ("X-Custom-Repeat", "2"),
                    ("X-Custom-Repeat", "3"),
                ],
            )
            return resp.status_code

    code = asyncio.run(_run())
    assert code == 200


@pytest.mark.stress
@pytest.mark.slow
def test_edge_emoji_in_api_key(stress_proxy_client: TestClient) -> None:
    # HTTP headers must be latin-1; emoji in Authorization breaks httpx encoding.
    # Exercise emoji in request payload (still hits JSON parse + policy path).
    r = stress_proxy_client.post(
        "/execute",
        json={
            "action": "run_sql",
            "params": {"query": "SELECT 1", "api_key": "sk-🗝️🔐-test"},
        },
    )
    assert r.status_code == 200


@pytest.mark.stress
@pytest.mark.slow
def test_edge_rtl_unicode_in_message(stress_proxy_client: TestClient) -> None:
    rtl = "\u202eHELLO\u202c"
    r = stress_proxy_client.post(
        "/execute",
        json={"action": "run_sql", "params": {"query": f"SELECT '{rtl}'"}},
    )
    assert r.status_code == 200


@pytest.mark.stress
@pytest.mark.slow
def test_edge_mixed_encodings(stress_proxy_client: TestClient) -> None:
    r = stress_proxy_client.post(
        "/execute",
        content='{"action":"run_sql","params":{"query":"café"}}'.encode("latin-1"),
        headers={"Content-Type": "application/json; charset=latin-1"},
    )
    assert r.status_code in {200, 400, 403, 422}
