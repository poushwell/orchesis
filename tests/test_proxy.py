from __future__ import annotations

import asyncio
import json

import pytest
from fastapi.testclient import TestClient

from orchesis.demo_backend import app
from orchesis.models import Decision
from orchesis.proxy import app as proxy_module_app
from orchesis.proxy import (
    OrchesisProxy,
    ProxyConfig,
    ProxyStats,
    build_app_from_env,
    create_proxy_app,
)


def test_demo_backend_get_data() -> None:
    client = TestClient(app)

    response = client.get("/data")

    assert response.status_code == 200
    assert response.json() == {"items": ["report.csv", "data.json"]}


def test_demo_backend_post_execute() -> None:
    client = TestClient(app)

    response = client.post(
        "/execute",
        json={"action": "run_sql", "params": {"query": "SELECT 1"}},
    )

    assert response.status_code == 200
    assert response.json() == {"status": "done"}


def test_demo_backend_delete_files_path() -> None:
    client = TestClient(app)

    response = client.delete("/files/tmp/a/b/report.csv")

    assert response.status_code == 200
    assert response.json() == {"deleted": True}


def test_proxy_allows_and_forwards_get_data() -> None:
    proxy_app = create_proxy_app(
        policy={"rules": [{"name": "budget_limit", "max_cost_per_call": 1.0}]},
        backend_app=app,
    )
    proxy_client = TestClient(proxy_app)

    response = proxy_client.get("/data")

    assert response.status_code == 200
    assert response.json() == {"items": ["report.csv", "data.json"]}
    assert response.headers.get("X-Orchesis-Decision") == "ALLOW"
    assert response.headers.get("X-Orchesis-Trace-Id")


def test_proxy_denies_and_does_not_forward_delete_when_path_blocked() -> None:
    state = {"delete_calls": 0}

    from fastapi import FastAPI

    backend = FastAPI()

    @backend.delete("/files/{path:path}")
    def delete_file(path: str) -> dict[str, bool]:
        _ = path
        state["delete_calls"] += 1
        return {"deleted": True}

    proxy_app = create_proxy_app(
        policy={"rules": [{"name": "file_access", "denied_paths": ["/etc"]}]},
        backend_app=backend,
    )
    proxy_client = TestClient(proxy_app)

    response = proxy_client.delete("/files/etc/passwd")

    assert response.status_code == 403
    assert response.json()["allowed"] is False
    assert response.headers.get("X-Orchesis-Decision") == "DENY"
    assert response.headers.get("X-Orchesis-Trace-Id")
    assert state["delete_calls"] == 0


def test_proxy_denies_post_execute_with_drop_query() -> None:
    proxy_app = create_proxy_app(
        policy={"rules": [{"name": "sql_restriction", "denied_operations": ["DROP"]}]},
        backend_app=app,
    )
    proxy_client = TestClient(proxy_app)

    response = proxy_client.post(
        "/execute",
        json={"action": "run_sql", "params": {"query": "DROP TABLE users"}},
    )

    assert response.status_code == 403
    assert "sql_restriction: DROP is denied" in response.json()["reasons"]


def test_proxy_budget_limit_uses_x_cost_header() -> None:
    proxy_app = create_proxy_app(
        policy={"rules": [{"name": "budget_limit", "max_cost_per_call": 0.5}]},
        backend_app=app,
    )
    proxy_client = TestClient(proxy_app)

    response = proxy_client.get("/data", headers={"x-cost": "0.9"})

    assert response.status_code == 403
    assert response.json()["allowed"] is False


def test_proxy_module_exports_default_app() -> None:
    assert proxy_module_app is not None


def test_build_app_from_env_uses_policy_path(monkeypatch, tmp_path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
rules:
  - name: file_access
    denied_paths:
      - "/etc"
""".strip(),
        encoding="utf-8",
    )
    monkeypatch.setenv("POLICY_PATH", str(policy_path))
    monkeypatch.setenv("BACKEND_URL", "http://backend:8081")

    env_proxy_app = build_app_from_env()
    client = TestClient(env_proxy_app)

    response = client.delete("/files/etc/passwd")

    assert response.status_code == 403
    assert "file_access: path '/etc/passwd' is denied by '/etc'" in response.json()["reasons"]


class _FakeEngine:
    def __init__(self, deny_tools: set[str] | None = None):
        self.calls: list[dict] = []
        self.deny_tools = deny_tools or set()

    def evaluate(self, payload: dict):
        self.calls.append(payload)
        if payload.get("tool") in self.deny_tools:
            return Decision(allowed=False, reasons=["file_access: blocked for test"], rules_checked=["file_access"])
        return Decision(allowed=True, reasons=[], rules_checked=["file_access"])


@pytest.mark.asyncio
async def test_proxy_allows_clean_request() -> None:
    proxy = OrchesisProxy(_FakeEngine(), ProxyConfig(upstream_url="http://localhost:9999"))

    async def _forward(method, path, headers, body):
        _ = (method, path, headers, body)
        return 200, {"content-type": "application/json"}, b'{"ok":true}'

    proxy._forward_request = _forward  # type: ignore[method-assign]
    server = await asyncio.start_server(proxy.handle_request, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    body = b'{"path":"/tmp/a"}'
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(
        (
            "POST /tools/read_file HTTP/1.1\r\n"
            "Host: x\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode("utf-8")
        + body
    )
    await writer.drain()
    raw = await reader.read()
    writer.close()
    await writer.wait_closed()
    server.close()
    await server.wait_closed()
    assert b"HTTP/1.1 200" in raw
    assert b"x-orchesis-decision: ALLOW" in raw


@pytest.mark.asyncio
async def test_proxy_denies_blocked_tool() -> None:
    proxy = OrchesisProxy(_FakeEngine(deny_tools={"read_file"}), ProxyConfig(upstream_url="http://localhost:9999"))

    async def _forward(method, path, headers, body):
        _ = (method, path, headers, body)
        raise AssertionError("should not forward denied request")

    proxy._forward_request = _forward  # type: ignore[method-assign]
    server = await asyncio.start_server(proxy.handle_request, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    body = b'{"path":"/etc"}'
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(
        (
            "POST /tools/read_file HTTP/1.1\r\n"
            "Host: x\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode("utf-8")
        + body
    )
    await writer.drain()
    raw = await reader.read()
    writer.close()
    await writer.wait_closed()
    server.close()
    await server.wait_closed()
    assert b"HTTP/1.1 403 Forbidden" in raw
    assert b"blocked_by_policy" in raw


def test_proxy_passthrough_mode() -> None:
    engine = _FakeEngine()
    proxy = OrchesisProxy(engine, ProxyConfig(upstream_url="http://localhost:3000", intercept_mode="passthrough"))
    extracted = proxy._extract_tool_call("POST", "/tools/read_file", {"content-type": "application/json"}, b'{"path":"/tmp"}')
    assert extracted is not None
    # In passthrough mode, runtime should skip policy evaluation.
    assert engine.calls == []


def test_proxy_extracts_tool_from_json_body() -> None:
    proxy = OrchesisProxy(_FakeEngine(), ProxyConfig(upstream_url="http://localhost:3000"))
    parsed = proxy._extract_tool_call(
        "POST",
        "/invoke",
        {"content-type": "application/json"},
        b'{"tool_name":"read_file","params":{"path":"/tmp/a"}}',
    )
    assert parsed == ("read_file", {"path": "/tmp/a"})


def test_proxy_extracts_tool_openai_format() -> None:
    proxy = OrchesisProxy(_FakeEngine(), ProxyConfig(upstream_url="http://localhost:3000"))
    parsed = proxy._extract_tool_call(
        "POST",
        "/invoke",
        {"content-type": "application/json"},
        b'{"function":"read_file","arguments":{"path":"/tmp/a"}}',
    )
    assert parsed == ("read_file", {"path": "/tmp/a"})


def test_proxy_extracts_tool_mcp_format() -> None:
    proxy = OrchesisProxy(_FakeEngine(), ProxyConfig(upstream_url="http://localhost:3000"))
    parsed = proxy._extract_tool_call(
        "POST",
        "/mcp",
        {"content-type": "application/json"},
        b'{"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/a"}}}',
    )
    assert parsed == ("read_file", {"path": "/tmp/a"})


def test_proxy_extracts_tool_rest_style() -> None:
    proxy = OrchesisProxy(_FakeEngine(), ProxyConfig(upstream_url="http://localhost:3000"))
    parsed = proxy._extract_tool_call(
        "POST",
        "/tools/read_file",
        {"content-type": "application/json"},
        b'{"path":"/tmp/a"}',
    )
    assert parsed == ("read_file", {"path": "/tmp/a"})


def test_proxy_extracts_tool_jsonrpc() -> None:
    proxy = OrchesisProxy(_FakeEngine(), ProxyConfig(upstream_url="http://localhost:3000"))
    parsed = proxy._extract_tool_call(
        "POST",
        "/rpc",
        {"content-type": "application/json"},
        b'{"jsonrpc":"2.0","method":"read_file","params":{"path":"/tmp/a"}}',
    )
    assert parsed == ("read_file", {"path": "/tmp/a"})


def test_proxy_deny_response_format() -> None:
    proxy = OrchesisProxy(_FakeEngine(), ProxyConfig(upstream_url="http://localhost:3000"))
    data = proxy._build_deny_response("denied", "file_access")
    assert b"HTTP/1.1 403 Forbidden" in data
    assert b"X-Orchesis-Decision: DENY" in data
    assert b'"error": "blocked_by_policy"' in data


def test_proxy_stats_tracking() -> None:
    stats = ProxyStats()
    stats.record_request("ALLOW", 10.0, 100)
    stats.record_request("DENY", 20.0, 50)
    payload = stats.to_dict()
    assert payload["requests_total"] == 2
    assert payload["requests_allowed"] == 1
    assert payload["requests_denied"] == 1
    assert payload["bytes_proxied"] == 150


def test_proxy_scan_response_for_secrets() -> None:
    proxy = OrchesisProxy(_FakeEngine(), ProxyConfig(upstream_url="http://localhost:3000"))
    findings = proxy._scan_response("read_file", b"OPENAI_KEY=sk-abcdefghijklmnopqrstuvwxyz123")
    assert findings


@pytest.mark.asyncio
async def test_proxy_large_body_rejected() -> None:
    proxy = OrchesisProxy(_FakeEngine(), ProxyConfig(upstream_url="http://localhost:3000", max_body_size=16))
    server = await asyncio.start_server(proxy.handle_request, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    body = json.dumps({"path": "/tmp/a", "data": "x" * 64}).encode("utf-8")
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(
        (
            "POST /tools/write_file HTTP/1.1\r\n"
            "Host: x\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode("utf-8")
        + body
    )
    await writer.drain()
    raw = await reader.read()
    writer.close()
    await writer.wait_closed()
    server.close()
    await server.wait_closed()
    assert b"HTTP/1.1 413 Payload Too Large" in raw
