from __future__ import annotations

import asyncio
import io
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.request import Request as UrlRequest, urlopen

import pytest
from fastapi.testclient import TestClient

from orchesis.demo_backend import app
from orchesis.models import Decision
from orchesis.proxy import app as proxy_module_app
from orchesis.proxy import (
    HTTPProxyConfig,
    LLMHTTPProxy,
    OrchesisProxy,
    ProxyConfig,
    ProxyStats,
    build_app_from_env,
    compute_upstream_retry_delay,
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


def test_proxy_emitted_secret_findings_redact_raw_match() -> None:
    class _CapturingEventBus:
        def __init__(self) -> None:
            self.events: list[dict] = []

        def emit(self, event: dict) -> None:
            self.events.append(event)

    bus = _CapturingEventBus()
    proxy = OrchesisProxy(_FakeEngine(), ProxyConfig(upstream_url="http://localhost:3000"), event_bus=bus)
    findings = proxy._scan_response("read_file", b"OPENAI_KEY=sk-abcdefghijklmnopqrstuvwxyz123")

    assert findings
    assert any("raw_match" in finding for finding in findings)
    assert bus.events
    event = bus.events[-1]
    assert event.get("event") == "proxy_response_scan"
    emitted_findings = event.get("findings")
    assert isinstance(emitted_findings, list)
    assert emitted_findings
    assert all("raw_match" not in finding for finding in emitted_findings if isinstance(finding, dict))


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


class _MockUpstreamHandler(BaseHTTPRequestHandler):
    response_status = 200
    response_body = {"id": "x", "model": "gpt-4o-mini", "usage": {"prompt_tokens": 10, "completion_tokens": 5}, "choices": [{"finish_reason": "stop", "message": {"content": "ok"}}]}
    captured_paths: list[str] = []
    captured_bodies: list[dict] = []
    captured_headers: list[dict[str, str]] = []

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length)
        payload: dict = {}
        try:
            parsed = json.loads(body.decode("utf-8"))
            if isinstance(parsed, dict):
                payload = parsed
        except Exception:
            payload = {}
        self.__class__.captured_paths.append(self.path)
        self.__class__.captured_bodies.append(payload)
        self.__class__.captured_headers.append({k: v for k, v in self.headers.items()})
        data = json.dumps(self.__class__.response_body).encode("utf-8")
        self.send_response(self.__class__.response_status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt: str, *args) -> None:
        _ = (fmt, args)


def _start_http_server(handler_cls: type[BaseHTTPRequestHandler]) -> tuple[HTTPServer, threading.Thread]:
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _pick_free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = int(sock.getsockname()[1])
    sock.close()
    return port


def test_llm_proxy_starts_and_serves_health() -> None:
    port = _pick_free_port()
    proxy = LLMHTTPProxy(config=HTTPProxyConfig(host="127.0.0.1", port=port))
    thread = proxy.start(blocking=False)
    assert thread is not None
    try:
        with urlopen(f"http://127.0.0.1:{port}/health", timeout=2) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        assert payload["status"] == "ok"
    finally:
        proxy.stop()


def test_llm_proxy_returns_stats_endpoint() -> None:
    port = _pick_free_port()
    proxy = LLMHTTPProxy(config=HTTPProxyConfig(host="127.0.0.1", port=port))
    proxy.start(blocking=False)
    try:
        with urlopen(f"http://127.0.0.1:{port}/stats", timeout=2) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        assert "requests" in payload
    finally:
        proxy.stop()


def test_llm_proxy_unknown_get_path_404() -> None:
    port = _pick_free_port()
    proxy = LLMHTTPProxy(config=HTTPProxyConfig(host="127.0.0.1", port=port))
    proxy.start(blocking=False)
    try:
        with pytest.raises(HTTPError) as error:
            urlopen(f"http://127.0.0.1:{port}/missing", timeout=2)
        assert error.value.code == 404
    finally:
        proxy.stop()


def test_llm_proxy_invalid_json_post_400() -> None:
    port = _pick_free_port()
    proxy = LLMHTTPProxy(config=HTTPProxyConfig(host="127.0.0.1", port=port))
    proxy.start(blocking=False)
    try:
        req = UrlRequest(
            f"http://127.0.0.1:{port}/v1/chat/completions",
            data=b"{bad",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(HTTPError) as error:
            urlopen(req, timeout=2)
        assert error.value.code == 400
    finally:
        proxy.stop()


def test_llm_proxy_rejects_when_content_length_exceeds_max_body_size(tmp_path: Path) -> None:
    policy = tmp_path / "policy-max-body.yaml"
    policy.write_text(
        """
rules: []
proxy:
  max_body_size_bytes: 64
""".strip(),
        encoding="utf-8",
    )
    _MockUpstreamHandler.response_status = 200
    _MockUpstreamHandler.response_body = {
        "model": "gpt-4o-mini",
        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
        "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
    }
    upstream_server, _ = _start_http_server(_MockUpstreamHandler)
    port = _pick_free_port()
    proxy = LLMHTTPProxy(
        policy_path=str(policy),
        config=HTTPProxyConfig(
            host="127.0.0.1",
            port=port,
            upstream={
                "openai": f"http://127.0.0.1:{upstream_server.server_address[1]}",
                "anthropic": f"http://127.0.0.1:{upstream_server.server_address[1]}",
            },
        ),
    )
    proxy.start(blocking=False)
    try:
        oversized = {"model": "gpt-4o", "messages": [{"role": "user", "content": "x" * 200}]}
        req = UrlRequest(
            f"http://127.0.0.1:{port}/v1/chat/completions",
            data=json.dumps(oversized).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": "Bearer t"},
            method="POST",
        )
        with pytest.raises(HTTPError) as error:
            urlopen(req, timeout=3)
        assert error.value.code == 413
    finally:
        proxy.stop()
        upstream_server.shutdown()
        upstream_server.server_close()


def test_llm_proxy_allows_when_content_length_within_max_body_size(tmp_path: Path) -> None:
    policy = tmp_path / "policy-max-body-ok.yaml"
    policy.write_text(
        """
rules: []
proxy:
  max_body_size_bytes: 4096
""".strip(),
        encoding="utf-8",
    )
    _MockUpstreamHandler.response_status = 200
    _MockUpstreamHandler.response_body = {
        "model": "gpt-4o-mini",
        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
        "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
    }
    upstream_server, _ = _start_http_server(_MockUpstreamHandler)
    port = _pick_free_port()
    proxy = LLMHTTPProxy(
        policy_path=str(policy),
        config=HTTPProxyConfig(
            host="127.0.0.1",
            port=port,
            upstream={
                "openai": f"http://127.0.0.1:{upstream_server.server_address[1]}",
                "anthropic": f"http://127.0.0.1:{upstream_server.server_address[1]}",
            },
        ),
    )
    proxy.start(blocking=False)
    try:
        body = {"model": "gpt-4o", "messages": [{"role": "user", "content": "hello"}]}
        req = UrlRequest(
            f"http://127.0.0.1:{port}/v1/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": "Bearer t"},
            method="POST",
        )
        with urlopen(req, timeout=3) as resp:
            assert int(resp.status) == 200
    finally:
        proxy.stop()
        upstream_server.shutdown()
        upstream_server.server_close()


def test_llm_proxy_no_content_length_uses_default_behavior() -> None:
    port = _pick_free_port()
    proxy = LLMHTTPProxy(config=HTTPProxyConfig(host="127.0.0.1", port=port))
    proxy.start(blocking=False)
    sock = socket.create_connection(("127.0.0.1", port), timeout=3)
    try:
        raw = (
            "POST /kill HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n"
            "Content-Type: application/json\r\n"
            "Connection: close\r\n\r\n"
        ).encode("utf-8")
        sock.sendall(raw)
        data = sock.recv(4096)
        assert b"200" in data
    finally:
        sock.close()
        proxy.stop()


def test_llm_proxy_blocks_denied_tool_call(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        """
tool_access:
  mode: allowlist
  default: deny
  allowed:
    - web_search
""".strip(),
        encoding="utf-8",
    )
    port = _pick_free_port()
    proxy = LLMHTTPProxy(policy_path=str(policy), config=HTTPProxyConfig(host="127.0.0.1", port=port))
    proxy.start(blocking=False)
    try:
        body = {
            "model": "gpt-4o",
            "messages": [
                {
                    "role": "assistant",
                    "tool_calls": [
                        {"id": "c1", "type": "function", "function": {"name": "read_file", "arguments": '{"path":"/etc/passwd"}'}}
                    ],
                }
            ],
        }
        req = UrlRequest(
            f"http://127.0.0.1:{port}/v1/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(HTTPError) as error:
            urlopen(req, timeout=2)
        assert error.value.code == 403
    finally:
        proxy.stop()


def test_llm_proxy_blocks_when_daily_budget_exceeded(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\nbudgets:\n  daily: 0.0\n", encoding="utf-8")
    port = _pick_free_port()
    proxy = LLMHTTPProxy(policy_path=str(policy), config=HTTPProxyConfig(host="127.0.0.1", port=port))
    proxy.start(blocking=False)
    try:
        req = UrlRequest(
            f"http://127.0.0.1:{port}/v1/chat/completions",
            data=json.dumps({"model": "gpt-4o", "messages": []}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(HTTPError) as error:
            urlopen(req, timeout=2)
        assert error.value.code == 429
    finally:
        proxy.stop()


def test_llm_proxy_blocks_loop_detection(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        """
rules: []
loop_detection:
  enabled: true
  warn_threshold: 1
  block_threshold: 2
  window_seconds: 300
""".strip(),
        encoding="utf-8",
    )
    port = _pick_free_port()
    proxy = LLMHTTPProxy(policy_path=str(policy), config=HTTPProxyConfig(host="127.0.0.1", port=port))
    # force requests to same tool call and bypass upstream via local mock
    _MockUpstreamHandler.response_status = 200
    _MockUpstreamHandler.response_body = {"model": "gpt-4o-mini", "usage": {"prompt_tokens": 1, "completion_tokens": 1}, "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]}
    upstream_server, _t = _start_http_server(_MockUpstreamHandler)
    proxy._config.upstream = {"openai": f"http://127.0.0.1:{upstream_server.server_address[1]}", "anthropic": f"http://127.0.0.1:{upstream_server.server_address[1]}"}
    proxy.start(blocking=False)
    body = {
        "model": "gpt-4o",
        "messages": [
            {
                "role": "assistant",
                "tool_calls": [{"id": "x", "type": "function", "function": {"name": "web_search", "arguments": '{"query":"x"}'}}],
            }
        ],
    }
    req = UrlRequest(
        f"http://127.0.0.1:{port}/v1/chat/completions",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": "Bearer t"},
        method="POST",
    )
    try:
        with urlopen(req, timeout=3) as first:
            assert first.status == 200
        with pytest.raises(HTTPError) as error:
            urlopen(req, timeout=3)
        assert error.value.code == 429
    finally:
        proxy.stop()
        upstream_server.shutdown()
        upstream_server.server_close()


def _post_chat_completion(
    proxy_port: int,
    message: str,
    session_id: str = "loop-session",
    *,
    session_header: str = "X-Session-Id",
) -> tuple[int, dict[str, str], dict]:
    req = UrlRequest(
        f"http://127.0.0.1:{proxy_port}/v1/chat/completions",
        data=json.dumps({"model": "gpt-4o", "messages": [{"role": "user", "content": message}]}).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer t",
            session_header: session_id,
        },
        method="POST",
    )
    try:
        with urlopen(req, timeout=3) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
            return int(resp.status), dict(resp.headers.items()), payload
    except HTTPError as error:
        payload = json.loads(error.read().decode("utf-8"))
        return int(error.code), dict(error.headers.items()), payload


def test_loop_detection_blocks_repeated_proxy_requests(tmp_path: Path) -> None:
    policy = tmp_path / "policy-loop-block.yaml"
    policy.write_text(
        """
rules: []
loop_detection:
  enabled: true
  warn_threshold: 3
  block_threshold: 5
  window_seconds: 300
  content_loop:
    enabled: true
    warn_threshold: 3
    max_identical: 5
  exact:
    threshold: 999
  fuzzy:
    threshold: 999
""".strip(),
        encoding="utf-8",
    )
    _MockUpstreamHandler.response_status = 200
    _MockUpstreamHandler.response_body = {"model": "gpt-4o-mini", "usage": {"prompt_tokens": 1, "completion_tokens": 1}, "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]}
    upstream_server, _ = _start_http_server(_MockUpstreamHandler)
    port = _pick_free_port()
    proxy = LLMHTTPProxy(
        policy_path=str(policy),
        config=HTTPProxyConfig(
            host="127.0.0.1",
            port=port,
            upstream={
                "openai": f"http://127.0.0.1:{upstream_server.server_address[1]}",
                "anthropic": f"http://127.0.0.1:{upstream_server.server_address[1]}",
            },
        ),
    )
    proxy.start(blocking=False)
    try:
        for _ in range(4):
            status, _, _ = _post_chat_completion(port, "Read HEARTBEAT.md")
            assert status == 200
        blocked_status, blocked_headers, blocked_payload = _post_chat_completion(port, "Read HEARTBEAT.md")
        assert blocked_status == 429
        assert blocked_payload.get("error", {}).get("type") == "content_loop_detected"
        assert "X-Orchesis-Loop-Count" in blocked_headers
    finally:
        proxy.stop()
        upstream_server.shutdown()
        upstream_server.server_close()


def test_loop_detection_warns_before_blocking(tmp_path: Path) -> None:
    policy = tmp_path / "policy-loop-warn.yaml"
    policy.write_text(
        """
rules: []
loop_detection:
  enabled: true
  warn_threshold: 2
  block_threshold: 4
  window_seconds: 300
  content_loop:
    enabled: true
    warn_threshold: 2
    max_identical: 4
  exact:
    threshold: 999
  fuzzy:
    threshold: 999
""".strip(),
        encoding="utf-8",
    )
    _MockUpstreamHandler.response_status = 200
    _MockUpstreamHandler.response_body = {"model": "gpt-4o-mini", "usage": {"prompt_tokens": 1, "completion_tokens": 1}, "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]}
    upstream_server, _ = _start_http_server(_MockUpstreamHandler)
    port = _pick_free_port()
    proxy = LLMHTTPProxy(
        policy_path=str(policy),
        config=HTTPProxyConfig(
            host="127.0.0.1",
            port=port,
            upstream={
                "openai": f"http://127.0.0.1:{upstream_server.server_address[1]}",
                "anthropic": f"http://127.0.0.1:{upstream_server.server_address[1]}",
            },
        ),
    )
    proxy.start(blocking=False)
    try:
        status1, headers1, _ = _post_chat_completion(port, "Read HEARTBEAT.md")
        status2, headers2, _ = _post_chat_completion(port, "Read HEARTBEAT.md")
        status3, headers3, _ = _post_chat_completion(port, "Read HEARTBEAT.md")
        status4, _, _ = _post_chat_completion(port, "Read HEARTBEAT.md")
        assert status1 == 200 and "X-Orchesis-Loop-Warning" not in headers1
        assert status2 == 200 and "X-Orchesis-Loop-Warning" in headers2
        assert status3 == 200 and "X-Orchesis-Loop-Warning" in headers3
        assert status4 == 429
    finally:
        proxy.stop()
        upstream_server.shutdown()
        upstream_server.server_close()


def test_loop_detection_resets_after_different_content(tmp_path: Path) -> None:
    policy = tmp_path / "policy-loop-reset.yaml"
    policy.write_text(
        """
rules: []
loop_detection:
  enabled: true
  warn_threshold: 2
  block_threshold: 4
  window_seconds: 300
  content_loop:
    enabled: true
    warn_threshold: 2
    max_identical: 4
  exact:
    threshold: 999
  fuzzy:
    threshold: 999
""".strip(),
        encoding="utf-8",
    )
    _MockUpstreamHandler.response_status = 200
    _MockUpstreamHandler.response_body = {"model": "gpt-4o-mini", "usage": {"prompt_tokens": 1, "completion_tokens": 1}, "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]}
    upstream_server, _ = _start_http_server(_MockUpstreamHandler)
    port = _pick_free_port()
    proxy = LLMHTTPProxy(
        policy_path=str(policy),
        config=HTTPProxyConfig(
            host="127.0.0.1",
            port=port,
            upstream={
                "openai": f"http://127.0.0.1:{upstream_server.server_address[1]}",
                "anthropic": f"http://127.0.0.1:{upstream_server.server_address[1]}",
            },
        ),
    )
    proxy.start(blocking=False)
    try:
        status1, _, _ = _post_chat_completion(port, "Read HEARTBEAT.md")
        status2, headers2, _ = _post_chat_completion(port, "Read HEARTBEAT.md")
        status3, headers3, _ = _post_chat_completion(port, "Read DIFFERENT.md")
        status4, headers4, _ = _post_chat_completion(port, "Read HEARTBEAT.md")
        assert status1 == 200
        assert status2 == 200 and "X-Orchesis-Loop-Warning" in headers2
        assert status3 == 200 and "X-Orchesis-Loop-Warning" not in headers3
        assert status4 == 200 and "X-Orchesis-Loop-Warning" not in headers4
    finally:
        proxy.stop()
        upstream_server.shutdown()
        upstream_server.server_close()


def test_resolve_session_id_prefers_openclaw_session_id() -> None:
    headers = {"x-openclaw-session-id": "sess-1"}
    assert LLMHTTPProxy._resolve_session_id(headers) == "sess-1"  # noqa: SLF001


def test_resolve_session_id_supports_openclaw_session_fallback() -> None:
    headers = {"x-openclaw-session": "sess-2"}
    assert LLMHTTPProxy._resolve_session_id(headers) == "sess-2"  # noqa: SLF001


def test_resolve_session_id_defaults_when_missing_headers() -> None:
    assert LLMHTTPProxy._resolve_session_id({}) == "default"  # noqa: SLF001


def test_loop_detection_scopes_independently_per_session(tmp_path: Path) -> None:
    policy = tmp_path / "policy-loop-session-scope.yaml"
    policy.write_text(
        """
rules: []
loop_detection:
  enabled: true
  warn_threshold: 3
  block_threshold: 4
  window_seconds: 300
  content_loop:
    enabled: true
    warn_threshold: 3
    max_identical: 4
  exact:
    threshold: 999
  fuzzy:
    threshold: 999
""".strip(),
        encoding="utf-8",
    )
    _MockUpstreamHandler.response_status = 200
    _MockUpstreamHandler.response_body = {
        "model": "gpt-4o-mini",
        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
        "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
    }
    upstream_server, _ = _start_http_server(_MockUpstreamHandler)
    port = _pick_free_port()
    proxy = LLMHTTPProxy(
        policy_path=str(policy),
        config=HTTPProxyConfig(
            host="127.0.0.1",
            port=port,
            upstream={
                "openai": f"http://127.0.0.1:{upstream_server.server_address[1]}",
                "anthropic": f"http://127.0.0.1:{upstream_server.server_address[1]}",
            },
        ),
    )
    proxy.start(blocking=False)
    try:
        # Alternate between two OpenClaw sessions; counts must not bleed across sessions.
        status1, _, _ = _post_chat_completion(port, "Read HEARTBEAT.md", "sess-a", session_header="X-OpenClaw-Session-Id")
        status2, _, _ = _post_chat_completion(port, "Read HEARTBEAT.md", "sess-b", session_header="X-OpenClaw-Session-Id")
        status3, _, _ = _post_chat_completion(port, "Read HEARTBEAT.md", "sess-a", session_header="X-OpenClaw-Session-Id")
        status4, _, _ = _post_chat_completion(port, "Read HEARTBEAT.md", "sess-b", session_header="X-OpenClaw-Session-Id")
        status5, _, _ = _post_chat_completion(port, "Read HEARTBEAT.md", "sess-a", session_header="X-OpenClaw-Session-Id")
        assert status1 == 200
        assert status2 == 200
        assert status3 == 200
        assert status4 == 200
        assert status5 == 200
    finally:
        proxy.stop()
        upstream_server.shutdown()
        upstream_server.server_close()


def test_llm_proxy_forwards_allowed_request_to_upstream() -> None:
    _MockUpstreamHandler.captured_paths = []
    _MockUpstreamHandler.captured_bodies = []
    _MockUpstreamHandler.response_status = 200
    _MockUpstreamHandler.response_body = {"model": "gpt-4o-mini", "usage": {"prompt_tokens": 2, "completion_tokens": 3}, "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]}
    upstream_server, _ = _start_http_server(_MockUpstreamHandler)
    upstream_port = upstream_server.server_address[1]
    port = _pick_free_port()
    proxy = LLMHTTPProxy(
        config=HTTPProxyConfig(
            host="127.0.0.1",
            port=port,
            upstream={"openai": f"http://127.0.0.1:{upstream_port}", "anthropic": f"http://127.0.0.1:{upstream_port}"},
        )
    )
    proxy.start(blocking=False)
    try:
        req = UrlRequest(
            f"http://127.0.0.1:{port}/v1/chat/completions",
            data=json.dumps({"model": "gpt-4o", "messages": [{"role": "user", "content": "hello"}]}).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": "Bearer t"},
            method="POST",
        )
        with urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            headers = dict(resp.headers.items())
        assert data["choices"][0]["message"]["content"] == "ok"
        assert _MockUpstreamHandler.captured_paths
        assert "X-Orchesis-Cost" in headers
        assert "X-Orchesis-Daily-Total" in headers
    finally:
        proxy.stop()
        upstream_server.shutdown()
        upstream_server.server_close()


def test_llm_proxy_handles_upstream_connection_error_502() -> None:
    port = _pick_free_port()
    proxy = LLMHTTPProxy(
        config=HTTPProxyConfig(
            host="127.0.0.1",
            port=port,
            upstream={"openai": "http://127.0.0.1:1", "anthropic": "http://127.0.0.1:1"},
            timeout=0.2,
        )
    )
    proxy.start(blocking=False)
    try:
        req = UrlRequest(
            f"http://127.0.0.1:{port}/v1/chat/completions",
            data=json.dumps({"model": "gpt-4o", "messages": []}).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": "Bearer t"},
            method="POST",
        )
        with pytest.raises(HTTPError) as error:
            urlopen(req, timeout=5)
        assert error.value.code == 502
    finally:
        proxy.stop()


def test_llm_proxy_passes_through_upstream_http_error() -> None:
    _MockUpstreamHandler.response_status = 401
    _MockUpstreamHandler.response_body = {"error": "unauthorized"}
    upstream_server, _ = _start_http_server(_MockUpstreamHandler)
    port = upstream_server.server_address[1]
    proxy_port = _pick_free_port()
    proxy = LLMHTTPProxy(
        config=HTTPProxyConfig(
            host="127.0.0.1",
            port=proxy_port,
            upstream={"openai": f"http://127.0.0.1:{port}", "anthropic": f"http://127.0.0.1:{port}"},
        )
    )
    proxy.start(blocking=False)
    try:
        req = UrlRequest(
            f"http://127.0.0.1:{proxy_port}/v1/chat/completions",
            data=json.dumps({"model": "gpt-4o", "messages": []}).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": "Bearer x"},
            method="POST",
        )
        with pytest.raises(HTTPError) as error:
            urlopen(req, timeout=3)
        assert error.value.code == 401
    finally:
        proxy.stop()
        upstream_server.shutdown()
        upstream_server.server_close()


def test_llm_proxy_detects_anthropic_provider_by_headers() -> None:
    proxy = LLMHTTPProxy(config=HTTPProxyConfig())
    provider = proxy._detect_provider("openai", {"x-api-key": "x"})
    assert provider == "anthropic"


def test_llm_proxy_detects_openai_provider_by_headers() -> None:
    proxy = LLMHTTPProxy(config=HTTPProxyConfig())
    provider = proxy._detect_provider("anthropic", {"Authorization": "Bearer x"})
    assert provider == "openai"


def test_get_upstream_blocks_loopback_override(monkeypatch: pytest.MonkeyPatch) -> None:
    proxy = LLMHTTPProxy(config=HTTPProxyConfig())
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 443))],
    )
    upstream = proxy._get_upstream("openai", {"X-Orchesis-Upstream": "http://127.0.0.1:8000"})  # noqa: SLF001
    assert upstream == "https://api.openai.com"


def test_get_upstream_blocks_metadata_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    proxy = LLMHTTPProxy(config=HTTPProxyConfig())
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("169.254.169.254", 80))],
    )
    upstream = proxy._get_upstream("openai", {"X-Orchesis-Upstream": "http://169.254.169.254/latest"})  # noqa: SLF001
    assert upstream == "https://api.openai.com"


def test_get_upstream_allows_public_https(monkeypatch: pytest.MonkeyPatch) -> None:
    proxy = LLMHTTPProxy(config=HTTPProxyConfig())
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("104.18.33.45", 443))],
    )
    upstream = proxy._get_upstream("openai", {"X-Orchesis-Upstream": "https://api.openai.com"})  # noqa: SLF001
    assert upstream == "https://api.openai.com"


def test_get_upstream_allows_private_when_enabled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    policy = tmp_path / "policy-ssrf-allow-private.yaml"
    policy.write_text(
        """
rules: []
proxy:
  ssrf_allow_private: true
""".strip(),
        encoding="utf-8",
    )
    proxy = LLMHTTPProxy(policy_path=str(policy), config=HTTPProxyConfig())
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 8000))],
    )
    upstream = proxy._get_upstream("openai", {"X-Orchesis-Upstream": "http://127.0.0.1:8000"})  # noqa: SLF001
    assert upstream == "http://127.0.0.1:8000"


def test_get_upstream_blocks_non_http_scheme() -> None:
    proxy = LLMHTTPProxy(config=HTTPProxyConfig())
    upstream = proxy._get_upstream("openai", {"X-Orchesis-Upstream": "ftp://api.openai.com"})  # noqa: SLF001
    assert upstream == "https://api.openai.com"


def test_llm_proxy_applies_model_routing(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        """
rules: []
model_routing:
  enabled: true
  default: gpt-4o
  rules:
    - complexity: low
      model: gpt-4o-mini
""".strip(),
        encoding="utf-8",
    )
    _MockUpstreamHandler.captured_bodies = []
    _MockUpstreamHandler.response_status = 200
    _MockUpstreamHandler.response_body = {"model": "gpt-4o-mini", "usage": {"prompt_tokens": 1, "completion_tokens": 1}, "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]}
    upstream_server, _ = _start_http_server(_MockUpstreamHandler)
    port = upstream_server.server_address[1]
    proxy_port = _pick_free_port()
    proxy = LLMHTTPProxy(
        policy_path=str(policy),
        config=HTTPProxyConfig(
            host="127.0.0.1",
            port=proxy_port,
            upstream={"openai": f"http://127.0.0.1:{port}", "anthropic": f"http://127.0.0.1:{port}"},
        ),
    )
    proxy.start(blocking=False)
    try:
        req = UrlRequest(
            f"http://127.0.0.1:{proxy_port}/v1/chat/completions",
            data=json.dumps({"model": "gpt-4o", "messages": [{"role": "user", "content": "hello"}]}).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": "Bearer t"},
            method="POST",
        )
        with urlopen(req, timeout=3) as resp:
            assert resp.status == 200
        assert _MockUpstreamHandler.captured_bodies
        assert _MockUpstreamHandler.captured_bodies[-1]["model"] == "gpt-4o-mini"
    finally:
        proxy.stop()
        upstream_server.shutdown()
        upstream_server.server_close()


def test_llm_proxy_scans_request_content_for_secrets_and_blocks() -> None:
    port = _pick_free_port()
    proxy = LLMHTTPProxy(config=HTTPProxyConfig(host="127.0.0.1", port=port))
    proxy.start(blocking=False)
    try:
        body = {"model": "gpt-4o", "messages": [{"role": "user", "content": "my key sk-abcdefghijklmnopqrstuvwxyz123"}]}
        req = UrlRequest(
            f"http://127.0.0.1:{port}/v1/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": "Bearer t"},
            method="POST",
        )
        with pytest.raises(HTTPError) as error:
            urlopen(req, timeout=2)
        assert error.value.code == 403
    finally:
        proxy.stop()


def test_loop_warn_adds_dashboard_event() -> None:
    proxy = LLMHTTPProxy(config=HTTPProxyConfig(port=0))
    try:
        proxy._loop_detector = SimpleNamespace(  # noqa: SLF001
            check_request=lambda _req: SimpleNamespace(action="warn", reason="Exact loop threshold exceeded")
        )
        proxy._content_loop_detector = None  # noqa: SLF001
        ctx = SimpleNamespace(
            body={"model": "gpt-4o-mini"},
            parsed_req=SimpleNamespace(
                messages=[{"role": "user", "content": "What is 2+2?"}],
                tool_calls=[],
                content_text="What is 2+2?",
                model="gpt-4o-mini",
            ),
            session_id="loop-test-session",
            loop_warning_header="",
            was_loop_detected=False,
        )

        ok = proxy._phase_loop_detection(ctx)  # noqa: SLF001

        assert ok is True
        assert ctx.was_loop_detected is True
        assert "Exact loop threshold exceeded" in ctx.loop_warning_header
        events = list(proxy._dashboard_events)  # noqa: SLF001
        assert any(str(item.get("type")) == "loop_warning" for item in events)
    finally:
        proxy.stop()


def test_cascade_cache_hit_still_runs_loop_detection() -> None:
    class _DummyHandler:
        def __init__(self) -> None:
            self.headers_sent: dict[str, str] = {}
            self.wfile = io.BytesIO()
            self.status = 0

        def send_response(self, status: int) -> None:
            self.status = int(status)

        def send_header(self, key: str, value: str) -> None:
            self.headers_sent[str(key)] = str(value)

        def end_headers(self) -> None:
            return None

    proxy = LLMHTTPProxy(config=HTTPProxyConfig(port=0))
    try:
        proxy._cascade_router = SimpleNamespace(  # noqa: SLF001
            classify=lambda _req, context=None: SimpleNamespace(name="SIMPLE"),
            level_name=lambda _level: "simple",
            make_cache_key=lambda _req, _model: "k",
            get_cache=lambda _key, _level: b'{"ok":true}',
        )
        proxy._phase_loop_detection = lambda ctx: setattr(ctx, "loop_warning_header", "loop warn") or True  # type: ignore[method-assign]  # noqa: E501, SLF001
        handler = _DummyHandler()
        ctx = SimpleNamespace(
            body={},
            parsed_req=SimpleNamespace(model="gpt-4o-mini", provider="openai"),
            proc_result={},
            session_id="s",
            spend_rate_per_min=0.0,
            request_started=0.0,
            loop_warning_header="",
            behavior_agent_id="a",
            behavior_header="normal",
            request_id="r",
        )
        ctx.handler = handler

        ok = proxy._phase_cascade(ctx)  # noqa: SLF001

        assert ok is False
        assert handler.status == 200
        assert handler.headers_sent.get("X-Orchesis-Cache") == "hit"
        assert handler.headers_sent.get("X-Orchesis-Loop-Warning") == "loop warn"
    finally:
        proxy.stop()


def test_retry_backoff_delays_increase() -> None:
    d0 = compute_upstream_retry_delay(0, base_delay=0.1, max_delay=100.0, random_unit=1.0)
    d1 = compute_upstream_retry_delay(1, base_delay=0.1, max_delay=100.0, random_unit=1.0)
    assert d1 > d0


def test_retry_backoff_has_jitter() -> None:
    d_lo = compute_upstream_retry_delay(0, base_delay=1.0, max_delay=100.0, random_unit=0.0)
    d_hi = compute_upstream_retry_delay(0, base_delay=1.0, max_delay=100.0, random_unit=1.0)
    assert d_lo == pytest.approx(0.5)
    assert d_hi == pytest.approx(1.0)


def test_retry_respects_max_delay() -> None:
    d = compute_upstream_retry_delay(10, base_delay=1.0, max_delay=2.0, random_unit=1.0)
    assert d == pytest.approx(2.0)
    d_low = compute_upstream_retry_delay(10, base_delay=1.0, max_delay=2.0, random_unit=0.0)
    assert d_low == pytest.approx(1.0)
