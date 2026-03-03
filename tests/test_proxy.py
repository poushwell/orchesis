from __future__ import annotations

import asyncio
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
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
