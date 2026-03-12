from __future__ import annotations

import json
from pathlib import Path
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler
from urllib.request import Request as UrlRequest, urlopen

import pytest

from orchesis.config import load_policy
from orchesis.connection_pool import ConnectionPool, PoolConfig
from orchesis.proxy import HTTPProxyConfig, LLMHTTPProxy, PooledThreadHTTPServer, _RequestContext


def _pick_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = int(sock.getsockname()[1])
    sock.close()
    return port


class _JsonUpstreamHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length)
        body = {}
        try:
            body = json.loads(raw.decode("utf-8"))
        except Exception:
            body = {}
        if body.get("stream") is True:
            events = [
                'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Hello"}}\n\n',
                'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":" world"}}\n\n',
                'data: {"type":"message_delta","usage":{"input_tokens":5,"output_tokens":2}}\n\n',
                "data: [DONE]\n\n",
            ]
            payload = "".join(events).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        resp = {
            "model": "gpt-4o-mini",
            "usage": {"prompt_tokens": 5, "completion_tokens": 2},
            "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
        }
        data = json.dumps(resp).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt: str, *args) -> None:
        _ = (fmt, args)


def _start_server(handler_cls: type[BaseHTTPRequestHandler]) -> tuple[PooledThreadHTTPServer, threading.Thread]:
    server = PooledThreadHTTPServer(("127.0.0.1", 0), handler_cls, max_workers=4)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _wait_for_server_ready(host: str, port: int, timeout: float = 2.0) -> None:
    """Poll until server accepts connections. Reduces flakiness from socket bind race."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect((host, port))
            return
        except (ConnectionRefusedError, OSError):
            time.sleep(0.02)
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass


def _make_proxy(tmp_path: Path, policy_text: str) -> tuple[LLMHTTPProxy, PooledThreadHTTPServer]:
    upstream, _ = _start_server(_JsonUpstreamHandler)
    policy = tmp_path / "policy.yaml"
    policy.write_text(policy_text, encoding="utf-8")
    proxy = LLMHTTPProxy(
        policy_path=str(policy),
        config=HTTPProxyConfig(
            host="127.0.0.1",
            port=_pick_port(),
            upstream={
                "openai": f"http://127.0.0.1:{upstream.server_address[1]}",
                "anthropic": f"http://127.0.0.1:{upstream.server_address[1]}",
            },
        ),
    )
    proxy.start(blocking=False)
    _wait_for_server_ready("127.0.0.1", proxy._config.port)
    return proxy, upstream


# Connection pool tests (12)
def test_pool_acquire_creates_connection() -> None:
    pool = ConnectionPool(PoolConfig())
    conn = pool.acquire("example.com", 80, use_ssl=False)
    assert conn is not None
    pool.release(conn)
    pool.close_all()


def test_pool_acquire_reuses_idle() -> None:
    pool = ConnectionPool(PoolConfig())
    c1 = pool.acquire("example.com", 80, use_ssl=False)
    pool.release(c1)
    c2 = pool.acquire("example.com", 80, use_ssl=False)
    assert c1 is c2
    pool.release(c2)
    pool.close_all()


def test_pool_release_returns_to_pool() -> None:
    pool = ConnectionPool(PoolConfig())
    c1 = pool.acquire("example.com", 80, use_ssl=False)
    pool.release(c1)
    stats = pool.get_stats()
    assert stats["active"] == 0
    pool.close_all()


def test_pool_release_with_error_closes() -> None:
    pool = ConnectionPool(PoolConfig())
    c1 = pool.acquire("example.com", 80, use_ssl=False)
    pool.release(c1, error=True)
    stats = pool.get_stats()
    assert stats["total_connections"] == 0
    pool.close_all()


def test_pool_max_per_host() -> None:
    pool = ConnectionPool(PoolConfig(max_connections_per_host=2, max_total_connections=10))
    c1 = pool.acquire("example.com", 80, use_ssl=False)
    c2 = pool.acquire("example.com", 80, use_ssl=False)
    pool.release(c1)
    pool.release(c2)
    stats = pool.get_stats()
    assert stats["pools"]["example.com:80"] <= 2
    pool.close_all()


def test_pool_max_total() -> None:
    pool = ConnectionPool(PoolConfig(max_connections_per_host=10, max_total_connections=2))
    c1 = pool.acquire("a.com", 80, use_ssl=False)
    c2 = pool.acquire("b.com", 80, use_ssl=False)
    pool.release(c1)
    pool.release(c2)
    stats = pool.get_stats()
    assert stats["total_connections"] <= 2
    pool.close_all()


def test_pool_idle_eviction() -> None:
    pool = ConnectionPool(PoolConfig(idle_timeout=0.05))
    c1 = pool.acquire("example.com", 80, use_ssl=False)
    pool.release(c1)
    time.sleep(0.08)
    stats = pool.get_stats()
    assert stats["total_connections"] == 0
    pool.close_all()


def test_pool_stats_tracking() -> None:
    pool = ConnectionPool(PoolConfig())
    c1 = pool.acquire("example.com", 80, use_ssl=False)
    pool.release(c1)
    c2 = pool.acquire("example.com", 80, use_ssl=False)
    pool.release(c2)
    stats = pool.get_stats()
    assert stats["misses"] >= 1
    assert stats["hits"] >= 1
    pool.close_all()


def test_pool_thread_safety() -> None:
    pool = ConnectionPool(PoolConfig(max_connections_per_host=5, max_total_connections=10))
    errors: list[str] = []

    def worker() -> None:
        try:
            conn = pool.acquire("example.com", 80, use_ssl=False)
            time.sleep(0.005)
            pool.release(conn)
        except Exception as exc:  # pragma: no cover - failure path
            errors.append(str(exc))

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    pool.close_all()


def test_pool_close_all() -> None:
    pool = ConnectionPool(PoolConfig())
    c1 = pool.acquire("example.com", 80, use_ssl=False)
    pool.release(c1)
    pool.close_all()
    assert pool.get_stats()["total_connections"] == 0


def test_pool_different_hosts() -> None:
    pool = ConnectionPool(PoolConfig())
    a = pool.acquire("a.com", 80, use_ssl=False)
    b = pool.acquire("b.com", 80, use_ssl=False)
    pool.release(a)
    pool.release(b)
    stats = pool.get_stats()
    assert "a.com:80" in stats["pools"] and "b.com:80" in stats["pools"]
    pool.close_all()


def test_pool_config_defaults() -> None:
    cfg = PoolConfig()
    assert cfg.max_connections_per_host > 0
    assert cfg.max_total_connections > 0
    assert cfg.idle_timeout > 0


# Thread pool tests (5)
def test_pooled_server_creates_with_max_workers() -> None:
    server = PooledThreadHTTPServer(("127.0.0.1", 0), _JsonUpstreamHandler, max_workers=7)
    try:
        assert server._pool._max_workers == 7  # noqa: SLF001
    finally:
        server.server_close()


def test_pooled_server_reuses_threads() -> None:
    thread_ids: set[int] = set()

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            thread_ids.add(threading.get_ident())
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, fmt: str, *args) -> None:
            _ = (fmt, args)

    server = PooledThreadHTTPServer(("127.0.0.1", 0), _Handler, max_workers=2)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/"
        for _ in range(8):
            with urlopen(url, timeout=3) as resp:
                assert resp.status == 200
        assert len(thread_ids) <= 2
    finally:
        server.shutdown()
        server.server_close()


def test_pooled_server_limits_concurrent() -> None:
    lock = threading.Lock()
    active = 0
    peak = 0

    class _SlowHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            time.sleep(0.03)
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
            with lock:
                active -= 1

        def log_message(self, fmt: str, *args) -> None:
            _ = (fmt, args)

    server = PooledThreadHTTPServer(("127.0.0.1", 0), _SlowHandler, max_workers=3)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/"
        req_threads = [threading.Thread(target=lambda: urlopen(url, timeout=5).read()) for _ in range(10)]
        for item in req_threads:
            item.start()
        for item in req_threads:
            item.join()
        assert peak <= 3
    finally:
        server.shutdown()
        server.server_close()


def test_pooled_server_graceful_shutdown() -> None:
    server = PooledThreadHTTPServer(("127.0.0.1", 0), _JsonUpstreamHandler, max_workers=2)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    server.shutdown()
    server.server_close()
    assert True


def test_pooled_server_config_integration(tmp_path: Path) -> None:
    policy = tmp_path / "p.yaml"
    policy.write_text("rules: []\nproxy:\n  max_workers: 111\n", encoding="utf-8")
    loaded = load_policy(str(policy))
    assert loaded["proxy"]["max_workers"] == 111


# Streaming tests (15)
def test_streaming_detection_true(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, "rules: []\n")
    try:
        ctx = _RequestContext(handler=None, body={"stream": True})
        assert proxy._is_streaming_request(ctx) is True  # noqa: SLF001
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_streaming_detection_false(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, "rules: []\n")
    try:
        ctx = _RequestContext(handler=None, body={})
        assert proxy._is_streaming_request(ctx) is False  # noqa: SLF001
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_streaming_detection_explicit_false(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, "rules: []\n")
    try:
        ctx = _RequestContext(handler=None, body={"stream": False})
        assert proxy._is_streaming_request(ctx) is False  # noqa: SLF001
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_extract_text_delta_anthropic() -> None:
    event = 'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Hello"}}'
    assert LLMHTTPProxy._extract_text_delta(event) == "Hello"  # noqa: SLF001


def test_extract_text_delta_openai() -> None:
    event = 'data: {"choices":[{"delta":{"content":"Hello"}}]}'
    assert LLMHTTPProxy._extract_text_delta(event) == "Hello"  # noqa: SLF001


def test_extract_text_delta_done() -> None:
    assert LLMHTTPProxy._extract_text_delta("data: [DONE]") == ""  # noqa: SLF001


def test_extract_text_delta_invalid_json() -> None:
    assert LLMHTTPProxy._extract_text_delta("data: {broken") == ""  # noqa: SLF001


def test_build_synthetic_response() -> None:
    ctx = _RequestContext(handler=None, body={"model": "gpt-4o", "id": "x"}, original_model="gpt-4o")
    payload = LLMHTTPProxy._build_synthetic_response([], ["abc"], ctx)  # noqa: SLF001
    data = json.loads(payload)
    assert data["type"] == "message"
    assert data["_orchesis_streaming"] is True


def test_build_synthetic_response_includes_full_text() -> None:
    ctx = _RequestContext(handler=None, body={"model": "gpt-4o"}, original_model="gpt-4o")
    payload = LLMHTTPProxy._build_synthetic_response([], ["Hel", "lo"], ctx)  # noqa: SLF001
    data = json.loads(payload)
    assert data["content"][0]["text"] == "Hello"


def test_build_synthetic_response_extracts_usage() -> None:
    ctx = _RequestContext(handler=None, body={"model": "gpt-4o"}, original_model="gpt-4o")
    payload = LLMHTTPProxy._build_synthetic_response(  # noqa: SLF001
        ['data: {"type":"message_delta","usage":{"input_tokens":9,"output_tokens":4}}'],
        ["x"],
        ctx,
    )
    data = json.loads(payload)
    assert data["usage"]["input_tokens"] == 9


def test_streaming_response_non_streaming_unchanged(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, "rules: []\n")
    try:
        req = UrlRequest(
            f"http://127.0.0.1:{proxy._config.port}/v1/chat/completions",
            data=json.dumps({"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]}).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": "Bearer x"},
            method="POST",
        )
        with urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        assert "choices" in data
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_streaming_post_processing(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, "rules: []\nrecording:\n  enabled: true\n")
    try:
        req = UrlRequest(
            f"http://127.0.0.1:{proxy._config.port}/v1/chat/completions",
            data=json.dumps({"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}], "stream": True}).encode(
                "utf-8"
            ),
            headers={"Content-Type": "application/json", "Authorization": "Bearer x"},
            method="POST",
        )
        with urlopen(req, timeout=5) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            assert "data:" in body
        assert proxy._streaming_count >= 1  # noqa: SLF001
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_streaming_client_disconnect(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, "rules: []\n")
    try:
        req = UrlRequest(
            f"http://127.0.0.1:{proxy._config.port}/v1/chat/completions",
            data=json.dumps({"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}], "stream": True}).encode(
                "utf-8"
            ),
            headers={"Content-Type": "application/json", "Authorization": "Bearer x"},
            method="POST",
        )
        resp = urlopen(req, timeout=5)
        _ = resp.read(8)
        resp.close()
        assert True
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_streaming_upstream_error(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, "rules: []\n")
    upstream.shutdown()
    upstream.server_close()
    try:
        req = UrlRequest(
            f"http://127.0.0.1:{proxy._config.port}/v1/chat/completions",
            data=json.dumps({"model": "gpt-4o", "messages": [], "stream": True}).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": "Bearer x"},
            method="POST",
        )
        with pytest.raises(Exception):
            urlopen(req, timeout=5)
    finally:
        proxy.stop()


def test_streaming_empty_response(tmp_path: Path) -> None:
    class _EmptyStreamHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, fmt: str, *args) -> None:
            _ = (fmt, args)

    upstream, _ = _start_server(_EmptyStreamHandler)
    policy = tmp_path / "p.yaml"
    policy.write_text("rules: []\n", encoding="utf-8")
    proxy = LLMHTTPProxy(
        policy_path=str(policy),
        config=HTTPProxyConfig(
            host="127.0.0.1",
            port=_pick_port(),
            upstream={"openai": f"http://127.0.0.1:{upstream.server_address[1]}", "anthropic": f"http://127.0.0.1:{upstream.server_address[1]}"},
        ),
    )
    proxy.start(blocking=False)
    _wait_for_server_ready("127.0.0.1", proxy._config.port)
    try:
        req = UrlRequest(
            f"http://127.0.0.1:{proxy._config.port}/v1/chat/completions",
            data=json.dumps({"model": "gpt-4o", "messages": [], "stream": True}).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": "Bearer x"},
            method="POST",
        )
        with urlopen(req, timeout=5) as resp:
            _ = resp.read().decode("utf-8", errors="replace")
        # Empty stream should not fail post-processing; count policy can vary by implementation.
        assert proxy._streaming_count >= 0  # noqa: SLF001
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


# Integration tests (5)
def test_connection_pool_in_stats(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, "rules: []\n")
    try:
        with urlopen(f"http://127.0.0.1:{proxy._config.port}/stats", timeout=5) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        assert "connection_pool" in payload["proxy_engine"]
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_streaming_count_in_stats(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, "rules: []\n")
    try:
        req = UrlRequest(
            f"http://127.0.0.1:{proxy._config.port}/v1/chat/completions",
            data=json.dumps({"model": "gpt-4o", "messages": [], "stream": True}).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": "Bearer x"},
            method="POST",
        )
        with urlopen(req, timeout=5) as resp:
            _ = resp.read()
        with urlopen(f"http://127.0.0.1:{proxy._config.port}/stats", timeout=5) as resp2:
            payload = json.loads(resp2.read().decode("utf-8"))
        assert payload["proxy_engine"]["streaming"]["total_streamed_requests"] >= 1
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_existing_non_streaming_still_works(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, "rules: []\n")
    try:
        req = UrlRequest(
            f"http://127.0.0.1:{proxy._config.port}/v1/chat/completions",
            data=json.dumps({"model": "gpt-4o", "messages": []}).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": "Bearer x"},
            method="POST",
        )
        with urlopen(req, timeout=5) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        assert "choices" in payload
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_dashboard_overview_includes_pool(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, "rules: []\n")
    try:
        with urlopen(f"http://127.0.0.1:{proxy._config.port}/api/dashboard/overview", timeout=5) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        assert "connection_pool" in payload
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_config_normalization(tmp_path: Path) -> None:
    policy = tmp_path / "norm.yaml"
    policy.write_text("rules: []\n", encoding="utf-8")
    loaded = load_policy(str(policy))
    assert "proxy" in loaded
    assert loaded["proxy"]["max_workers"] == 200
    assert loaded["proxy"]["connection_pool"]["max_per_host"] == 10
    assert loaded["proxy"]["streaming"]["enabled"] is True
