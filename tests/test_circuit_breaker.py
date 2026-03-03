from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request as UrlRequest, urlopen

import pytest

from orchesis.circuit_breaker import CircuitBreaker
from orchesis.proxy import HTTPProxyConfig, LLMHTTPProxy


def test_closed_to_open_after_threshold_errors() -> None:
    cb = CircuitBreaker(enabled=True, error_threshold=3, window_seconds=60)
    cb.record_failure()
    cb.record_failure()
    assert cb.get_state() == "CLOSED"
    cb.record_failure()
    assert cb.get_state() == "OPEN"


def test_open_state_blocks_requests() -> None:
    cb = CircuitBreaker(enabled=True, error_threshold=1, cooldown_seconds=30)
    cb.record_failure()
    assert cb.should_allow() is False


def test_open_to_half_open_after_cooldown() -> None:
    cb = CircuitBreaker(enabled=True, error_threshold=1, cooldown_seconds=1)
    cb.record_failure()
    time.sleep(1.1)
    assert cb.should_allow() is True
    assert cb.get_state() == "HALF_OPEN"


def test_half_open_to_closed_on_success() -> None:
    cb = CircuitBreaker(enabled=True, error_threshold=1, cooldown_seconds=1)
    cb.record_failure()
    time.sleep(1.1)
    assert cb.should_allow() is True
    cb.record_success()
    assert cb.get_state() == "CLOSED"


def test_half_open_to_open_on_failure_with_backoff() -> None:
    cb = CircuitBreaker(enabled=True, error_threshold=1, cooldown_seconds=1, max_cooldown_seconds=8)
    cb.record_failure()
    time.sleep(1.1)
    assert cb.should_allow() is True
    cb.record_failure()
    stats = cb.get_stats()
    assert cb.get_state() == "OPEN"
    assert stats["trip_count"] >= 2


def test_failures_outside_window_not_counted() -> None:
    cb = CircuitBreaker(enabled=True, error_threshold=2, window_seconds=1)
    cb.record_failure()
    time.sleep(1.1)
    cb.record_failure()
    assert cb.get_state() == "CLOSED"


def test_reset_resets_state() -> None:
    cb = CircuitBreaker(enabled=True, error_threshold=1)
    cb.record_failure()
    assert cb.get_state() == "OPEN"
    cb.reset()
    assert cb.get_state() == "CLOSED"
    assert cb.get_stats()["trip_count"] == 0


def test_thread_safety_concurrent_failures() -> None:
    cb = CircuitBreaker(enabled=True, error_threshold=50, window_seconds=60)

    def worker() -> None:
        for _ in range(100):
            cb.record_failure()

    with ThreadPoolExecutor(max_workers=8) as pool:
        for _ in range(8):
            pool.submit(worker)
    stats = cb.get_stats()
    assert stats["error_count"] >= 50


def test_get_stats_fields_present() -> None:
    cb = CircuitBreaker(enabled=True)
    stats = cb.get_stats()
    assert "state" in stats
    assert "trip_count" in stats
    assert "error_count" in stats
    assert "cooldown_remaining" in stats


class _FailingUpstreamHandler(BaseHTTPRequestHandler):
    status_code = 500
    calls = 0

    def do_POST(self) -> None:  # noqa: N802
        self.__class__.calls += 1
        body = json.dumps({"error": "upstream failed"}).encode("utf-8")
        self.send_response(self.__class__.status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

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


def test_proxy_integration_fallback_and_header(tmp_path: Path) -> None:
    _FailingUpstreamHandler.calls = 0
    upstream, _ = _start_http_server(_FailingUpstreamHandler)
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        """
rules: []
circuit_breaker:
  enabled: true
  error_threshold: 1
  window_seconds: 60
  cooldown_seconds: 30
  max_cooldown_seconds: 300
  half_open_max_requests: 1
  fallback_status: 503
  fallback_message: "Service temporarily unavailable. Circuit breaker is open."
""".strip(),
        encoding="utf-8",
    )
    port = _pick_free_port()
    proxy = LLMHTTPProxy(
        policy_path=str(policy),
        config=HTTPProxyConfig(
            host="127.0.0.1",
            port=port,
            upstream={"openai": f"http://127.0.0.1:{upstream.server_address[1]}", "anthropic": f"http://127.0.0.1:{upstream.server_address[1]}"},
        ),
    )
    proxy.start(blocking=False)
    try:
        req = UrlRequest(
            f"http://127.0.0.1:{port}/v1/chat/completions",
            data=json.dumps({"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]}).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": "Bearer x"},
            method="POST",
        )
        with pytest.raises(HTTPError) as first:
            urlopen(req, timeout=3)
        assert first.value.code == 500
        with pytest.raises(HTTPError) as second:
            urlopen(req, timeout=3)
        assert second.value.code == 503
        body = json.loads(second.value.read().decode("utf-8"))
        assert body["error"]["type"] == "circuit_open"
        assert second.value.headers.get("X-Orchesis-Circuit") == "open"
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()
