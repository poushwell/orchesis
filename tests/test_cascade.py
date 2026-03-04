from __future__ import annotations

import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.request import Request as UrlRequest, urlopen

from orchesis.cascade import CascadeClassifier, CascadeDecision, CascadeLevel, CascadeRouter, ResponseCache
from orchesis.proxy import HTTPProxyConfig, LLMHTTPProxy
from orchesis.request_parser import ParsedRequest, ParsedResponse, ToolCall


def _request(
    text: str = "",
    tools: int = 0,
    tool_defs: int = 0,
    model: str = "claude-opus-4",
) -> ParsedRequest:
    return ParsedRequest(
        provider="openai",
        model=model,
        messages=[{"role": "user", "content": text}],
        content_text=text,
        tool_calls=[ToolCall(name=f"t{i}", params={}) for i in range(tools)],
        tool_definitions=[{"name": f"d{i}"} for i in range(tool_defs)],
        raw_body={"model": model},
    )


def _default_cascade_cfg(enabled: bool = True) -> dict:
    return {
        "enabled": enabled,
        "levels": {
            "trivial": {"action": "cache"},
            "simple": {"model": "claude-haiku-4", "max_tokens": 1024},
            "medium": {"model": "claude-sonnet-4", "max_tokens": 4096},
            "complex": {"model": "claude-opus-4", "max_tokens": 8192},
        },
        "auto_escalate": {"enabled": True, "on_error": True, "on_low_confidence": True},
        "cache": {"enabled": True, "ttl_seconds": 1, "max_entries": 2},
    }


def test_classifier_short_text_no_tools_simple() -> None:
    level = CascadeClassifier().classify(_request("hello world", tools=0))
    assert level == CascadeLevel.SIMPLE


def test_classifier_long_text_with_tools_complex() -> None:
    level = CascadeClassifier().classify(_request("x" * 9000, tools=3))
    assert level == CascadeLevel.COMPLEX


def test_classifier_code_keywords_boost() -> None:
    level = CascadeClassifier().classify(_request("please debug python code issue", tools=0))
    assert level >= CascadeLevel.MEDIUM


def test_classifier_math_keywords_boost() -> None:
    level = CascadeClassifier().classify(_request("solve math equation with steps", tools=0))
    assert level >= CascadeLevel.MEDIUM


def test_classifier_multiple_tools_medium_or_complex() -> None:
    level = CascadeClassifier().classify(_request("run tools", tools=2))
    assert level in {CascadeLevel.MEDIUM, CascadeLevel.COMPLEX}


def test_classifier_empty_request_trivial() -> None:
    level = CascadeClassifier().classify(_request("", tools=0))
    assert level == CascadeLevel.TRIVIAL


def test_classifier_retry_context_escalates() -> None:
    clf = CascadeClassifier()
    req1 = _request("first attempt")
    req2 = _request("second attempt changed")
    _ = clf.classify(req1, context={"task_id": "t1"})
    level2 = clf.classify(req2, context={"task_id": "t1"})
    assert level2 >= CascadeLevel.MEDIUM


def test_classifier_many_tool_definitions_boost() -> None:
    level = CascadeClassifier().classify(_request("normal", tools=0, tool_defs=25))
    assert level >= CascadeLevel.MEDIUM


def test_classifier_previous_failed_attempts_escalates() -> None:
    level = CascadeClassifier().classify(_request("simple"), context={"previous_failed_attempts": True})
    assert level >= CascadeLevel.MEDIUM


def test_classifier_very_long_text_complex() -> None:
    level = CascadeClassifier().classify(_request("a" * 12000))
    assert level == CascadeLevel.COMPLEX


def test_router_routes_simple_to_haiku() -> None:
    router = CascadeRouter(_default_cascade_cfg())
    decision = router.route(_request("short question"))
    assert decision.model == "claude-haiku-4"


def test_router_routes_medium_to_sonnet() -> None:
    router = CascadeRouter(_default_cascade_cfg())
    decision = router.route(_request("analyze and compare two strategies"))
    assert decision.model == "claude-sonnet-4"


def test_router_routes_complex_to_opus() -> None:
    router = CascadeRouter(_default_cascade_cfg())
    decision = router.route(_request("x" * 9000, tools=4))
    assert decision.model == "claude-opus-4"


def test_router_cache_hit_returns_payload() -> None:
    router = CascadeRouter(_default_cascade_cfg())
    req = _request("repeat me")
    key = router.make_cache_key(req, "claude-haiku-4")
    router.cache_response(CascadeDecision("claude-haiku-4", 1024, CascadeLevel.SIMPLE, cache_key=key), b'{"ok":1}')
    hit = router.get_cache(key, CascadeLevel.SIMPLE)
    assert hit == b'{"ok":1}'


def test_router_cache_miss_falls_through() -> None:
    router = CascadeRouter(_default_cascade_cfg())
    miss = router.get_cache("missing", CascadeLevel.SIMPLE)
    assert miss is None


def test_router_cache_ttl_expiry_works() -> None:
    router = CascadeRouter(_default_cascade_cfg())
    req = _request("ttl")
    key = router.make_cache_key(req, "claude-haiku-4")
    router.cache_response(CascadeDecision("claude-haiku-4", 1024, CascadeLevel.SIMPLE, cache_key=key), b"x")
    time.sleep(1.1)
    assert router.get_cache(key, CascadeLevel.SIMPLE) is None


def test_router_cache_max_entries_lru() -> None:
    cache = ResponseCache(ttl_seconds=30, max_entries=2)
    cache.set("a", b"1")
    cache.set("b", b"2")
    _ = cache.get("a")
    cache.set("c", b"3")
    assert cache.get("b") is None
    assert cache.get("a") == b"1"
    assert cache.get("c") == b"3"


def test_router_auto_escalate_on_error_flag() -> None:
    router = CascadeRouter(_default_cascade_cfg())
    assert router.should_escalate(500, None) is True


def test_router_config_disabled_passthrough() -> None:
    router = CascadeRouter(_default_cascade_cfg(enabled=False))
    decision = router.route(_request("short", model="gpt-4o"))
    assert decision.model == "gpt-4o"


def test_router_missing_level_config_fallback_default_model() -> None:
    cfg = _default_cascade_cfg()
    cfg["levels"].pop("simple", None)
    router = CascadeRouter(cfg)
    decision = router.route(_request("short", model="gpt-4o"))
    assert decision.model == "gpt-4o"


def test_response_cache_store_and_retrieve() -> None:
    cache = ResponseCache(ttl_seconds=30, max_entries=10)
    cache.set("x", b"payload")
    assert cache.get("x") == b"payload"


def test_response_cache_ttl_expiry() -> None:
    cache = ResponseCache(ttl_seconds=1, max_entries=10)
    cache.set("x", b"payload")
    time.sleep(1.1)
    assert cache.get("x") is None


def test_response_cache_lru_eviction_at_max_entries() -> None:
    cache = ResponseCache(ttl_seconds=30, max_entries=2)
    cache.set("a", b"a")
    cache.set("b", b"b")
    cache.set("c", b"c")
    assert cache.get("a") is None
    assert cache.get("b") == b"b"
    assert cache.get("c") == b"c"


def test_response_cache_thread_safe_concurrent_access() -> None:
    cache = ResponseCache(ttl_seconds=30, max_entries=100)

    def worker(prefix: str) -> None:
        for i in range(100):
            key = f"{prefix}-{i}"
            cache.set(key, key.encode("utf-8"))
            _ = cache.get(key)

    threads = [threading.Thread(target=worker, args=(f"t{idx}",)) for idx in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert cache.size() <= 100


def test_response_cache_different_requests_different_cache_keys() -> None:
    router = CascadeRouter(_default_cascade_cfg())
    k1 = router.make_cache_key(_request("one"), "claude-haiku-4")
    k2 = router.make_cache_key(_request("two"), "claude-haiku-4")
    assert k1 != k2


def test_router_level_name_helper() -> None:
    router = CascadeRouter(_default_cascade_cfg())
    assert router.level_name(CascadeLevel.MEDIUM) == "medium"


def test_router_record_result_callable() -> None:
    router = CascadeRouter(_default_cascade_cfg())
    decision = router.route(_request("hello"))
    router.record_result(decision, ParsedResponse(provider="openai", model=decision.model))


class _CascadeUpstreamHandler(BaseHTTPRequestHandler):
    status_code = 200
    first_fail_then_ok = False
    calls = 0
    captured_models: list[str] = []

    def do_POST(self) -> None:  # noqa: N802
        body_len = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(body_len)
        payload = json.loads(raw.decode("utf-8"))
        self.__class__.calls += 1
        self.__class__.captured_models.append(str(payload.get("model", "")))
        status = self.__class__.status_code
        if self.__class__.first_fail_then_ok and self.__class__.calls == 1:
            status = 500
            resp = {"error": "retry me"}
        else:
            resp = {
                "model": str(payload.get("model", "claude-haiku-4")),
                "usage": {"prompt_tokens": 20, "completion_tokens": 10},
                "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
            }
        data = json.dumps(resp).encode("utf-8")
        self.send_response(status)
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


def _post_json(port: int, body: dict) -> tuple[int, dict[str, str]]:
    req = UrlRequest(
        f"http://127.0.0.1:{port}/v1/chat/completions",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": "Bearer t"},
        method="POST",
    )
    with urlopen(req, timeout=5) as resp:
        _ = json.loads(resp.read().decode("utf-8"))
        return int(resp.status), dict(resp.headers.items())


def test_proxy_integration_cascade_level_header_present(tmp_path: Path) -> None:
    _CascadeUpstreamHandler.calls = 0
    _CascadeUpstreamHandler.captured_models = []
    _CascadeUpstreamHandler.first_fail_then_ok = False
    upstream, _ = _start_http_server(_CascadeUpstreamHandler)
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        """
rules: []
cascade:
  enabled: true
  levels:
    simple:
      model: claude-haiku-4
      max_tokens: 512
    medium:
      model: claude-sonnet-4
      max_tokens: 2048
    complex:
      model: claude-opus-4
      max_tokens: 4096
  auto_escalate:
    enabled: true
    on_error: true
    on_low_confidence: true
  cache:
    enabled: true
    ttl_seconds: 300
    max_entries: 100
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
        status, headers = _post_json(port, {"model": "claude-opus-4", "messages": [{"role": "user", "content": "hello"}]})
        assert status == 200
        assert "X-Orchesis-Cascade-Level" in headers
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_proxy_integration_cache_header_present(tmp_path: Path) -> None:
    _CascadeUpstreamHandler.calls = 0
    _CascadeUpstreamHandler.captured_models = []
    _CascadeUpstreamHandler.first_fail_then_ok = False
    upstream, _ = _start_http_server(_CascadeUpstreamHandler)
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        """
rules: []
cascade:
  enabled: true
  levels:
    simple:
      model: claude-haiku-4
      max_tokens: 512
  cache:
    enabled: true
    ttl_seconds: 300
    max_entries: 100
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
        _ = _post_json(port, {"model": "claude-opus-4", "messages": [{"role": "user", "content": "same"}]})
        _, headers_second = _post_json(port, {"model": "claude-opus-4", "messages": [{"role": "user", "content": "same"}]})
        assert headers_second.get("X-Orchesis-Cache") in {"hit", "miss"}
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_proxy_stats_include_cascade_savings(tmp_path: Path) -> None:
    _CascadeUpstreamHandler.calls = 0
    _CascadeUpstreamHandler.captured_models = []
    _CascadeUpstreamHandler.first_fail_then_ok = False
    upstream, _ = _start_http_server(_CascadeUpstreamHandler)
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        """
rules: []
cascade:
  enabled: true
  levels:
    simple:
      model: claude-haiku-4
      max_tokens: 512
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
        _ = _post_json(port, {"model": "claude-opus-4", "messages": [{"role": "user", "content": "cheap route"}]})
        with urlopen(f"http://127.0.0.1:{port}/stats", timeout=3) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        assert "cascade_savings_today_usd" in payload
        assert "cache_hit_rate_percent" in payload
        assert "cache_entries_count" in payload
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_proxy_auto_escalate_retries_with_higher_level(tmp_path: Path) -> None:
    _CascadeUpstreamHandler.calls = 0
    _CascadeUpstreamHandler.captured_models = []
    _CascadeUpstreamHandler.first_fail_then_ok = True
    upstream, _ = _start_http_server(_CascadeUpstreamHandler)
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        """
rules: []
cascade:
  enabled: true
  levels:
    simple:
      model: claude-haiku-4
      max_tokens: 512
    medium:
      model: claude-sonnet-4
      max_tokens: 2048
  auto_escalate:
    enabled: true
    on_error: true
    on_low_confidence: true
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
        status, headers = _post_json(port, {"model": "claude-opus-4", "messages": [{"role": "user", "content": "short"}]})
        assert status == 200
        assert _CascadeUpstreamHandler.calls >= 2
        assert headers.get("X-Orchesis-Cascade-Model") in {"claude-sonnet-4", "claude-haiku-4"}
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()
