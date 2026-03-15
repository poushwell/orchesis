from __future__ import annotations

import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request as UrlRequest, urlopen

from orchesis.proxy import HTTPProxyConfig, LLMHTTPProxy


class _EchoUpstreamHandler(BaseHTTPRequestHandler):
    response_status = 200
    response_body = {
        "id": "ok",
        "model": "gpt-4o-mini",
        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
        "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
    }
    captured_paths: list[str] = []

    def do_POST(self) -> None:  # noqa: N802
        self.__class__.captured_paths.append(self.path)
        body = json.dumps(self.__class__.response_body).encode("utf-8")
        self.send_response(self.__class__.response_status)
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
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = int(sock.getsockname()[1])
    return port


def _post_json(port: int, path: str, payload: dict | None) -> tuple[int, dict, dict[str, str]]:
    data = b"" if payload is None else json.dumps(payload).encode("utf-8")
    req = UrlRequest(
        f"http://127.0.0.1:{port}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    last_error: ConnectionAbortedError | ConnectionRefusedError | None = None
    for attempt in range(3):
        try:
            with urlopen(req, timeout=3) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                return int(resp.status), body, dict(resp.headers.items())
        except HTTPError as error:
            body = json.loads(error.read().decode("utf-8"))
            return int(error.code), body, dict(error.headers.items())
        except (ConnectionAbortedError, ConnectionRefusedError) as error:
            last_error = error
            if attempt < 2:
                time.sleep(0.1)
                continue
    if last_error is not None:
        raise last_error
    raise RuntimeError("unexpected request failure")


def _get_json(port: int, path: str) -> tuple[int, dict]:
    with urlopen(f"http://127.0.0.1:{port}{path}", timeout=3) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
        return int(resp.status), payload


def _chat_body(content: str = "hello") -> dict:
    return {"model": "gpt-4o", "messages": [{"role": "user", "content": content}]}


def _tool_call_body() -> dict:
    return {
        "model": "gpt-4o",
        "messages": [
            {
                "role": "assistant",
                "tool_calls": [
                    {"id": "x", "type": "function", "function": {"name": "web_search", "arguments": '{"query":"x"}'}}
                ],
            }
        ],
    }


def _start_proxy(tmp_path: Path, policy_text: str | None = None) -> tuple[LLMHTTPProxy, HTTPServer]:
    upstream_server, _ = _start_http_server(_EchoUpstreamHandler)
    port = _pick_free_port()
    config = HTTPProxyConfig(
        host="127.0.0.1",
        port=port,
        upstream={
            "openai": f"http://127.0.0.1:{upstream_server.server_address[1]}",
            "anthropic": f"http://127.0.0.1:{upstream_server.server_address[1]}",
        },
    )
    if policy_text is not None:
        policy = tmp_path / f"policy_{port}.yaml"
        policy.write_text(policy_text, encoding="utf-8")
        proxy = LLMHTTPProxy(policy_path=str(policy), config=config)
    else:
        proxy = LLMHTTPProxy(config=config)
    proxy.start(blocking=False)
    return proxy, upstream_server


def _stop_proxy(proxy: LLMHTTPProxy, upstream_server: HTTPServer) -> None:
    proxy.stop()
    upstream_server.shutdown()
    upstream_server.server_close()


def test_manual_kill_blocks_all_requests(tmp_path: Path) -> None:
    proxy, upstream = _start_proxy(tmp_path)
    try:
        _post_json(proxy._config.port, "/kill", {"reason": "manual stop"})
        code, payload, _ = _post_json(proxy._config.port, "/v1/chat/completions", _chat_body())
        assert code == 503
        assert payload["error"]["type"] == "kill_switch"
    finally:
        _stop_proxy(proxy, upstream)


def test_resume_with_correct_token_reenables_requests(tmp_path: Path) -> None:
    policy = "rules: []\nkill_switch:\n  enabled: true\n  resume_token: good\n"
    proxy, upstream = _start_proxy(tmp_path, policy)
    try:
        _post_json(proxy._config.port, "/kill", {"reason": "manual"})
        code, _, _ = _post_json(proxy._config.port, "/resume", {"token": "good"})
        assert code == 200
        code2, _, _ = _post_json(proxy._config.port, "/v1/chat/completions", _chat_body())
        assert code2 == 200
    finally:
        _stop_proxy(proxy, upstream)


def test_resume_with_wrong_token_rejected(tmp_path: Path) -> None:
    policy = "rules: []\nkill_switch:\n  enabled: true\n  resume_token: right-token\n"
    proxy, upstream = _start_proxy(tmp_path, policy)
    try:
        _post_json(proxy._config.port, "/kill", {"reason": "manual"})
        code, payload, _ = _post_json(proxy._config.port, "/resume", {"token": "wrong"})
        assert code == 403
        assert payload["error"]["type"] == "invalid_resume_token"
    finally:
        _stop_proxy(proxy, upstream)


def test_kill_reason_appears_in_health_and_error(tmp_path: Path) -> None:
    proxy, upstream = _start_proxy(tmp_path)
    try:
        _post_json(proxy._config.port, "/kill", {"reason": "operator intervention"})
        _, health = _get_json(proxy._config.port, "/health")
        code, payload, _ = _post_json(proxy._config.port, "/v1/chat/completions", _chat_body())
        assert health["kill_reason"] == "operator intervention"
        assert code == 503
        assert "operator intervention" in payload["error"]["message"]
    finally:
        _stop_proxy(proxy, upstream)


def test_auto_kill_on_cost_threshold(tmp_path: Path) -> None:
    policy = (
        "rules: []\n"
        "budgets:\n  daily: 1.0\n"
        "kill_switch:\n"
        "  enabled: true\n"
        "  auto_triggers:\n"
        "    cost_multiplier: 2\n"
    )
    proxy, upstream = _start_proxy(tmp_path, policy)
    try:
        proxy.cost_tracker.record_call("web_search", cost_override=2.1)
        code, payload, _ = _post_json(proxy._config.port, "/v1/chat/completions", _chat_body())
        assert code == 503
        assert payload["error"]["type"] == "kill_switch"
    finally:
        _stop_proxy(proxy, upstream)


def test_auto_kill_on_secrets_threshold(tmp_path: Path) -> None:
    policy = (
        "rules: []\n"
        "kill_switch:\n"
        "  enabled: true\n"
        "  auto_triggers:\n"
        "    secrets_threshold: 1\n"
    )
    proxy, upstream = _start_proxy(tmp_path, policy)
    try:
        body = _chat_body("token sk-abcdefghijklmnopqrstuvwxyz123")
        code, payload, _ = _post_json(proxy._config.port, "/v1/chat/completions", body)
        assert code == 503
        assert payload["error"]["type"] == "kill_switch"
    finally:
        _stop_proxy(proxy, upstream)


def test_auto_kill_on_loops_threshold(tmp_path: Path) -> None:
    policy = (
        "rules: []\n"
        "loop_detection:\n"
        "  enabled: true\n"
        "  warn_threshold: 1\n"
        "  block_threshold: 1\n"
        "  window_seconds: 60\n"
        "kill_switch:\n"
        "  enabled: true\n"
        "  auto_triggers:\n"
        "    loops_threshold: 1\n"
    )
    proxy, upstream = _start_proxy(tmp_path, policy)
    try:
        code, payload, _ = _post_json(proxy._config.port, "/v1/chat/completions", _tool_call_body())
        assert code == 503
        assert payload["error"]["type"] == "kill_switch"
    finally:
        _stop_proxy(proxy, upstream)


def test_kill_state_persists_across_requests(tmp_path: Path) -> None:
    proxy, upstream = _start_proxy(tmp_path)
    try:
        _post_json(proxy._config.port, "/kill", {"reason": "persist"})
        code1, _, _ = _post_json(proxy._config.port, "/v1/chat/completions", _chat_body())
        code2, _, _ = _post_json(proxy._config.port, "/v1/chat/completions", _chat_body())
        assert code1 == 503
        assert code2 == 503
    finally:
        _stop_proxy(proxy, upstream)


def test_kill_switch_disabled_by_default_when_missing_in_config(tmp_path: Path) -> None:
    proxy, upstream = _start_proxy(tmp_path, "rules: []\n")
    try:
        _, stats = _get_json(proxy._config.port, "/stats")
        assert stats["kill_switch"]["enabled"] is False
    finally:
        _stop_proxy(proxy, upstream)


def test_health_shows_killed_state(tmp_path: Path) -> None:
    proxy, upstream = _start_proxy(tmp_path)
    try:
        _, health_before = _get_json(proxy._config.port, "/health")
        _post_json(proxy._config.port, "/kill", {"reason": "check"})
        _, health_after = _get_json(proxy._config.port, "/health")
        assert health_before["killed"] is False
        assert health_after["killed"] is True
    finally:
        _stop_proxy(proxy, upstream)


def test_kill_without_body_uses_default_reason(tmp_path: Path) -> None:
    proxy, upstream = _start_proxy(tmp_path)
    try:
        _, payload, _ = _post_json(proxy._config.port, "/kill", None)
        assert payload["reason"] == "manual emergency shutdown"
    finally:
        _stop_proxy(proxy, upstream)


def test_kill_when_already_killed_updates_reason(tmp_path: Path) -> None:
    proxy, upstream = _start_proxy(tmp_path)
    try:
        _post_json(proxy._config.port, "/kill", {"reason": "first"})
        _post_json(proxy._config.port, "/kill", {"reason": "second"})
        _, health = _get_json(proxy._config.port, "/health")
        assert health["kill_reason"] == "second"
    finally:
        _stop_proxy(proxy, upstream)


def test_kill_response_includes_killed_at_timestamp(tmp_path: Path) -> None:
    proxy, upstream = _start_proxy(tmp_path)
    try:
        _post_json(proxy._config.port, "/kill", {"reason": "timestamp"})
        code, payload, _ = _post_json(proxy._config.port, "/v1/chat/completions", _chat_body())
        assert code == 503
        assert isinstance(payload["error"]["killed_at"], str)
        assert payload["error"]["killed_at"]
    finally:
        _stop_proxy(proxy, upstream)


def test_stats_reflect_kill_switch_activations_count(tmp_path: Path) -> None:
    proxy, upstream = _start_proxy(tmp_path)
    try:
        _post_json(proxy._config.port, "/kill", {"reason": "one"})
        _post_json(proxy._config.port, "/kill", {"reason": "two"})
        _, stats = _get_json(proxy._config.port, "/stats")
        assert stats["kill_switch_activations"] >= 2
    finally:
        _stop_proxy(proxy, upstream)


def test_resume_clears_reason_and_timestamp(tmp_path: Path) -> None:
    policy = "rules: []\nkill_switch:\n  enabled: true\n  resume_token: t\n"
    proxy, upstream = _start_proxy(tmp_path, policy)
    try:
        _post_json(proxy._config.port, "/kill", {"reason": "clear"})
        _post_json(proxy._config.port, "/resume", {"token": "t"})
        _, health = _get_json(proxy._config.port, "/health")
        assert health["killed"] is False
        assert health["kill_reason"] == ""
        assert health["killed_at"] == ""
    finally:
        _stop_proxy(proxy, upstream)


def test_stats_include_kill_switch_object(tmp_path: Path) -> None:
    proxy, upstream = _start_proxy(tmp_path)
    try:
        _, stats = _get_json(proxy._config.port, "/stats")
        assert "kill_switch" in stats
        assert "killed" in stats["kill_switch"]
    finally:
        _stop_proxy(proxy, upstream)


def test_stats_show_killed_state_after_activation(tmp_path: Path) -> None:
    proxy, upstream = _start_proxy(tmp_path)
    try:
        _post_json(proxy._config.port, "/kill", {"reason": "for stats"})
        _, stats = _get_json(proxy._config.port, "/stats")
        assert stats["kill_switch"]["killed"] is True
    finally:
        _stop_proxy(proxy, upstream)


def test_kill_with_invalid_body_defaults_reason(tmp_path: Path) -> None:
    proxy, upstream = _start_proxy(tmp_path)
    try:
        req = UrlRequest(
            f"http://127.0.0.1:{proxy._config.port}/kill",
            data=b"{bad json",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(req, timeout=3) as response:
            payload = json.loads(response.read().decode("utf-8"))
        assert payload["reason"] == "manual emergency shutdown"
    finally:
        _stop_proxy(proxy, upstream)


def test_resume_without_token_rejected(tmp_path: Path) -> None:
    policy = "rules: []\nkill_switch:\n  enabled: true\n  resume_token: t\n"
    proxy, upstream = _start_proxy(tmp_path, policy)
    try:
        _post_json(proxy._config.port, "/kill", {"reason": "manual"})
        code, payload, _ = _post_json(proxy._config.port, "/resume", {})
        assert code == 403
        assert payload["error"]["type"] == "invalid_resume_token"
    finally:
        _stop_proxy(proxy, upstream)


def test_resume_when_not_killed_returns_ok(tmp_path: Path) -> None:
    policy = "rules: []\nkill_switch:\n  enabled: true\n  resume_token: t\n"
    proxy, upstream = _start_proxy(tmp_path, policy)
    try:
        code, payload, _ = _post_json(proxy._config.port, "/resume", {"token": "t"})
        assert code == 200
        assert payload["status"] == "resumed"
    finally:
        _stop_proxy(proxy, upstream)


def test_kill_works_while_already_killed_and_increments_counter(tmp_path: Path) -> None:
    proxy, upstream = _start_proxy(tmp_path)
    try:
        _post_json(proxy._config.port, "/kill", {"reason": "1"})
        _post_json(proxy._config.port, "/kill", {"reason": "2"})
        _post_json(proxy._config.port, "/kill", {"reason": "3"})
        _, stats = _get_json(proxy._config.port, "/stats")
        assert stats["kill_switch_activations"] >= 3
    finally:
        _stop_proxy(proxy, upstream)


def test_killed_state_blocks_before_json_validation(tmp_path: Path) -> None:
    proxy, upstream = _start_proxy(tmp_path)
    try:
        _post_json(proxy._config.port, "/kill", {"reason": "priority"})
        req = UrlRequest(
            f"http://127.0.0.1:{proxy._config.port}/v1/chat/completions",
            data=b"{bad",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urlopen(req, timeout=3)
            raise AssertionError("Expected HTTPError")
        except HTTPError as error:
            body = json.loads(error.read().decode("utf-8"))
            assert error.code == 503
            assert body["error"]["type"] == "kill_switch"
        except ConnectionAbortedError:
            # On some Windows runs, the socket is aborted before HTTP body is readable.
            _, stats = _get_json(proxy._config.port, "/stats")
            assert stats["killed"] is True
    finally:
        _stop_proxy(proxy, upstream)
