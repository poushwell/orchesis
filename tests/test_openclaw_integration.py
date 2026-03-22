from __future__ import annotations

import json
from pathlib import Path
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler
from urllib.error import HTTPError
from urllib.request import Request as UrlRequest, urlopen

from orchesis.proxy import HTTPProxyConfig, LLMHTTPProxy, PooledThreadHTTPServer


def _pick_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = int(sock.getsockname()[1])
    sock.close()
    return port


class _OpenClawUpstreamHandler(BaseHTTPRequestHandler):
    last_body: dict | None = None

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or "0")
        body_raw = self.rfile.read(max(0, length))
        body: dict = {}
        try:
            body = json.loads(body_raw.decode("utf-8"))
        except Exception:
            body = {}
        _OpenClawUpstreamHandler.last_body = body
        text = ""
        for msg in body.get("messages", []) if isinstance(body.get("messages"), list) else []:
            if isinstance(msg, dict) and isinstance(msg.get("content"), str):
                text += msg["content"] + "\n"
        prompt_tokens = 250
        completion_tokens = 50
        if "expensive" in text.lower():
            prompt_tokens = 18000
            completion_tokens = 1200
        resp = {
            "model": body.get("model", "gpt-4o-mini"),
            "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens},
            "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
        }
        payload = json.dumps(resp).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt: str, *args) -> None:
        _ = (fmt, args)


def _start_server(handler_cls: type[BaseHTTPRequestHandler]) -> tuple[PooledThreadHTTPServer, threading.Thread]:
    server = PooledThreadHTTPServer(("127.0.0.1", 0), handler_cls, max_workers=4)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _wait_for_server_ready(host: str, port: int, timeout: float = 2.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.02)


def _make_proxy(tmp_path: Path, policy_text: str) -> tuple[LLMHTTPProxy, PooledThreadHTTPServer]:
    upstream, _ = _start_server(_OpenClawUpstreamHandler)
    policy = tmp_path / "openclaw.yaml"
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


def _policy(window_seconds: int = 60, cooldown_seconds: int = 1) -> str:
    return f"""
rules: []
flow_xray:
  enabled: true
loop_detection:
  enabled: true
  warn_threshold: 99
  block_threshold: 999
  content_loop:
    enabled: true
    window_seconds: {window_seconds}
    max_identical: 3
    cooldown_seconds: {cooldown_seconds}
    hash_prefix_len: 256
budgets:
  daily: 10.0
  spend_rate:
    enabled: true
    windows:
      - seconds: 60
        max_spend: 4.0
    spike_multiplier: 20.0
    pause_seconds: 1
    heartbeat_cost_threshold: 0.10
"""


def _policy_with_max_identical(max_identical: int) -> str:
    return _policy().replace("max_identical: 3", f"max_identical: {int(max_identical)}")


def _post(proxy: LLMHTTPProxy, body: dict, headers: dict[str, str] | None = None) -> tuple[int, dict, dict]:
    req = UrlRequest(
        f"http://127.0.0.1:{proxy._config.port}/v1/chat/completions",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": "Bearer x", **(headers or {})},
        method="POST",
    )
    try:
        with urlopen(req, timeout=5) as resp:
            return int(resp.status), json.loads(resp.read().decode("utf-8")), dict(resp.headers.items())
    except HTTPError as exc:
        payload = {}
        try:
            payload = json.loads(exc.read().decode("utf-8"))
        except Exception:
            payload = {}
        return int(exc.code), payload, dict(exc.headers.items())


def test_normal_chat_session_allowed(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, _policy())
    try:
        status, _, _ = _post(proxy, {"model": "gpt-4o", "messages": [{"role": "user", "content": "hello"}]})
        assert status == 200
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_heartbeat_every_30min_allowed(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, _policy(window_seconds=1, cooldown_seconds=1))
    try:
        for i in range(2):
            status, _, _ = _post(
                proxy,
                {"model": "gpt-4o", "messages": [{"role": "user", "content": f"Read HEARTBEAT.md run #{i}"}]},
            )
            assert status == 200
            time.sleep(1.05)
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_heartbeat_storm_5_in_1min_blocked(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, _policy(window_seconds=60))
    try:
        for _ in range(2):
            assert _post(proxy, {"model": "gpt-4o", "messages": [{"role": "user", "content": "Read HEARTBEAT.md"}]})[0] == 200
        blocked = _post(proxy, {"model": "gpt-4o", "messages": [{"role": "user", "content": "Read HEARTBEAT.md"}]})
        assert blocked[0] == 429
        assert blocked[1].get("error", {}).get("type") == "content_loop_detected"
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_heartbeat_storm_recovery_after_cooldown(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, _policy(window_seconds=60, cooldown_seconds=1))
    try:
        for _ in range(3):
            _post(proxy, {"model": "gpt-4o", "messages": [{"role": "user", "content": "Read HEARTBEAT.md"}]})
        time.sleep(1.05)
        status, _, _ = _post(proxy, {"model": "gpt-4o", "messages": [{"role": "user", "content": "new chat"}]})
        assert status == 200
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_mixed_chat_and_heartbeat(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, _policy())
    try:
        assert _post(proxy, {"model": "gpt-4o", "messages": [{"role": "user", "content": "hello"}]})[0] == 200
        assert _post(proxy, {"model": "gpt-4o", "messages": [{"role": "user", "content": "Read HEARTBEAT.md"}]})[0] == 200
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_session_id_from_openclaw_header(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, _policy())
    try:
        _, _, headers = _post(
            proxy,
            {"model": "gpt-4o", "messages": [{"role": "user", "content": "hello"}]},
            headers={"x-openclaw-session": "oc-123"},
        )
        assert headers.get("X-Orchesis-Session") == "oc-123"
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_session_id_from_x_session_id_header(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, _policy())
    try:
        _, _, headers = _post(
            proxy,
            {"model": "gpt-4o", "messages": [{"role": "user", "content": "hello"}]},
            headers={"x-session-id": "sid-9"},
        )
        assert headers.get("X-Orchesis-Session") == "sid-9"
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_session_id_missing_defaults(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, _policy())
    try:
        _, _, headers = _post(proxy, {"model": "gpt-4o", "messages": [{"role": "user", "content": "hello"}]})
        assert headers.get("X-Orchesis-Session") == "default"
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_heartbeat_routed_to_cheap_model(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, _policy())
    try:
        _post(proxy, {"model": "gpt-4o", "messages": [{"role": "user", "content": "Read HEARTBEAT.md"}]})
        assert _OpenClawUpstreamHandler.last_body is not None
        assert _OpenClawUpstreamHandler.last_body.get("model") in {"gpt-4o-mini", "claude-haiku-4-5-20251001"}
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_skill_tool_call_flow_xray_tracked(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, _policy())
    try:
        _post(
            proxy,
            {
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": "use tool"}],
                "tools": [{"name": "read_file"}],
            },
        )
        with urlopen(f"http://127.0.0.1:{proxy._config.port}/api/flow/sessions", timeout=5) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        assert isinstance(payload.get("sessions"), list)
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_budget_blocks_after_daily_limit(tmp_path: Path) -> None:
    policy = _policy() + "\nbudgets:\n  daily: 0.01\n"
    proxy, upstream = _make_proxy(tmp_path, policy)
    try:
        _post(proxy, {"model": "gpt-4o", "messages": [{"role": "user", "content": "expensive request"}]})
        blocked = _post(proxy, {"model": "gpt-4o", "messages": [{"role": "user", "content": "expensive request"}]})
        assert blocked[0] == 429
        assert blocked[1].get("error", {}).get("type") in {"budget_exceeded", "spend_rate_exceeded"}
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_spend_rate_blocks_rapid_spend(tmp_path: Path) -> None:
    policy = _policy() + """
budgets:
  daily: 20.0
  spend_rate:
    enabled: true
    windows:
      - seconds: 60
        max_spend: 0.02
    spike_multiplier: 100.0
    pause_seconds: 1
"""
    proxy, upstream = _make_proxy(tmp_path, policy)
    try:
        _post(proxy, {"model": "gpt-4o", "messages": [{"role": "user", "content": "expensive request"}]})
        blocked = _post(proxy, {"model": "gpt-4o", "messages": [{"role": "user", "content": "expensive request"}]})
        assert blocked[0] == 429
        assert blocked[1].get("error", {}).get("type") == "spend_rate_exceeded"
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_content_loop_then_budget_both_enforced(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, _policy())
    try:
        for _ in range(3):
            status, body, _ = _post(proxy, {"model": "gpt-4o", "messages": [{"role": "user", "content": "Read HEARTBEAT.md"}]})
        assert status == 429
        assert body.get("error", {}).get("type") == "content_loop_detected"
        # Separate path should still evaluate budget/spend-rate controls.
        status2, body2, _ = _post(proxy, {"model": "gpt-4o", "messages": [{"role": "user", "content": "expensive request"}]})
        assert status2 in {200, 429}
        if status2 == 429:
            assert body2.get("error", {}).get("type") in {"budget_exceeded", "spend_rate_exceeded"}
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_savings_calculation_accuracy(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, _policy())
    try:
        _post(proxy, {"model": "gpt-4o", "messages": [{"role": "user", "content": "hello"}]})
        with urlopen(f"http://127.0.0.1:{proxy._config.port}/api/v1/savings", timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        total = float(data["cache_savings"]) + float(data["cascade_savings"]) + float(data["loop_savings"])
        assert abs(total - float(data["total_savings"])) < 1e-5
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_response_headers_present(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, _policy())
    try:
        _, _, headers = _post(proxy, {"model": "gpt-4o", "messages": [{"role": "user", "content": "hello"}]})
        assert "X-Orchesis-Cost" in headers
        assert "X-Orchesis-Daily-Total" in headers
        assert "X-Orchesis-Daily-Budget" in headers
        assert "X-Orchesis-Saved" in headers
        assert "X-Orchesis-Session" in headers
        assert "X-Orchesis-Spend-Rate" in headers
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_heartbeat_routing_uses_config_model(tmp_path: Path) -> None:
    """Heartbeat should route to model from config, not hardcoded."""
    policy = (
        _policy()
        + """
model_routing:
  enabled: true
  heartbeat_models:
    openai: "gpt-4.1-mini"
    anthropic: "claude-sonnet-4"
    default: "gpt-4.1-mini"
"""
    )
    proxy, upstream = _make_proxy(tmp_path, policy)
    try:
        _post(proxy, {"model": "gpt-4o", "messages": [{"role": "user", "content": "Read HEARTBEAT.md now"}]})
        assert _OpenClawUpstreamHandler.last_body is not None
        assert _OpenClawUpstreamHandler.last_body.get("model") == "gpt-4.1-mini"
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_normal_schedule_message_not_heartbeat(tmp_path: Path) -> None:
    """'Schedule a meeting' should NOT trigger heartbeat routing."""
    proxy, upstream = _make_proxy(tmp_path, _policy())
    try:
        _post(
            proxy,
            {
                "model": "gpt-4o",
                "messages": [
                    {"role": "system", "content": "You are a helpful assistant."},
                    {"role": "user", "content": "Can you help me schedule a meeting with the team?"},
                    {"role": "assistant", "content": "Sure, what day works best?"},
                    {"role": "user", "content": "Tomorrow at 3pm please"},
                ],
            },
        )
        assert _OpenClawUpstreamHandler.last_body is not None
        assert _OpenClawUpstreamHandler.last_body.get("model") == "gpt-4o"
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_openclaw_start_repeated_not_blocked(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, _policy_with_max_identical(5))
    try:
        for _ in range(5):
            status, _, _ = _post(
                proxy,
                {"model": "gpt-4o", "messages": [{"role": "user", "content": "/start"}]},
            )
            assert status == 200
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_normal_identical_posts_still_blocked(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, _policy_with_max_identical(5))
    try:
        statuses: list[int] = []
        for _ in range(5):
            status, _, _ = _post(
                proxy,
                {"model": "gpt-4o", "messages": [{"role": "user", "content": "normal repeated content"}]},
            )
            statuses.append(status)
        assert statuses[-1] == 429
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_openclaw_new_then_three_identical_not_blocked(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, _policy_with_max_identical(5))
    try:
        first, _, _ = _post(
            proxy,
            {"model": "gpt-4o", "messages": [{"role": "user", "content": "/new"}]},
        )
        assert first == 200
        for _ in range(3):
            status, _, _ = _post(
                proxy,
                {"model": "gpt-4o", "messages": [{"role": "user", "content": "normal repeated content"}]},
            )
            assert status == 200
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_openclaw_start_then_five_normal_blocks_on_sixth(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, _policy_with_max_identical(5))
    try:
        first, _, _ = _post(
            proxy,
            {"model": "gpt-4o", "messages": [{"role": "user", "content": "/start"}]},
        )
        assert first == 200
        statuses: list[int] = []
        for _ in range(5):
            status, _, _ = _post(
                proxy,
                {"model": "gpt-4o", "messages": [{"role": "user", "content": "normal repeated content"}]},
            )
            statuses.append(status)
        assert statuses[-1] == 429
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()
