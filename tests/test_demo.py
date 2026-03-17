from __future__ import annotations

import json
import socket
import threading
import time
from urllib.error import HTTPError
from urllib.request import Request as UrlRequest, urlopen

from orchesis.demo import DEMO_STATS, DemoServer
from tests.cli_test_utils import CliRunner
from orchesis.cli import main


def _pick_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = int(sock.getsockname()[1])
    sock.close()
    return port


def _get_json(url: str) -> dict:
    with _urlopen_with_retry(url, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _urlopen_with_retry(request_or_url, timeout: int = 5, attempts: int = 3):
    last_error = None
    for _ in range(max(1, attempts)):
        try:
            return urlopen(request_or_url, timeout=timeout)
        except Exception as error:
            last_error = error
            time.sleep(0.05)
    if last_error is not None:
        raise last_error
    return urlopen(request_or_url, timeout=timeout)


def _wait_for_server(port: int, attempts: int = 20) -> None:
    for _ in range(max(1, attempts)):
        try:
            with _urlopen_with_retry(f"http://127.0.0.1:{port}/dashboard", timeout=1, attempts=1):
                return
        except Exception:
            time.sleep(0.05)
    raise RuntimeError(f"demo server did not start on port {port}")


def test_demo_stats_valid_json() -> None:
    assert isinstance(DEMO_STATS, dict)
    assert "cost_velocity" in DEMO_STATS


def test_demo_server_starts() -> None:
    port = _pick_port()
    thread = threading.Thread(target=DemoServer().start, kwargs={"port": port}, daemon=True)
    thread.start()
    _wait_for_server(port)
    with _urlopen_with_retry(f"http://127.0.0.1:{port}/dashboard", timeout=5) as resp:
        assert int(resp.status) == 200


def test_demo_dashboard_has_banner() -> None:
    port = _pick_port()
    thread = threading.Thread(target=DemoServer().start, kwargs={"port": port}, daemon=True)
    thread.start()
    _wait_for_server(port)
    with _urlopen_with_retry(f"http://127.0.0.1:{port}/dashboard", timeout=5) as resp:
        body = resp.read().decode("utf-8")
    assert "DEMO MODE" in body


def test_demo_stats_endpoint() -> None:
    port = _pick_port()
    threading.Thread(target=DemoServer().start, kwargs={"port": port}, daemon=True).start()
    _wait_for_server(port)
    payload = _get_json(f"http://127.0.0.1:{port}/stats")
    assert "cost_today" in payload
    assert "cost_velocity" in payload


def test_demo_agents_endpoint() -> None:
    port = _pick_port()
    threading.Thread(target=DemoServer().start, kwargs={"port": port}, daemon=True).start()
    _wait_for_server(port)
    payload = _get_json(f"http://127.0.0.1:{port}/api/dashboard/agents")
    assert "agents" in payload
    assert isinstance(payload["agents"], list)


def test_demo_mode_no_real_proxy() -> None:
    port = _pick_port()
    threading.Thread(target=DemoServer().start, kwargs={"port": port}, daemon=True).start()
    _wait_for_server(port)
    req = UrlRequest(
        f"http://127.0.0.1:{port}/v1/chat/completions",
        data=b"{}",
        method="POST",
    )
    try:
        _urlopen_with_retry(req, timeout=5)
        assert False
    except HTTPError as error:
        assert error.code == 404


def test_demo_approvals_endpoint() -> None:
    port = _pick_port()
    threading.Thread(target=DemoServer().start, kwargs={"port": port}, daemon=True).start()
    _wait_for_server(port)
    payload = _get_json(f"http://127.0.0.1:{port}/api/v1/approvals")
    assert "pending" in payload
    assert "history" in payload


def test_demo_approve_action() -> None:
    port = _pick_port()
    threading.Thread(target=DemoServer().start, kwargs={"port": port}, daemon=True).start()
    _wait_for_server(port)
    req = UrlRequest(f"http://127.0.0.1:{port}/api/v1/approvals/demo-approval-1/approve", data=b"{}", method="POST")
    with _urlopen_with_retry(req, timeout=5) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    assert payload["approved"] is True


def test_demo_deny_action() -> None:
    port = _pick_port()
    threading.Thread(target=DemoServer().start, kwargs={"port": port}, daemon=True).start()
    _wait_for_server(port)
    req = UrlRequest(f"http://127.0.0.1:{port}/api/v1/approvals/demo-approval-2/deny", data=b"{}", method="POST")
    with _urlopen_with_retry(req, timeout=5) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    assert payload["denied"] is True


def test_demo_overview_contains_compliance() -> None:
    port = _pick_port()
    threading.Thread(target=DemoServer().start, kwargs={"port": port}, daemon=True).start()
    _wait_for_server(port)
    payload = _get_json(f"http://127.0.0.1:{port}/api/dashboard/overview")
    assert "compliance_overview" in payload


def test_demo_starts_both_services(monkeypatch) -> None:
    import orchesis.cli as cli_module
    import orchesis.proxy as proxy_module

    events: list[str] = []

    class _FakeProxy:
        def __init__(self, policy_path=None, config=None):
            _ = (policy_path, config)
            events.append("proxy_init")

        def start(self, blocking: bool = False) -> None:
            events.append(f"proxy_start:{bool(blocking)}")

        def stop(self) -> None:
            events.append("proxy_stop")

    class _FakeHTTPProxyConfig:
        def __init__(self, host: str = "127.0.0.1", port: int = 8080):
            _ = host
            _ = port

    class _FakeUvicorn:
        class Config:
            def __init__(self, app, host: str, port: int, log_level: str):
                _ = (app, host, port, log_level)

        class Server:
            def __init__(self, cfg):
                _ = cfg
                self.should_exit = False

            def run(self) -> None:
                events.append("api_run")

    def _fake_create_api_app(policy_path: str = "policy.yaml"):
        events.append(f"api_app:{policy_path}")
        return object()

    monkeypatch.setattr(proxy_module, "LLMHTTPProxy", _FakeProxy)
    monkeypatch.setattr(proxy_module, "HTTPProxyConfig", _FakeHTTPProxyConfig)
    monkeypatch.setattr(
        cli_module,
        "_load_server_runtime",
        lambda: (_FakeUvicorn, _fake_create_api_app, object, object),
    )

    def _stop_loop(_seconds: float) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(cli_module.time, "sleep", _stop_loop)

    runner = CliRunner()
    result = runner.invoke(main, ["demo", "--port", "8080", "--api-port", "8090"])
    assert result.exit_code == 0
    assert "Orchesis proxy:    http://localhost:8080" in result.output
    assert "Orchesis API:      http://localhost:8090" in result.output
    assert "Dashboard:         http://localhost:8080/dashboard" in result.output
    assert "Overwatch API:     http://localhost:8090/api/v1/overwatch" in result.output
    assert "proxy_start:False" in events
    assert "api_run" in events

