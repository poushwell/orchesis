from __future__ import annotations

import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request as UrlRequest, urlopen

import orchesis.cli as cli_module
from orchesis.cli import main
from orchesis.proxy import HTTPProxyConfig, LLMHTTPProxy
from tests.cli_test_utils import CliRunner


def _pick_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = int(sock.getsockname()[1])
    sock.close()
    return port


def _post_json(url: str, payload: dict) -> tuple[int, dict]:
    req = UrlRequest(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(req, timeout=3) as resp:
            return int(resp.status), json.loads(resp.read().decode("utf-8"))
    except HTTPError as error:
        return int(error.code), json.loads(error.read().decode("utf-8"))


def _wait_health(port: int) -> None:
    for _ in range(40):
        try:
            with urlopen(f"http://127.0.0.1:{port}/health", timeout=1):
                return
        except Exception:
            time.sleep(0.05)
    raise RuntimeError("proxy did not start")


def test_policy_reload_valid_policy(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\n", encoding="utf-8")
    port = _pick_port()
    proxy = LLMHTTPProxy(policy_path=str(policy), config=HTTPProxyConfig(host="127.0.0.1", port=port))
    proxy.start(blocking=False)
    try:
        _wait_health(port)
        status, payload = _post_json(f"http://127.0.0.1:{port}/api/v1/policy/reload", {})
        assert status == 200
        assert payload["status"] == "reloaded"
        assert isinstance(payload.get("version"), str)
    finally:
        proxy.stop()


def test_policy_reload_invalid_policy_rejected(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\n", encoding="utf-8")
    port = _pick_port()
    proxy = LLMHTTPProxy(policy_path=str(policy), config=HTTPProxyConfig(host="127.0.0.1", port=port))
    proxy.start(blocking=False)
    try:
        _wait_health(port)
        policy.write_text("rules:\n  - {}\n", encoding="utf-8")
        status, payload = _post_json(f"http://127.0.0.1:{port}/api/v1/policy/reload", {})
        assert status == 400
        assert payload.get("status") == "invalid"
        assert isinstance(payload.get("errors"), list)
    finally:
        proxy.stop()


def test_policy_reload_atomic(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules:\n  - name: budget_limit\n    max_cost_per_call: 1.0\n", encoding="utf-8")
    proxy = LLMHTTPProxy(policy_path=str(policy), config=HTTPProxyConfig(host="127.0.0.1", port=0))
    original = dict(proxy._policy)  # noqa: SLF001
    assert proxy.reload_policy(original) is True
    policy.write_text("rules:\n  - {}\n", encoding="utf-8")
    port = _pick_port()
    proxy2 = LLMHTTPProxy(policy_path=str(policy), config=HTTPProxyConfig(host="127.0.0.1", port=port))
    proxy2.start(blocking=False)
    try:
        _wait_health(port)
        before = json.dumps(proxy2._policy, sort_keys=True, ensure_ascii=False)  # noqa: SLF001
        status, _payload = _post_json(f"http://127.0.0.1:{port}/api/v1/policy/reload", {})
        assert status == 400
        after = json.dumps(proxy2._policy, sort_keys=True, ensure_ascii=False)  # noqa: SLF001
        assert before == after
    finally:
        proxy2.stop()


def test_policy_reload_cli_command(monkeypatch, tmp_path: Path) -> None:
    cfg = tmp_path / "orchesis.yaml"
    cfg.write_text("rules: []\nproxy:\n  port: 8999\n", encoding="utf-8")

    called: dict[str, object] = {}

    def _fake_post(port: int, path: str, payload: dict) -> dict:
        called["port"] = port
        called["path"] = path
        called["payload"] = payload
        return {"status": "reloaded", "version": "abc123"}

    monkeypatch.setattr(cli_module, "_post_proxy_control", _fake_post)

    runner = CliRunner()
    result = runner.invoke(main, ["reload", "--config", str(cfg)])
    assert result.exit_code == 0
    assert "✓ Policy reloaded (version: abc123)" in result.output
    assert called["port"] == 8999
    assert called["path"] == "/api/v1/policy/reload"


def test_policy_reload_thread_safe() -> None:
    proxy = LLMHTTPProxy(policy_path=None, config=HTTPProxyConfig(host="127.0.0.1", port=0))
    policy_a = {"rules": [{"name": "budget_limit", "max_cost_per_call": 1.0}]}
    policy_b = {"rules": [{"name": "budget_limit", "max_cost_per_call": 2.0}]}

    def _reload_once(index: int) -> bool:
        return proxy.reload_policy(policy_a if index % 2 == 0 else policy_b)

    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(_reload_once, range(40)))

    assert all(results)
    assert proxy._policy in (policy_a, policy_b)  # noqa: SLF001
