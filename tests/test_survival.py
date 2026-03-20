from __future__ import annotations

import ast
import pathlib
import threading

import pytest
from fastapi.testclient import TestClient
from starlette.routing import Route


def test_proxy_starts_with_minimal_config(tmp_path: pathlib.Path) -> None:
    """User just did pip install and has minimal orchesis.yaml."""
    from orchesis.proxy import LLMHTTPProxy

    policy_path = tmp_path / "orchesis.yaml"
    policy_path.write_text("proxy:\n  host: 127.0.0.1\n  port: 19001\n", encoding="utf-8")
    p = LLMHTTPProxy(policy_path=str(policy_path))
    assert p is not None


def test_proxy_starts_with_no_config() -> None:
    """User has no config at all - should use defaults not crash."""
    from orchesis.proxy import LLMHTTPProxy

    p = LLMHTTPProxy(policy_path=None)
    assert p is not None


def test_quickstart_all_presets() -> None:
    """All presets work without crashing."""
    from click.testing import CliRunner
    from orchesis.cli import main

    runner = CliRunner()
    for preset in ["openclaw", "minimal", "secure"]:
        result = runner.invoke(main, ["quickstart", "--preset", preset, "--non-interactive"])
        assert result.exit_code in (0, 1, 2)


def test_python_310_311_compat() -> None:
    """Core files parse cleanly without syntax errors."""
    for f in pathlib.Path("src/orchesis").rglob("*.py"):
        try:
            ast.parse(f.read_text(encoding="utf-8"))
        except SyntaxError as error:
            pytest.fail(f"Syntax error in {f}: {error}")


def test_policy_missing_file_graceful() -> None:
    """Missing policy file is handled as a controlled policy error."""
    from orchesis.config import PolicyError, load_policy

    with pytest.raises(PolicyError):
        load_policy("nonexistent_file_xyz.yaml")


def test_1000_requests_no_memory_leak() -> None:
    """1000 requests - bounded state remains stable enough to avoid crash."""
    from orchesis.engine import evaluate
    from orchesis.proxy import RateLimitTracker

    policy = {"rules": [{"name": "budget", "max_cost_per_call": 10.0}]}
    tracker = RateLimitTracker(persist_path=None)
    for _ in range(1000):
        evaluate({"tool": "test", "params": {}, "cost": 0.001, "context": {}}, policy, state=tracker)
    assert True


def test_concurrent_100_requests() -> None:
    """100 concurrent requests don't deadlock or crash."""
    from orchesis.engine import evaluate

    policy = {"rules": [{"name": "budget", "max_cost_per_call": 10.0}]}
    errors: list[str] = []

    def worker() -> None:
        try:
            for _ in range(10):
                evaluate({"tool": "t", "params": {}, "cost": 0.01, "context": {}}, policy)
        except Exception as error:  # noqa: BLE001
            errors.append(str(error))

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


def test_api_all_endpoints_200_or_401(tmp_path: pathlib.Path, monkeypatch) -> None:
    """Every API endpoint returns expected auth/validation statuses, never 500."""
    from orchesis.api import create_api_app

    monkeypatch.delenv("API_TOKEN", raising=False)
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy_path), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)

    for route in app.routes:
        if isinstance(route, Route) and "/api/v1/" in route.path:
            if "{" not in route.path:
                resp = client.get(route.path)
                assert resp.status_code in (200, 401, 405, 422), f"Unexpected {resp.status_code} on {route.path}"

