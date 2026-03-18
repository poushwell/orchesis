from __future__ import annotations

import json
from urllib.error import URLError

from tests.cli_test_utils import CliRunner

from orchesis.cli import main


class _FakeResponse:
    def __init__(self, payload: dict):
        self._payload = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):  # noqa: ANN001
        _ = exc_type, exc, tb
        return False


def _urlopen_factory(proxy_payload: dict | None = None, api_payload: dict | None = None):
    def _fake_urlopen(request, timeout=0):  # noqa: ANN001, ARG001
        url = request.full_url if hasattr(request, "full_url") else str(request)
        if "8080" in url:
            if proxy_payload is None:
                raise URLError("proxy down")
            return _FakeResponse(proxy_payload)
        if "8090" in url:
            if api_payload is None:
                raise URLError("api down")
            return _FakeResponse(api_payload)
        raise URLError("unknown")

    return _fake_urlopen


def test_status_command_runs(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setattr("orchesis.cli.urlopen", _urlopen_factory(proxy_payload={}, api_payload={}))
    runner = CliRunner()
    result = runner.invoke(main, ["status"])
    assert result.exit_code == 0
    assert "System Status" in result.output


def test_status_json_output(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setattr(
        "orchesis.cli.urlopen",
        _urlopen_factory(
            proxy_payload={"requests_total": 100, "cost_today": 1.25},
            api_payload={"uptime_seconds": 120},
        ),
    )
    runner = CliRunner()
    result = runner.invoke(main, ["status", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["proxy_running"] is True
    assert payload["api_running"] is True
    assert payload["requests_total"] == 100


def test_status_proxy_not_running_graceful(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setattr("orchesis.cli.urlopen", _urlopen_factory(proxy_payload=None, api_payload={"uptime_seconds": 1}))
    runner = CliRunner()
    result = runner.invoke(main, ["status"])
    assert result.exit_code == 0
    assert "Proxy        ✗ not running" in result.output


def test_status_shows_key_metrics(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setattr(
        "orchesis.cli.urlopen",
        _urlopen_factory(
            proxy_payload={
                "requests_total": 14847,
                "cost_today": 20.09,
                "requests_blocked": 23,
                "block_rate": 0.0015,
                "cache_hit_rate": 0.081,
                "tokens_saved": 2891443,
                "money_saved_usd": 43.37,
                "approvals_pending": 0,
                "active_agents": 12,
                "agent_errors": 0,
                "loops_detected_today": 0,
                "budget_limit_usd": "unlimited",
            },
            api_payload={"uptime_seconds": 9240},
        ),
    )
    runner = CliRunner()
    result = runner.invoke(main, ["status"])
    assert result.exit_code == 0
    assert "14,847 requests" in result.output
    assert "Security" in result.output
    assert "Cache" in result.output
    assert "Budget" in result.output
    assert "Agents       12 active" in result.output


def test_status_watch_mode_exits_on_ctrl_c(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setattr("orchesis.cli.urlopen", _urlopen_factory(proxy_payload={}, api_payload={}))

    def _interrupt(_seconds: float) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr("orchesis.cli.time.sleep", _interrupt)
    runner = CliRunner()
    result = runner.invoke(main, ["status", "--watch"])
    assert result.exit_code == 0
    assert "Stopped." in result.output
