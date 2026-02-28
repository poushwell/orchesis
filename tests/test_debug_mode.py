from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from click.testing import CliRunner

from orchesis.api import create_api_app
from orchesis.cli import main
from orchesis.engine import evaluate


def _policy() -> dict:
    return {
        "rules": [
            {"name": "budget_limit", "max_cost_per_call": 1.0},
            {"name": "file_access", "denied_paths": ["/etc"]},
            {"name": "rate_limit", "max_requests_per_minute": 100},
        ]
    }


def test_debug_trace_present() -> None:
    decision = evaluate(
        {"tool": "read_file", "params": {"path": "/data/safe.txt"}, "cost": 0.1},
        _policy(),
        debug=True,
    )
    assert isinstance(decision.debug_trace, dict)
    assert "rule_results" in decision.debug_trace


def test_debug_trace_rule_results() -> None:
    decision = evaluate(
        {"tool": "read_file", "params": {"path": "/etc/passwd"}, "cost": 0.1},
        _policy(),
        debug=True,
    )
    assert isinstance(decision.debug_trace, dict)
    assert len(decision.debug_trace["rule_results"]) >= 3


def test_debug_trace_timing() -> None:
    decision = evaluate(
        {"tool": "read_file", "params": {"path": "/data/safe.txt"}, "cost": 0.1},
        _policy(),
        debug=True,
    )
    assert isinstance(decision.debug_trace, dict)
    for item in decision.debug_trace["rule_results"]:
        assert "duration_us" in item
        assert isinstance(item["duration_us"], int)


def test_debug_false_no_trace() -> None:
    decision = evaluate(
        {"tool": "read_file", "params": {"path": "/data/safe.txt"}, "cost": 0.1},
        _policy(),
        debug=False,
    )
    assert decision.debug_trace is None


def test_debug_via_cli() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("policy.yaml").write_text(
            """
rules:
  - name: budget_limit
    max_cost_per_call: 1.0
  - name: file_access
    denied_paths: ["/etc"]
""".strip(),
            encoding="utf-8",
        )
        Path("request.json").write_text(
            json.dumps({"tool": "read_file", "params": {"path": "/etc/passwd"}, "cost": 0.1}),
            encoding="utf-8",
        )
        result = runner.invoke(
            main, ["verify", "request.json", "--policy", "policy.yaml", "--debug"]
        )
        assert result.exit_code == 1
        assert "debug_trace" in result.output


@pytest.mark.asyncio
async def test_debug_via_api(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
api:
  token: "orch_sk_test"
rules:
  - name: budget_limit
    max_cost_per_call: 1.0
  - name: file_access
    denied_paths: ["/etc"]
""".strip(),
        encoding="utf-8",
    )
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/evaluate",
            headers={"Authorization": "Bearer orch_sk_test"},
            json={
                "tool": "read_file",
                "params": {"path": "/etc/passwd"},
                "cost": 0.1,
                "debug": True,
            },
        )
    assert response.status_code == 200
    payload = response.json()
    assert payload["allowed"] is False
    assert "debug_trace" in payload
    assert response.headers.get("X-Orchesis-Decision") == "DENY"
    assert response.headers.get("X-Orchesis-Trace-Id")
