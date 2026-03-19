from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from orchesis.agent_autopsy import AgentAutopsy
from orchesis.api import create_api_app
from orchesis.cli import main
from tests.cli_test_utils import CliRunner


def _policy_yaml() -> str:
    return """
api:
  token: "orch_sk_test"
rules: []
"""


def _auth() -> dict[str, str]:
    return {"Authorization": "Bearer orch_sk_test"}


async def _client(app):
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


def _event(
    session_id: str,
    *,
    decision: str = "ALLOW",
    reasons: list[str] | None = None,
    tokens: int = 100,
    state_snapshot: dict | None = None,
) -> dict:
    return {
        "timestamp": "2026-03-19T00:00:00Z",
        "decision": decision,
        "reasons": reasons or [],
        "tokens": tokens,
        "state_snapshot": {"session_id": session_id, **(state_snapshot or {})},
        "session_id": session_id,
    }


def _write_events(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n",
        encoding="utf-8",
    )


def test_autopsy_performed() -> None:
    model = AgentAutopsy()
    report = model.perform("sess-1", [_event("sess-1")])
    assert report["session_id"] == "sess-1"
    assert report["autopsy_id"].startswith("autopsy-")


def test_loop_cause_detected() -> None:
    model = AgentAutopsy()
    report = model.perform("sess-1", [_event("sess-1", decision="DENY", reasons=["loop guard triggered"])])
    assert report["cause_of_death"] == "loop_detected"


def test_budget_cause_detected() -> None:
    model = AgentAutopsy()
    report = model.perform("sess-1", [_event("sess-1", decision="DENY", reasons=["budget exceeded"])])
    assert report["cause_of_death"] == "budget_exhausted"


def test_contributing_factors_found() -> None:
    model = AgentAutopsy()
    report = model.perform(
        "sess-1",
        [_event("sess-1", tokens=12001, state_snapshot={"psi": 0.9, "slope_alert": True})],
    )
    factors = set(report["contributing_factors"])
    assert "high_crystallinity" in factors
    assert "cqs_declining" in factors
    assert "high_token_usage" in factors


def test_timeline_built() -> None:
    model = AgentAutopsy()
    report = model.perform("sess-1", [_event("sess-1"), _event("sess-1", decision="DENY")])
    assert len(report["timeline"]) == 2
    assert report["timeline"][-1]["decision"] == "DENY"


def test_recommendations_generated() -> None:
    model = AgentAutopsy()
    report = model.perform("sess-1", [_event("sess-1", decision="DENY", reasons=["budget limit hit"])])
    assert report["recommendations"]
    assert any("budget" in item.lower() for item in report["recommendations"])


def test_severity_scored() -> None:
    model = AgentAutopsy()
    report = model.perform("sess-1", [_event("sess-1", decision="DENY", reasons=["prompt injection pattern"])])
    assert report["severity"] == "critical"


def test_preventable_flagged() -> None:
    model = AgentAutopsy()
    report = model.perform("sess-1", [_event("sess-1", decision="DENY", reasons=["loop detected"])])
    assert report["preventable"] is True


def test_cli_autopsy_command() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        _write_events(Path("decisions.jsonl"), [_event("sess-1", decision="DENY", reasons=["loop"])] )
        result = runner.invoke(main, ["autopsy", "--session", "sess-1"])
    assert result.exit_code == 0
    assert "Cause of death: loop_detected" in result.output


@pytest.mark.asyncio
async def test_api_autopsy_endpoint(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    decisions_path = tmp_path / "decisions.jsonl"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    _write_events(decisions_path, [_event("sess-1", decision="DENY", reasons=["loop"])] )
    app = create_api_app(
        policy_path=str(policy_path),
        decisions_log=str(decisions_path),
        state_persist=str(tmp_path / "state.jsonl"),
        history_path=str(tmp_path / "history.jsonl"),
    )
    async with await _client(app) as client:
        res = await client.post("/api/v1/autopsy/sess-1", headers=_auth())
    assert res.status_code == 200
    payload = res.json()
    assert payload["session_id"] == "sess-1"
    assert payload["cause_of_death"] == "loop_detected"
