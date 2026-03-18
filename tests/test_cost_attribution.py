from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.cost_attribution import CostAttributionEngine


def _event(*, agent_id: str, cost: float, hours_ago: int = 1) -> dict:
    ts = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    return {
        "event_id": f"evt-{agent_id}-{hours_ago}",
        "timestamp": ts.isoformat().replace("+00:00", "Z"),
        "agent_id": agent_id,
        "tool": "shell.exec",
        "params_hash": "abc",
        "cost": float(cost),
        "decision": "ALLOW",
        "reasons": [],
        "rules_checked": [],
        "rules_triggered": [],
        "evaluation_order": [],
        "evaluation_duration_us": 100,
        "policy_version": "v1",
        "state_snapshot": {"session_id": f"s-{agent_id}", "model": "gpt-4o-mini"},
    }


def _engine() -> CostAttributionEngine:
    return CostAttributionEngine(
        {
            "rules": [
                {"agent_pattern": "research_*", "team": "research", "project": "nlp-project", "cost_center": "CC-001"},
                {"agent_pattern": "coding_*", "team": "engineering", "cost_center": "CC-002"},
            ],
            "team_budgets": {"research": 10.0, "engineering": 20.0},
        }
    )


def test_attribution_by_team() -> None:
    engine = _engine()
    result = engine.attribute(
        [
            _event(agent_id="research_alpha", cost=1.2),
            _event(agent_id="coding_beta", cost=2.0),
        ]
    )
    assert result["by_team"]["research"]["cost"] == 1.2
    assert result["by_team"]["engineering"]["cost"] == 2.0


def test_attribution_by_project() -> None:
    engine = _engine()
    result = engine.attribute([_event(agent_id="research_alpha", cost=1.2)])
    assert result["by_project"]["nlp-project"]["cost"] == 1.2


def test_unattributed_captured() -> None:
    engine = _engine()
    result = engine.attribute([_event(agent_id="unknown_agent", cost=3.4)])
    assert result["unattributed"]["requests"] == 1
    assert result["unattributed"]["cost"] == 3.4


def test_chargeback_report_generated() -> None:
    engine = _engine()
    engine.attribute([_event(agent_id="research_alpha", cost=2.5), _event(agent_id="coding_beta", cost=1.0)])
    rows = engine.get_chargebacks(period="month")
    assert len(rows) >= 2
    assert rows[0]["period"] == "month"


def test_budget_status_per_team() -> None:
    engine = _engine()
    engine.attribute([_event(agent_id="research_alpha", cost=4.0)])
    status = engine.get_budget_status("research")
    assert status["limit"] == 10.0
    assert status["used"] == 4.0
    assert status["over_budget"] is False


def test_api_attribution_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        """
rules: []
api:
  token: test-token
cost_attribution:
  rules:
    - agent_pattern: "research_*"
      team: "research"
      project: "nlp-project"
      cost_center: "CC-001"
  team_budgets:
    research: 10
""".strip(),
        encoding="utf-8",
    )
    decisions_log = tmp_path / "decisions.jsonl"
    decisions_log.write_text(
        "\n".join(
            [
                json.dumps(_event(agent_id="research_alpha", cost=1.2), ensure_ascii=False),
                json.dumps(_event(agent_id="unknown_agent", cost=0.5), ensure_ascii=False),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    app = create_api_app(policy_path=str(policy), decisions_log=str(decisions_log))
    client = TestClient(app)
    headers = {"Authorization": "Bearer test-token"}

    response = client.get("/api/v1/cost-attribution", headers=headers)
    assert response.status_code == 200
    payload = response.json()
    assert payload["by_team"]["research"]["cost"] == 1.2
    assert payload["unattributed"]["requests"] == 1


def test_api_chargebacks_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        """
rules: []
api:
  token: test-token
cost_attribution:
  rules:
    - agent_pattern: "coding_*"
      team: "engineering"
      cost_center: "CC-002"
""".strip(),
        encoding="utf-8",
    )
    decisions_log = tmp_path / "decisions.jsonl"
    decisions_log.write_text(json.dumps(_event(agent_id="coding_bot", cost=2.2), ensure_ascii=False) + "\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(decisions_log))
    client = TestClient(app)
    headers = {"Authorization": "Bearer test-token"}

    response = client.get("/api/v1/cost-attribution/chargebacks", headers=headers)
    assert response.status_code == 200
    payload = response.json()
    assert isinstance(payload["chargebacks"], list)
    assert payload["chargebacks"][0]["team"] == "engineering"
