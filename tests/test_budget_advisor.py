from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.budget_advisor import BudgetAdvisor


def _event(
    *,
    hours_ago: int,
    agent_id: str,
    session_id: str,
    cost: float,
    cache_hit_rate: float | None = None,
    loop_detected: bool = False,
) -> dict:
    ts = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    snapshot: dict[str, object] = {
        "session_id": session_id,
        "model": "gpt-4o-mini",
    }
    if cache_hit_rate is not None:
        snapshot["cache_hit_rate"] = float(cache_hit_rate)
    if loop_detected:
        snapshot["loop_detected"] = True
    return {
        "event_id": f"evt-{agent_id}-{session_id}-{hours_ago}",
        "timestamp": ts.isoformat().replace("+00:00", "Z"),
        "agent_id": agent_id,
        "tool": "shell.exec",
        "cost": float(cost),
        "decision": "ALLOW",
        "reasons": ["loop_detected"] if loop_detected else [],
        "state_snapshot": snapshot,
    }


def _sample_events() -> list[dict]:
    return [
        _event(hours_ago=1, agent_id="agent-a", session_id="s1", cost=1.2, cache_hit_rate=0.2, loop_detected=True),
        _event(hours_ago=2, agent_id="agent-a", session_id="s2", cost=0.8, cache_hit_rate=0.1),
        _event(hours_ago=3, agent_id="agent-b", session_id="s3", cost=0.4, cache_hit_rate=0.4),
    ]


def test_analysis_returns_recommendations() -> None:
    advisor = BudgetAdvisor()
    analysis = advisor.analyze(_sample_events(), {"daily_limit_usd": 2.0})
    assert "recommendations" in analysis
    assert isinstance(analysis["recommendations"], list)
    assert len(analysis["recommendations"]) >= 1


def test_quick_wins_returns_top_3() -> None:
    advisor = BudgetAdvisor()
    analysis = {
        "recommendations": [
            {"type": "enable_cache", "reason": "a", "suggested_value": 1, "estimated_savings": 9, "priority": "high"},
            {"type": "set_per_agent", "reason": "b", "suggested_value": 1, "estimated_savings": 8, "priority": "medium"},
            {"type": "decrease", "reason": "c", "suggested_value": 1, "estimated_savings": 7, "priority": "medium"},
            {"type": "increase", "reason": "d", "suggested_value": 1, "estimated_savings": 6, "priority": "low"},
        ]
    }
    wins = advisor.get_quick_wins(analysis)
    assert len(wins) == 3


def test_loop_waste_detected() -> None:
    advisor = BudgetAdvisor()
    analysis = advisor.analyze(
        [_event(hours_ago=1, agent_id="agent-a", session_id="s1", cost=2.0, loop_detected=True)],
        {"daily_limit_usd": 10.0},
    )
    assert analysis["waste_detected"]["loop_waste"] > 0.0


def test_cache_miss_waste_calculated() -> None:
    advisor = BudgetAdvisor()
    analysis = advisor.analyze(
        [_event(hours_ago=1, agent_id="agent-a", session_id="s1", cost=1.0, cache_hit_rate=0.0)],
        {"daily_limit_usd": 10.0},
    )
    assert analysis["waste_detected"]["cache_miss_waste"] > 0.0


def test_projected_monthly_computed() -> None:
    advisor = BudgetAdvisor()
    analysis = advisor.analyze(_sample_events(), {"daily_limit_usd": 100.0})
    assert analysis["projected_monthly"] == round(analysis["current_daily_spend"] * 30.0, 6)


def test_api_advice_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\nbudget_daily: 2.0\n", encoding="utf-8")
    decisions_log = tmp_path / "decisions.jsonl"
    decisions_log.write_text("\n".join(json.dumps(item, ensure_ascii=False) for item in _sample_events()) + "\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(decisions_log))
    client = TestClient(app)
    response = client.get("/api/v1/budget/advice", headers={"Authorization": "Bearer test-token"})
    assert response.status_code == 200
    payload = response.json()
    assert "current_daily_spend" in payload
    assert "projected_monthly" in payload
    assert "recommendations" in payload
