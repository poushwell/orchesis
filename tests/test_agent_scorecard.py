from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.agent_scorecard import AgentScorecard
from orchesis.api import create_api_app


def _event(
    *,
    event_id: str,
    agent_id: str,
    decision: str = "ALLOW",
    cost: float = 0.01,
    cache_hit_rate: float = 0.9,
    hours_ago: int = 1,
    duration_us: int = 5000,
) -> dict:
    ts = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    return {
        "event_id": event_id,
        "timestamp": ts.isoformat().replace("+00:00", "Z"),
        "agent_id": agent_id,
        "tool": "chat",
        "params_hash": "abc123",
        "cost": float(cost),
        "decision": str(decision).upper(),
        "reasons": [] if decision == "ALLOW" else ["policy:block"],
        "rules_checked": ["rule-a"],
        "rules_triggered": ["rule-a"] if str(decision).upper() == "DENY" else [],
        "evaluation_order": ["parse", "policy", "emit"],
        "evaluation_duration_us": int(duration_us),
        "policy_version": "v1",
        "state_snapshot": {"cache_hit_rate": float(cache_hit_rate)},
    }


def test_scorecard_computed() -> None:
    scorer = AgentScorecard()
    card = scorer.compute(
        agent_id="agent-a",
        decisions_log=[_event(event_id="1", agent_id="agent-a"), _event(event_id="2", agent_id="agent-a")],
    )
    assert card["agent_id"] == "agent-a"
    assert 0.0 <= card["overall_score"] <= 100.0
    assert "metrics" in card
    assert "security_score" in card["metrics"]


def test_grade_assigned_correctly() -> None:
    scorer = AgentScorecard()
    strong = [
        _event(event_id="a1", agent_id="agent-a", decision="ALLOW", cost=0.001, cache_hit_rate=0.95, duration_us=800),
        _event(event_id="a2", agent_id="agent-a", decision="ALLOW", cost=0.001, cache_hit_rate=0.95, duration_us=900),
    ]
    weak = [
        _event(event_id="b1", agent_id="agent-b", decision="DENY", cost=2.0, cache_hit_rate=0.0, duration_us=350000),
        _event(event_id="b2", agent_id="agent-b", decision="DENY", cost=2.0, cache_hit_rate=0.0, duration_us=360000),
    ]
    card_a = scorer.compute("agent-a", strong)
    card_b = scorer.compute("agent-b", weak)
    assert card_a["grade"] in {"A+", "A", "B+"}
    assert card_b["grade"] in {"C", "D"}


def test_week_over_week_delta() -> None:
    scorer = AgentScorecard()
    baseline = [
        _event(event_id="w1", agent_id="agent-a", decision="ALLOW", cost=0.01, cache_hit_rate=0.9),
        _event(event_id="w2", agent_id="agent-a", decision="ALLOW", cost=0.01, cache_hit_rate=0.9),
    ]
    degraded = [
        _event(event_id="w3", agent_id="agent-a", decision="DENY", cost=1.2, cache_hit_rate=0.1),
        _event(event_id="w4", agent_id="agent-a", decision="DENY", cost=1.2, cache_hit_rate=0.1),
    ]
    _ = scorer.compute("agent-a", baseline, period="7d")
    current = scorer.compute("agent-a", degraded, period="7d")
    assert current["week_over_week"]["overall_score_delta"] < 0.0


def test_badges_awarded() -> None:
    scorer = AgentScorecard()
    events = [
        _event(event_id="t1", agent_id="top", decision="ALLOW", cost=0.001, cache_hit_rate=0.97, duration_us=500),
        _event(event_id="t2", agent_id="top", decision="ALLOW", cost=0.001, cache_hit_rate=0.97, duration_us=600),
        _event(event_id="o1", agent_id="other", decision="DENY", cost=0.9, cache_hit_rate=0.2, duration_us=100000),
        _event(event_id="o2", agent_id="other", decision="ALLOW", cost=0.9, cache_hit_rate=0.2, duration_us=100000),
    ]
    cards = scorer.compute_all(events)
    top = cards[0]
    assert "🏆 Top Performer" in top["badges"]


def test_leaderboard_ranked() -> None:
    scorer = AgentScorecard()
    events = [
        _event(event_id="a1", agent_id="a", cost=0.001, cache_hit_rate=0.95),
        _event(event_id="a2", agent_id="a", cost=0.001, cache_hit_rate=0.95),
        _event(event_id="b1", agent_id="b", decision="DENY", cost=0.8, cache_hit_rate=0.3),
        _event(event_id="c1", agent_id="c", decision="DENY", cost=1.5, cache_hit_rate=0.0),
    ]
    leaderboard = scorer.get_leaderboard(events)
    assert len(leaderboard) == 3
    assert leaderboard[0]["overall_score"] >= leaderboard[1]["overall_score"] >= leaderboard[2]["overall_score"]
    assert leaderboard[0]["rank"] == 1


def test_compute_all_returns_list() -> None:
    scorer = AgentScorecard()
    cards = scorer.compute_all(
        [
            _event(event_id="1", agent_id="agent-a"),
            _event(event_id="2", agent_id="agent-b"),
        ]
    )
    assert isinstance(cards, list)
    assert len(cards) == 2


def test_api_scorecard_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    decisions = tmp_path / "decisions.jsonl"
    rows = [
        _event(event_id="1", agent_id="agent-a", cost=0.01, cache_hit_rate=0.8),
        _event(event_id="2", agent_id="agent-a", cost=0.02, cache_hit_rate=0.9),
    ]
    decisions.write_text("\n".join(json.dumps(item, ensure_ascii=False) for item in rows) + "\n", encoding="utf-8")

    app = create_api_app(policy_path=str(policy), decisions_log=str(decisions))
    client = TestClient(app)
    response = client.get("/api/v1/scorecard/agent-a?period=30d", headers={"Authorization": "Bearer test-token"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["agent_id"] == "agent-a"
    assert payload["period"] == "30d"
    assert "overall_score" in payload


def test_api_leaderboard_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    decisions = tmp_path / "decisions.jsonl"
    rows = [
        _event(event_id="1", agent_id="agent-a", cost=0.001, cache_hit_rate=0.95),
        _event(event_id="2", agent_id="agent-b", decision="DENY", cost=1.0, cache_hit_rate=0.1),
    ]
    decisions.write_text("\n".join(json.dumps(item, ensure_ascii=False) for item in rows) + "\n", encoding="utf-8")

    app = create_api_app(policy_path=str(policy), decisions_log=str(decisions))
    client = TestClient(app)
    response = client.get("/api/v1/scorecard/leaderboard", headers={"Authorization": "Bearer test-token"})
    assert response.status_code == 200
    payload = response.json()
    assert "leaderboard" in payload
    assert isinstance(payload["leaderboard"], list)
    if payload["leaderboard"]:
        assert payload["leaderboard"][0]["rank"] == 1
