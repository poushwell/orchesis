from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.cost_analytics import CostAnalytics


def _event(
    *,
    hours_ago: int,
    model: str,
    agent_id: str,
    session_id: str,
    cost: float,
    cache_saved: float = 0.0,
    loop_saved: float = 0.0,
    compression_saved: float = 0.0,
) -> dict:
    ts = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    return {
        "event_id": f"evt-{agent_id}-{session_id}-{hours_ago}",
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
        "state_snapshot": {
            "session_id": session_id,
            "model": model,
            "cache_cost_saved_usd": float(cache_saved),
            "loop_cost_saved_usd": float(loop_saved),
            "compression_cost_saved_usd": float(compression_saved),
        },
    }


def _sample_events() -> list[dict]:
    return [
        _event(hours_ago=1, model="gpt-4o-mini", agent_id="agent-a", session_id="s1", cost=0.4, cache_saved=0.1),
        _event(hours_ago=2, model="gpt-4o", agent_id="agent-b", session_id="s2", cost=0.8, loop_saved=0.2),
        _event(hours_ago=3, model="gpt-4o-mini", agent_id="agent-a", session_id="s1", cost=0.2, compression_saved=0.05),
    ]


def test_cost_by_model_computed() -> None:
    payload = CostAnalytics().compute(_sample_events(), period_hours=24)
    assert payload["cost_by_model"]["gpt-4o-mini"] == 0.6
    assert payload["cost_by_model"]["gpt-4o"] == 0.8


def test_cost_by_agent_computed() -> None:
    payload = CostAnalytics().compute(_sample_events(), period_hours=24)
    assert payload["cost_by_agent"]["agent-a"] == 0.6
    assert payload["cost_by_agent"]["agent-b"] == 0.8


def test_forecast_positive() -> None:
    payload = CostAnalytics().compute(_sample_events(), period_hours=24)
    assert float(payload["forecast_24h"]) > 0.0


def test_savings_breakdown() -> None:
    payload = CostAnalytics().compute(_sample_events(), period_hours=24)
    assert payload["savings"]["cache"] == 0.1
    assert payload["savings"]["loop_prevention"] == 0.2
    assert payload["savings"]["compression"] == 0.05
    assert payload["savings"]["total"] == 0.35


def test_hourly_breakdown_length() -> None:
    payload = CostAnalytics().compute(_sample_events(), period_hours=24)
    assert len(payload["cost_by_hour"]) == 24


def test_api_endpoint_returns_analytics(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    decisions_log = tmp_path / "decisions.jsonl"
    lines = [json.dumps(item, ensure_ascii=False) for item in _sample_events()]
    decisions_log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    app = create_api_app(policy_path=str(policy), decisions_log=str(decisions_log))
    client = TestClient(app)
    response = client.get("/api/v1/cost-analytics?period=24", headers={"Authorization": "Bearer test-token"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["period_hours"] == 24
    assert payload["total_cost"] == 1.4
    assert "cost_by_model" in payload
