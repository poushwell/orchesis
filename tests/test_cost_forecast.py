from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.cost_forecast import CostForecaster


def test_fit_and_predict() -> None:
    model = CostForecaster({"history_days": 7, "confidence": 0.95})
    points = [{"hour_index": i, "cost": 1.0 + (0.1 * i)} for i in range(24)]
    model.fit(points)
    forecast = model.predict(hours_ahead=24)
    assert forecast["hours_ahead"] == 24
    assert float(forecast["predicted_cost"]) >= 0.0


def test_increasing_trend_detected() -> None:
    model = CostForecaster()
    model.fit([{"hour_index": i, "cost": float(i)} for i in range(24)])
    forecast = model.predict(12)
    assert forecast["trend"] == "increasing"


def test_stable_trend_detected() -> None:
    model = CostForecaster()
    model.fit([{"hour_index": i, "cost": 2.0} for i in range(24)])
    forecast = model.predict(12)
    assert forecast["trend"] == "stable"


def test_monthly_projection() -> None:
    model = CostForecaster()
    model.fit([{"hour_index": i, "cost": 1.0 + (0.01 * i)} for i in range(48)])
    monthly = model.predict_monthly()
    assert monthly["hours_ahead"] == 24 * 30
    assert float(monthly["predicted_monthly_cost"]) >= 0.0


def test_breakeven_computed() -> None:
    model = CostForecaster()
    model.fit([{"hour_index": i, "cost": 10.0} for i in range(48)])
    breakeven = model.get_breakeven(monthly_budget=50.0)
    assert breakeven["safe"] is False
    assert isinstance(breakeven["days_until_exhausted"], float)
    assert isinstance(breakeven["exhaustion_date"], str)


def test_confidence_interval_valid() -> None:
    model = CostForecaster({"confidence": 0.95})
    model.fit([{"hour_index": i, "cost": (i % 5) + 1.0} for i in range(72)])
    forecast = model.predict(24)
    assert float(forecast["confidence_low"]) <= float(forecast["predicted_cost"])
    assert float(forecast["confidence_high"]) >= float(forecast["confidence_low"])


def _event(*, hours_ago: int, cost: float) -> dict:
    ts = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    return {
        "event_id": f"evt-{hours_ago}",
        "timestamp": ts.isoformat().replace("+00:00", "Z"),
        "agent_id": "agent-a",
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
        "state_snapshot": {"session_id": "s1", "model": "gpt-4o-mini"},
    }


def test_api_forecast_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    decisions_log = tmp_path / "decisions.jsonl"
    events = [_event(hours_ago=i, cost=0.5 + i * 0.02) for i in range(1, 25)]
    decisions_log.write_text("\n".join(json.dumps(item, ensure_ascii=False) for item in events) + "\n", encoding="utf-8")

    app = create_api_app(policy_path=str(policy), decisions_log=str(decisions_log))
    client = TestClient(app)

    res1 = client.get("/api/v1/cost-forecast?hours=24", headers={"Authorization": "Bearer test-token"})
    assert res1.status_code == 200
    payload1 = res1.json()
    assert payload1["hours_ahead"] == 24
    assert "predicted_cost" in payload1

    res2 = client.get("/api/v1/cost-forecast/monthly", headers={"Authorization": "Bearer test-token"})
    assert res2.status_code == 200
    assert "predicted_monthly_cost" in res2.json()

    res3 = client.get("/api/v1/cost-forecast/breakeven?budget=50.0", headers={"Authorization": "Bearer test-token"})
    assert res3.status_code == 200
    assert "safe" in res3.json()
