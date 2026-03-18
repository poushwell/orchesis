from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

from orchesis.anomaly_predictor import AnomalyPredictor
from orchesis.api import create_api_app


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


def _event(agent_id: str, score: float, level: str = "normal") -> dict:
    return {
        "event_id": f"evt-{agent_id}-{score}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent_id": agent_id,
        "tool": "chat",
        "params_hash": "abc",
        "cost": 0.01,
        "decision": "ALLOW",
        "reasons": [],
        "rules_checked": [],
        "rules_triggered": [],
        "evaluation_order": [],
        "evaluation_duration_us": 100,
        "policy_version": "v1",
        "state_snapshot": {"anomaly_score": score, "context_budget_level": level},
    }


def _write_events(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(item, ensure_ascii=False) for item in rows) + "\n", encoding="utf-8")


def _make_app(tmp_path: Path):
    policy_path = tmp_path / "policy.yaml"
    decisions_log = tmp_path / "decisions.jsonl"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(decisions_log),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    return app, decisions_log


def test_predict_returns_result() -> None:
    predictor = AnomalyPredictor({})
    out = predictor.predict([{"score": 0.2}, {"score": 0.4}, {"score": 0.7}])
    assert "anomaly_likely" in out
    assert "confidence" in out
    assert "signals" in out


def test_increasing_trend_detected() -> None:
    trend = AnomalyPredictor({}).detect_trend([0.1, 0.2, 0.3, 0.5])
    assert trend["trend"] == "increasing"
    assert trend["rate"] > 0


def test_early_warning_triggered() -> None:
    predictor = AnomalyPredictor({"confidence": 0.6})
    events = [_event("agent-a", 0.2), _event("agent-a", 0.6), _event("agent-a", 0.9, "L2")]
    out = predictor.early_warning("agent-a", events)
    assert out["anomaly_likely"] is True
    assert out["predicted_type"] is not None


def test_confidence_threshold_respected() -> None:
    predictor = AnomalyPredictor({"confidence": 0.95})
    out = predictor.predict([{"score": 0.2}, {"score": 0.3}, {"score": 0.4}])
    assert out["anomaly_likely"] is False


def test_prediction_history_tracked() -> None:
    predictor = AnomalyPredictor({})
    predictor.record_prediction("agent-z", predictor.predict([{"score": 0.2}, {"score": 0.5}, {"score": 0.7}]))
    history = predictor.get_predictions_history("agent-z")
    assert len(history) == 1
    assert history[0]["agent_id"] == "agent-z"


@pytest.mark.asyncio
async def test_api_predict_endpoint(tmp_path: Path) -> None:
    app, _ = _make_app(tmp_path)
    async with await _client(app) as client:
        res = await client.post(
            "/api/v1/predict/anomaly",
            json={"agent_id": "agent-a", "recent_metrics": [{"score": 0.2}, {"score": 0.6}, {"score": 0.9}]},
            headers=_auth(),
        )
    assert res.status_code == 200
    payload = res.json()
    assert "confidence" in payload
    assert "anomaly_likely" in payload


@pytest.mark.asyncio
async def test_api_warning_endpoint(tmp_path: Path) -> None:
    app, decisions_log = _make_app(tmp_path)
    _write_events(decisions_log, [_event("agent-w", 0.2), _event("agent-w", 0.7), _event("agent-w", 0.9, "L2")])
    async with await _client(app) as client:
        res = await client.get("/api/v1/predict/agent-w/warning", headers=_auth())
    assert res.status_code == 200
    payload = res.json()
    assert "anomaly_likely" in payload
    assert "recommendation" in payload
