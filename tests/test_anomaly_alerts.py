from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.anomaly_alerts import AnomalyAlertManager
from orchesis.api import create_api_app
from orchesis.context_dna import ContextDNA


class _DummyDNA:
    def __init__(self, baseline: dict):
        self.baseline = baseline


class _DummyStore:
    def __init__(self, baseline_by_agent: dict[str, dict]):
        self._baseline_by_agent = baseline_by_agent

    def get(self, agent_id: str):
        baseline = self._baseline_by_agent.get(agent_id)
        if baseline is None:
            return None
        return _DummyDNA(baseline)


def _manager() -> AnomalyAlertManager:
    store = _DummyStore(
        {
            "agent-a": {
                "cost_per_request": 0.1,
                "tool_call_frequency": 1.0,
                "avg_prompt_length": 100.0,
                "session_duration_avg": 1000.0,
                "error_rate": 0.05,
                "cache_hit_rate": 0.8,
            }
        }
    )
    return AnomalyAlertManager(store, {"anomaly_threshold": 0.5})


def test_cost_spike_triggers_alert() -> None:
    manager = _manager()
    alerts = manager.check(
        "agent-a",
        {
            "cost_per_request": 0.5,
            "tool_call_frequency": 1.0,
            "avg_prompt_length": 100.0,
            "session_duration_avg": 1000.0,
            "error_rate": 0.05,
            "cache_hit_rate": 0.8,
        },
    )
    assert any(item["type"] == "cost_spike" for item in alerts)


def test_normal_behavior_no_alert() -> None:
    manager = _manager()
    alerts = manager.check(
        "agent-a",
        {
            "cost_per_request": 0.11,
            "tool_call_frequency": 1.0,
            "avg_prompt_length": 102.0,
            "session_duration_avg": 980.0,
            "error_rate": 0.05,
            "cache_hit_rate": 0.79,
        },
    )
    assert alerts == []


def test_dismiss_alert() -> None:
    manager = _manager()
    alerts = manager.check("agent-a", {"cost_per_request": 0.5, "tool_call_frequency": 1.0})
    alert_id = alerts[0]["id"]
    assert manager.dismiss(alert_id) is True
    assert manager.dismiss(alert_id) is False


def test_filter_by_agent() -> None:
    manager = AnomalyAlertManager(
        _DummyStore(
            {
                "agent-a": {"cost_per_request": 0.1},
                "agent-b": {"cost_per_request": 0.1},
            }
        )
    )
    manager.check("agent-a", {"cost_per_request": 0.5})
    manager.check("agent-b", {"cost_per_request": 0.6})
    rows = manager.get_alerts(agent_id="agent-a")
    assert rows
    assert all(item["agent_id"] == "agent-a" for item in rows)


def test_filter_by_since() -> None:
    manager = _manager()
    manager.check("agent-a", {"cost_per_request": 0.5})
    old = manager.get_alerts(limit=1)[0]
    old["timestamp"] = time.time() - 3600.0
    manager.dismiss(old["id"])
    manager.check("agent-a", {"cost_per_request": 0.5, "error_rate": 0.8})
    recent = manager.get_alerts(since=time.time() - 120.0)
    assert recent
    assert all(float(item["timestamp"]) >= time.time() - 120.0 for item in recent)


def test_summary_counts_by_type() -> None:
    manager = _manager()
    manager.check("agent-a", {"cost_per_request": 0.5, "error_rate": 0.8})
    summary = manager.get_summary()
    assert summary["total_active"] >= 1
    assert "by_type" in summary
    assert "by_severity" in summary


def test_api_alerts_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    decisions_log = tmp_path / "decisions.jsonl"
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    row = {
        "event_id": "evt-1",
        "timestamp": now,
        "agent_id": "agent-api",
        "tool": "web.fetch",
        "params_hash": "abc",
        "cost": 1.2,
        "decision": "ALLOW",
        "reasons": [],
        "rules_checked": [],
        "rules_triggered": [],
        "evaluation_order": [],
        "evaluation_duration_us": 120,
        "policy_version": "v1",
        "state_snapshot": {"session_id": "sess-1", "prompt_length": 20, "cache_hit_rate": 0.8},
    }
    decisions_log.write_text(json.dumps(row, ensure_ascii=False) + "\n", encoding="utf-8")

    app = create_api_app(policy_path=str(policy), decisions_log=str(decisions_log))
    dna = ContextDNA("agent-api")
    dna.baseline = {
        "cost_per_request": 0.1,
        "tool_call_frequency": 1.0,
        "avg_prompt_length": 20.0,
        "session_duration_avg": 1.0,
        "error_rate": 0.0,
        "cache_hit_rate": 0.8,
    }
    app.state.dna_store.save(dna)

    client = TestClient(app)
    response = client.get("/api/v1/anomaly/alerts", headers={"Authorization": "Bearer test-token"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["count"] >= 1
    assert any(item["type"] == "cost_spike" for item in payload["alerts"])
