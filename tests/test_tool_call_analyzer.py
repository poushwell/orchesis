from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.tool_call_analyzer import ToolCallAnalyzer


def _call(name: str) -> dict:
    return {"tool": name}


def _event(event_id: str, session_id: str, tool: str, tool_calls: list[dict] | None = None) -> dict:
    return {
        "event_id": event_id,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "agent_id": "agent-x",
        "tool": tool,
        "params_hash": "abc123",
        "cost": 0.01,
        "decision": "ALLOW",
        "reasons": [],
        "rules_checked": ["rule-a"],
        "rules_triggered": [],
        "evaluation_order": ["parse", "policy", "emit"],
        "evaluation_duration_us": 900,
        "policy_version": "v1",
        "state_snapshot": {
            "session_id": session_id,
            "tool_calls": tool_calls or [],
        },
    }


def test_bash_classified_critical() -> None:
    analyzer = ToolCallAnalyzer()
    assert analyzer.get_tool_risk("bash") == "critical"
    payload = analyzer.analyze([_call("bash")])
    assert payload["risk_level"] == "critical"


def test_safe_tools_low_risk() -> None:
    analyzer = ToolCallAnalyzer()
    payload = analyzer.analyze([_call("read_file"), _call("read_file")])
    assert payload["risk_level"] == "low"
    assert payload["high_risk_tools_used"] == []


def test_chaining_detected() -> None:
    analyzer = ToolCallAnalyzer()
    payload = analyzer.analyze([_call("web_search"), _call("read_file"), _call("bash")])
    assert payload["chaining_detected"] is True
    assert payload["suspicious_patterns"]
    assert payload["suspicious_patterns"][0]["sequence"] == ["web_search", "read_file", "bash"]


def test_tool_frequency_counted() -> None:
    analyzer = ToolCallAnalyzer()
    payload = analyzer.analyze([_call("web_search"), _call("web_search"), _call("read_file")])
    assert payload["tool_frequency"]["web_search"] == 2
    assert payload["tool_frequency"]["read_file"] == 1


def test_session_stats_aggregated() -> None:
    analyzer = ToolCallAnalyzer()
    rows = [
        _event("1", "sess-1", "read_file", [{"tool": "web_search"}, {"tool": "read_file"}]),
        _event("2", "sess-1", "bash", [{"tool": "bash"}]),
        _event("3", "sess-2", "read_file", [{"tool": "read_file"}]),
    ]
    payload = analyzer.get_session_tool_stats("sess-1", rows)
    assert payload["session_id"] == "sess-1"
    stats = payload["tool_stats"]
    assert stats["total_calls"] >= 3
    assert "bash" in stats["high_risk_tools_used"]


def test_api_analyze_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)

    response = client.post(
        "/api/v1/tools/analyze",
        json={"tool_calls": [_call("web_search"), _call("read_file"), _call("bash")]},
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["risk_level"] == "critical"
    assert payload["chaining_detected"] is True


def test_api_tool_risk_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    decisions = tmp_path / "decisions.jsonl"
    decisions.write_text(
        json.dumps(_event("evt-1", "sess-x", "read_file", [{"tool": "read_file"}]), ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    app = create_api_app(policy_path=str(policy), decisions_log=str(decisions))
    client = TestClient(app)

    risk_response = client.get("/api/v1/tools/risk/bash", headers={"Authorization": "Bearer test-token"})
    assert risk_response.status_code == 200
    assert risk_response.json()["risk_level"] == "critical"

    session_response = client.get("/api/v1/tools/session/sess-x", headers={"Authorization": "Bearer test-token"})
    assert session_response.status_code == 200
    session_payload = session_response.json()
    assert session_payload["session_id"] == "sess-x"
    assert "tool_stats" in session_payload
