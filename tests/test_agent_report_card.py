from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.agent_report_card import AgentReportCard
from orchesis.api import create_api_app


def _metrics_good() -> dict:
    return {
        "deny_rate": 0.8,
        "token_yield": 0.9,
        "error_rate": 0.05,
        "recording_enabled": True,
        "audit_trail": True,
        "latency_within_sla": True,
        "cache_hit_rate": 0.7,
    }


def _client(tmp_path: Path, monkeypatch) -> TestClient:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    return TestClient(app)


def test_card_generated() -> None:
    card = AgentReportCard().generate("agent-a", _metrics_good())
    assert card["agent_id"] == "agent-a"
    assert "overall_score" in card


def test_grade_assigned() -> None:
    card = AgentReportCard().generate("agent-a", _metrics_good())
    assert card["grade"] in AgentReportCard.GRADE_THRESHOLDS


def test_badge_text_correct() -> None:
    card = AgentReportCard().generate("agent-a", _metrics_good())
    assert card["badge"].startswith("Orchesis Verified:")
    assert "/100" in card["badge"]


def test_strengths_identified() -> None:
    card = AgentReportCard().generate("agent-a", _metrics_good())
    assert isinstance(card["strengths"], list)
    assert "security" in card["strengths"]


def test_improvements_identified() -> None:
    weak = {
        "deny_rate": 0.1,
        "token_yield": 0.4,
        "error_rate": 0.4,
        "recording_enabled": False,
        "audit_trail": False,
        "latency_within_sla": False,
        "cache_hit_rate": 0.1,
    }
    card = AgentReportCard().generate("agent-b", weak)
    assert isinstance(card["improvements"], list)
    assert card["improvements"]


def test_arc_ready_flag() -> None:
    card = AgentReportCard().generate("agent-a", _metrics_good())
    assert isinstance(card["arc_ready"], bool)
    assert card["arc_ready"] is True


def test_compare_grades() -> None:
    report = AgentReportCard()
    _ = report.generate("a", _metrics_good())
    _ = report.generate(
        "b",
        {
            "deny_rate": 0.2,
            "token_yield": 0.3,
            "error_rate": 0.3,
            "recording_enabled": False,
            "audit_trail": False,
            "latency_within_sla": False,
            "cache_hit_rate": 0.1,
        },
    )
    result = report.compare_grades("a", "b")
    assert result["winner"] == "a"


def test_api_report_card_endpoint(tmp_path: Path, monkeypatch) -> None:
    client = _client(tmp_path, monkeypatch)
    headers = {"Authorization": "Bearer test-token"}
    created = client.post("/api/v1/report-card/agent-x", json=_metrics_good(), headers=headers)
    assert created.status_code == 200
    fetched = client.get("/api/v1/report-card/agent-x", headers=headers)
    assert fetched.status_code == 200
    compare = client.get("/api/v1/report-card/compare/agent-x/agent-x", headers=headers)
    assert compare.status_code == 200
