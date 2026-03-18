from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
from tests.cli_test_utils import CliRunner

from orchesis.api import create_api_app
from orchesis.arc_readiness import AgentReadinessCertifier
from orchesis.cli import main


def _good_policy() -> dict:
    return {
        "recording": {"enabled": True},
        "threat_intel": {"enabled": True},
        "loop_detection": {"enabled": True},
        "rules": [{"name": "rate_limit", "max_requests_per_minute": 60}],
        "api_rate_limit": {"enabled": True},
    }


def _good_metrics() -> dict:
    return {
        "credential_scanning_enabled": True,
        "circuit_breaker_configured": True,
        "auto_healing_enabled": True,
        "error_rate": 0.01,
        "uptime": 0.999,
        "audit_trail_available": True,
        "latency_ms": 120,
        "latency_sla_ms": 500,
        "cost": 10,
        "budget_limit": 100,
        "cache_hit_rate": 0.5,
    }


def test_certification_above_threshold() -> None:
    certifier = AgentReadinessCertifier()
    result = certifier.certify("agent-a", _good_metrics(), _good_policy())
    assert result["certified"] is True
    assert result["score"] >= 75.0


def test_not_certified_below_threshold() -> None:
    certifier = AgentReadinessCertifier()
    result = certifier.certify(
        "agent-b",
        {"error_rate": 0.9, "uptime": 0.2, "cache_hit_rate": 0.0, "latency_ms": 4000, "latency_sla_ms": 100},
        {"recording": {"enabled": False}, "threat_intel": {"enabled": False}, "loop_detection": {"enabled": False}, "rules": []},
    )
    assert result["certified"] is False
    assert result["grade"] == "NOT_CERTIFIED"


def test_all_14_criteria_checked() -> None:
    certifier = AgentReadinessCertifier()
    result = certifier.certify("agent-a", _good_metrics(), _good_policy())
    total = sum(len(items) for items in certifier.CRITERIA.values())
    passed = int(round(result["score"] * total / 100.0))
    assert passed + len(result["failures"]) == total
    assert total == 14


def test_badge_text_generated() -> None:
    certifier = AgentReadinessCertifier()
    badge = certifier.get_badge(82.0)
    assert badge == "Orchesis Verified: ARC 82/100"


def test_certificate_issued() -> None:
    certifier = AgentReadinessCertifier()
    result = certifier.certify("agent-a", _good_metrics(), _good_policy())
    assert result["certificate_id"] is not None
    rows = certifier.list_certificates()
    assert len(rows) == 1
    assert rows[0]["agent_id"] == "agent-a"


def _policy_yaml() -> str:
    return """
api:
  token: "test-token"
agent_readiness:
  metrics:
    agent-good:
      credential_scanning_enabled: true
      circuit_breaker_configured: true
      auto_healing_enabled: true
      error_rate: 0.01
      uptime: 0.999
      audit_trail_available: true
      latency_ms: 120
      latency_sla_ms: 500
      cost: 10
      budget_limit: 100
      cache_hit_rate: 0.4
    agent-bad:
      credential_scanning_enabled: false
      circuit_breaker_configured: false
      auto_healing_enabled: false
      error_rate: 0.8
      uptime: 0.3
      audit_trail_available: false
      latency_ms: 1200
      latency_sla_ms: 200
      cost: 200
      budget_limit: 50
      cache_hit_rate: 0.01
recording:
  enabled: true
threat_intel:
  enabled: true
loop_detection:
  enabled: true
rules:
  - name: rate_limit
    max_requests_per_minute: 60
""".strip()


def test_cli_arc_check_exits_0_on_pass(tmp_path: Path) -> None:
    policy = tmp_path / "orchesis.yaml"
    policy.write_text(_policy_yaml(), encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(main, ["arc-check", "--agent", "agent-good", "--min-score", "75", "--policy", str(policy)])
    assert result.exit_code == 0


def test_cli_arc_check_exits_1_on_fail(tmp_path: Path) -> None:
    policy = tmp_path / "orchesis.yaml"
    policy.write_text(_policy_yaml(), encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(main, ["arc-check", "--agent", "agent-bad", "--min-score", "75", "--policy", str(policy)])
    assert result.exit_code == 1


def test_api_certify_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text(_policy_yaml(), encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)
    response = client.post("/api/v1/arc/certify/agent-good", headers={"Authorization": "Bearer test-token"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["agent_id"] == "agent-good"
    assert "score" in payload


def test_api_certificate_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text(_policy_yaml(), encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)
    headers = {"Authorization": "Bearer test-token"}
    create = client.post("/api/v1/arc/certify/agent-good", headers=headers)
    assert create.status_code == 200
    response = client.get("/api/v1/arc/agent-good/certificate", headers=headers)
    assert response.status_code == 200
    assert response.json()["agent_id"] == "agent-good"
