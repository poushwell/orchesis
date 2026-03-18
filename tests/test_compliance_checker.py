from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.compliance_checker import RealTimeComplianceChecker


def _compliant_policy() -> dict:
    return {
        "recording": {"enabled": True},
        "threat_intel": {"enabled": True},
        "logging": {"enabled": True},
        "rules": [
            {"name": "rate_limit", "max_requests_per_minute": 60},
            {"name": "regex_match", "field": "prompt", "deny_patterns": ["ignore previous instructions"]},
        ],
    }


def test_compliant_policy_passes() -> None:
    checker = RealTimeComplianceChecker()
    result = checker.check_policy(_compliant_policy())
    assert result["compliant"] is True
    assert result["critical_failures"] == []


def test_missing_logging_fails() -> None:
    checker = RealTimeComplianceChecker()
    policy = _compliant_policy()
    policy["recording"] = {"enabled": False}
    policy["logging"] = {"enabled": False}
    result = checker.check_policy(policy)
    assert result["compliant"] is False
    assert "eu_ai_act_logging" in result["critical_failures"]


def test_missing_rate_limit_fails() -> None:
    checker = RealTimeComplianceChecker()
    policy = _compliant_policy()
    policy["rules"] = [item for item in policy["rules"] if item.get("name") != "rate_limit"]
    result = checker.check_policy(policy)
    assert result["compliant"] is False
    assert "owasp_rate_limiting" in result["warnings"]


def test_certificate_issued_when_compliant() -> None:
    checker = RealTimeComplianceChecker()
    result = checker.check_policy(_compliant_policy())
    cert = result["certificate"]
    assert cert is not None
    assert isinstance(cert["certificate_id"], str)
    assert cert["score"] == 100.0


def test_certificate_not_issued_when_not_compliant() -> None:
    checker = RealTimeComplianceChecker()
    policy = _compliant_policy()
    policy["threat_intel"] = {"enabled": False}
    result = checker.check_policy(policy)
    assert result["compliant"] is False
    assert result["certificate"] is None


def test_score_computed() -> None:
    checker = RealTimeComplianceChecker()
    result = checker.check_policy(_compliant_policy())
    assert 0.0 <= result["score"] <= 100.0
    assert result["score"] == 100.0


def test_api_check_policy_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy_path), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)
    response = client.post(
        "/api/v1/compliance/check-policy",
        json={"policy": _compliant_policy()},
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["compliant"] is True
    assert payload["score"] == 100.0
