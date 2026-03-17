from __future__ import annotations

from pathlib import Path

from orchesis.cli import main
from orchesis.policy_validator import PolicyAsCodeValidator
from tests.cli_test_utils import CliRunner


def _good_policy() -> dict:
    return {
        "version": "1.0",
        "rules": [
            {"name": "rate_limit", "max_requests_per_minute": 60},
            {"name": "regex_match", "field": "prompt", "deny_patterns": ["ignore all previous instructions"]},
            {"name": "budget_limit", "max_cost_per_call": 1.0},
        ],
        "logging": {"enabled": True},
        "recording": {"enabled": True},
        "budget": {"enabled": True, "daily_limit_usd": 10.0},
        "threat_intel": {"enabled": True},
        "loop_detection": {"enabled": True},
    }


def test_valid_policy_passes() -> None:
    validator = PolicyAsCodeValidator()
    report = validator.validate(_good_policy())
    assert report.passed is True
    assert report.violations == []


def test_missing_logging_fails_eu_ai_act() -> None:
    validator = PolicyAsCodeValidator()
    policy = _good_policy()
    policy["logging"] = {"enabled": False}
    violations = validator.validate_eu_ai_act(policy)
    assert any("logging_enabled" in item for item in violations)


def test_missing_rate_limit_fails_owasp() -> None:
    validator = PolicyAsCodeValidator()
    policy = _good_policy()
    policy["rules"] = [item for item in policy["rules"] if item.get("name") != "rate_limit"]
    policy["adaptive_detection"] = {"enabled": False}
    violations = validator.validate_owasp(policy)
    assert any("rate_limiting" in item for item in violations)


def test_fix_suggestions_generated() -> None:
    validator = PolicyAsCodeValidator()
    violations = [
        "EU_AI_ACT:logging_enabled: Article 12: logging must be enabled",
        "OWASP:rate_limiting: OWASP-A4: rate limiting required",
    ]
    fixes = validator.suggest_fixes(violations)
    assert any("logging:" in item for item in fixes)
    assert any("rate_limit" in item for item in fixes)


def test_eu_ai_act_score_computed() -> None:
    validator = PolicyAsCodeValidator()
    policy = _good_policy()
    policy["recording"] = {"enabled": False}
    report = validator.validate(policy)
    assert report.eu_ai_act_score < 1.0
    assert report.eu_ai_act_score >= 0.0


def test_strict_mode_fails_on_warnings() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        policy_path = Path("policy.yaml")
        policy_path.write_text(
            "rules:\n  - name: rate_limit\n    max_requests_per_minute: 60\n",
            encoding="utf-8",
        )
        result = runner.invoke(main, ["validate", "--policy", str(policy_path), "--strict"])
        assert result.exit_code == 1
        assert "warning" in result.output.lower()
