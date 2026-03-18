from __future__ import annotations

from pathlib import Path

from orchesis.cli import main
from orchesis.policy_diff import PolicyDiff
from tests.cli_test_utils import CliRunner


def _policy_a() -> dict:
    return {
        "threat_intel": {"enabled": True},
        "loop_detection": {"enabled": True},
        "rules": [{"name": "rate_limit", "max_requests_per_minute": 60}],
        "budget": {"daily_limit_usd": 10.0},
    }


def _policy_b() -> dict:
    return {
        "threat_intel": {"enabled": False},
        "loop_detection": {"enabled": True},
        "rules": [{"name": "rate_limit", "max_requests_per_minute": 20}],
        "budget": {"daily_limit_usd": 12.0},
        "adaptive_detection": {"enabled": True},
    }


def test_added_keys_detected() -> None:
    diff = PolicyDiff().compare(_policy_a(), _policy_b())
    assert "adaptive_detection.enabled" in diff["added"]


def test_removed_keys_detected() -> None:
    left = {"security": {"strict": True}, "legacy": {"enabled": True}}
    right = {"security": {"strict": True}}
    diff = PolicyDiff().compare(left, right)
    assert "legacy.enabled" in diff["removed"]


def test_changed_values_detected() -> None:
    diff = PolicyDiff().compare(_policy_a(), _policy_b())
    assert "budget.daily_limit_usd" in diff["changed"]
    assert diff["changed"]["budget.daily_limit_usd"]["old"] == 10.0
    assert diff["changed"]["budget.daily_limit_usd"]["new"] == 12.0


def test_breaking_change_detected() -> None:
    diff = PolicyDiff().compare(_policy_a(), _policy_b())
    breaking = diff["summary"]["breaking_changes"]
    assert "threat_intel.enabled" in breaking


def test_risk_level_computed() -> None:
    diff = PolicyDiff().compare(_policy_a(), _policy_b())
    assert diff["summary"]["risk_level"] in {"low", "medium", "high"}
    assert diff["summary"]["risk_level"] in {"medium", "high"}


def test_format_text_output() -> None:
    diff = PolicyDiff().compare(_policy_a(), _policy_b())
    text = PolicyDiff().format_text(diff)
    assert "Policy Diff" in text
    assert "Risk level:" in text
    assert "Changed:" in text


def test_cli_diff_command() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        a_path = Path("policy_v1.yaml")
        b_path = Path("policy_v2.yaml")
        a_path.write_text(
            "threat_intel:\n  enabled: true\nrules:\n  - name: rate_limit\n    max_requests_per_minute: 60\n",
            encoding="utf-8",
        )
        b_path.write_text(
            "threat_intel:\n  enabled: false\nrules:\n  - name: rate_limit\n    max_requests_per_minute: 20\nadaptive_detection:\n  enabled: true\n",
            encoding="utf-8",
        )

        result = runner.invoke(main, ["diff", str(a_path), str(b_path)])
        assert result.exit_code == 0
        assert "Policy Diff" in result.output
        assert "threat_intel.enabled" in result.output

        yaml_result = runner.invoke(main, ["diff", str(a_path), str(b_path), "--format", "yaml"])
        assert yaml_result.exit_code == 0
        assert "summary:" in yaml_result.output

        breaking_only = runner.invoke(main, ["diff", str(a_path), str(b_path), "--breaking-only"])
        assert breaking_only.exit_code == 0
        assert "threat_intel.enabled" in breaking_only.output
