from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from orchesis.cli import main
from orchesis.compliance import ComplianceEngine


def _write_policy(path: Path, content: str) -> None:
    path.write_text(content.strip() + "\n", encoding="utf-8")


def _strong_policy() -> str:
    return """
policy_version: "v1"
risk_profiles: true
incident_detection: true
anomaly_detection: true
decision_explanations: true
metrics: true
trust_tiers:
  - trusted
alerts:
  recipients: ["secops@example.com"]
sync:
  force_sync: true
authentication:
  required: true
plugins:
  - name: pii_detector
  - name: secret_scanner
rules:
  - name: budget_limit
    max_cost_per_call: 1.0
  - name: rate_limit
    max_requests_per_minute: 60
  - name: sql_restriction
    denied_operations: ["DROP", "DELETE"]
  - name: file_access
    denied_paths: ["/etc"]
  - name: context_rules
    rules:
      - agent: "agent_a"
        denied_tools: ["delete_file"]
      - agent: "agent_b"
        max_cost_per_call: 1.0
"""


def _weak_policy() -> str:
    return """
rules:
  - name: budget_limit
    max_cost_per_call: 2.0
"""


def test_hipaa_full_compliance(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    _write_policy(policy_path, _strong_policy())
    (tmp_path / "decisions.jsonl").write_text("{}", encoding="utf-8")
    (tmp_path / "incidents.jsonl").write_text("{}", encoding="utf-8")

    report = ComplianceEngine(
        policy_path=str(policy_path),
        decisions_path=str(tmp_path / "decisions.jsonl"),
        incidents_path=str(tmp_path / "incidents.jsonl"),
    ).check("hipaa")
    assert report.pass_count >= 6


def test_hipaa_partial_compliance(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    _write_policy(policy_path, _weak_policy())
    report = ComplianceEngine(policy_path=str(policy_path)).check("hipaa")
    assert report.partial_count + report.fail_count > 0


def test_soc2_check(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    _write_policy(policy_path, _strong_policy())
    report = ComplianceEngine(policy_path=str(policy_path)).check("soc2")
    assert report.framework == "soc2"
    assert len(report.checks) > 0


def test_eu_ai_act_check(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    _write_policy(policy_path, _strong_policy())
    report = ComplianceEngine(policy_path=str(policy_path)).check("eu_ai_act")
    assert report.framework == "eu_ai_act"
    assert len(report.checks) == 5


def test_nist_ai_rmf_check(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    _write_policy(policy_path, _strong_policy())
    report = ComplianceEngine(policy_path=str(policy_path)).check("nist_ai_rmf")
    assert report.framework == "nist_ai_rmf"


def test_check_all_frameworks(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    _write_policy(policy_path, _strong_policy())
    reports = ComplianceEngine(policy_path=str(policy_path)).check_all()
    assert set(reports.keys()) == {
        "hipaa",
        "soc2",
        "eu_ai_act",
        "nist_ai_rmf",
        "owasp_asi",
        "mitre_atlas",
        "cosai",
        "csa_maestro",
        "nist_ai_100_2",
    }


def test_compliance_score_calculation(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    _write_policy(policy_path, _strong_policy())
    report = ComplianceEngine(policy_path=str(policy_path)).check("hipaa")
    assert 0.0 <= report.score <= 1.0


def test_export_markdown(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    _write_policy(policy_path, _strong_policy())
    engine = ComplianceEngine(policy_path=str(policy_path))
    report = engine.check("hipaa")
    md = engine.export_markdown(report)
    assert "# Compliance Report: HIPAA" in md
    assert "| ID | Requirement | Status | Evidence |" in md


def test_export_json(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    _write_policy(policy_path, _strong_policy())
    engine = ComplianceEngine(policy_path=str(policy_path))
    report = engine.check("hipaa")
    payload = json.loads(engine.export_json(report))
    assert payload["framework"] == "hipaa"
    assert isinstance(payload["checks"], list)


def test_compliance_cli_single_framework(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    _write_policy(policy_path, _strong_policy())
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["compliance", "hipaa", "--policy", str(policy_path)],
    )
    assert result.exit_code == 0
    assert "HIPAA Compliance Check" in result.output
    assert "Score:" in result.output


def test_compliance_cli_all(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    _write_policy(policy_path, _strong_policy())
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["compliance", "all", "--policy", str(policy_path)],
    )
    assert result.exit_code == 0
    assert "Framework" in result.output and "Score" in result.output
    assert "Overall:" in result.output
