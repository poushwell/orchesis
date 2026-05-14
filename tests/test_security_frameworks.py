from __future__ import annotations

from pathlib import Path

from tests.cli_test_utils import CliRunner

from orchesis.cli import main
from orchesis.compliance import ComplianceEngine, FrameworkCrossReference


def _write(path: Path, content: str) -> None:
    path.write_text(content.strip() + "\n", encoding="utf-8")


def _security_policy() -> str:
    return """
version: "1.0"
policy_version: "v2"
default_trust_tier: intern
risk_profiles: true
incident_detection: true
anomaly_detection: true
integrity_checks: true
decision_explanations: true
metrics: true
compliance: true
network_scanner:
  enabled: true
  check_permissions: true
ci_gate:
  enabled: true
marketplace:
  enabled: true
ioc:
  enabled: true
  prompt_injection_patterns: true
  supply_chain_patterns: true
sync:
  force_sync: true
plugins:
  - name: pii_detector
  - name: secret_scanner
scanner:
  detect_hidden_instructions: true
  detect_unicode_tricks: true
  scan_skills_before_install: true
  remote_scan: true
  scan_mcp: true
proxy:
  scan_responses: true
  secret_scanning:
    enabled: true
    severity_threshold: high
    block_on_critical: true
  pii_scanning:
    enabled: true
    severity_threshold: medium
  response_redaction:
    enabled: true
logging:
  redaction:
    enabled: true
alerts:
  slack:
    webhook_url: "https://hooks.slack.com/services/T000/B000/abc123"
channel_policies:
  whatsapp:
    denied_tools: ["shell"]
    max_requests_per_minute: 10
    require_approval_for: ["send_email"]
session_policies:
  group:
    trust_tier: intern
    sandbox:
      execution:
        deny_shell: true
      network:
        denied_domains: ["webhook.site"]
agents:
  - id: "a1"
    name: "Agent One"
    trust_tier: assistant
tool_access:
  mode: allowlist
  allowed: ["read_file", "web_search", "send_message"]
  denied: ["shell", "exec", "eval", "subprocess"]
rules:
  - name: budget_limit
    max_cost_per_call: 1.0
    daily_budget: 20.0
  - name: rate_limit
    max_requests_per_minute: 30
  - name: file_access
    denied_paths: ["/etc"]
  - name: sql_restriction
    denied_operations: ["DROP", "DELETE"]
token_limits:
  max_tokens_per_call: 4000
"""


def test_owasp_asi_all_checks(tmp_path: Path) -> None:
    p = tmp_path / "policy.yaml"
    _write(p, _security_policy())
    report = ComplianceEngine(policy_path=str(p)).check("owasp_asi")
    assert len(report.checks) == 10


def test_owasp_asi_tool_misuse_allowlist_pass(tmp_path: Path) -> None:
    p = tmp_path / "policy.yaml"
    _write(p, _security_policy())
    report = ComplianceEngine(policy_path=str(p)).check("owasp_asi")
    check = next(item for item in report.checks if item.id == "ASI-02")
    assert check.status == "pass"


def test_owasp_asi_tool_misuse_no_config_fail(tmp_path: Path) -> None:
    p = tmp_path / "policy.yaml"
    _write(p, "rules: []")
    report = ComplianceEngine(policy_path=str(p)).check("owasp_asi")
    check = next(item for item in report.checks if item.id == "ASI-02")
    assert check.status == "fail"


def test_mitre_atlas_all_checks(tmp_path: Path) -> None:
    p = tmp_path / "policy.yaml"
    _write(p, _security_policy())
    report = ComplianceEngine(policy_path=str(p)).check("mitre_atlas")
    assert len(report.checks) == 6


def test_mitre_atlas_prompt_injection_check(tmp_path: Path) -> None:
    p = tmp_path / "policy.yaml"
    _write(p, _security_policy())
    report = ComplianceEngine(policy_path=str(p)).check("mitre_atlas")
    check = next(item for item in report.checks if item.id == "AML-T0051")
    assert check.status in {"pass", "partial"}


def test_mitre_atlas_supply_chain_check(tmp_path: Path) -> None:
    p = tmp_path / "policy.yaml"
    _write(p, _security_policy())
    report = ComplianceEngine(policy_path=str(p)).check("mitre_atlas")
    check = next(item for item in report.checks if item.id == "AML-T0052")
    assert check.status in {"pass", "partial"}


def test_cosai_all_checks(tmp_path: Path) -> None:
    p = tmp_path / "policy.yaml"
    _write(p, _security_policy())
    report = ComplianceEngine(policy_path=str(p)).check("cosai")
    assert len(report.checks) == 5


def test_cosai_governance_check(tmp_path: Path) -> None:
    p = tmp_path / "policy.yaml"
    _write(p, _security_policy())
    report = ComplianceEngine(policy_path=str(p)).check("cosai")
    check = next(item for item in report.checks if item.id == "COSAI-GOV-01")
    assert check.status in {"pass", "partial"}


def test_csa_maestro_all_checks(tmp_path: Path) -> None:
    p = tmp_path / "policy.yaml"
    _write(p, _security_policy())
    report = ComplianceEngine(policy_path=str(p)).check("csa_maestro")
    assert len(report.checks) == 7


def test_csa_maestro_7_layers(tmp_path: Path) -> None:
    p = tmp_path / "policy.yaml"
    _write(p, _security_policy())
    report = ComplianceEngine(policy_path=str(p)).check("csa_maestro")
    assert {item.id for item in report.checks} == {
        "MAESTRO-L1",
        "MAESTRO-L2",
        "MAESTRO-L3",
        "MAESTRO-L4",
        "MAESTRO-L5",
        "MAESTRO-L6",
        "MAESTRO-L7",
    }


def test_nist_ai_100_2_all_checks(tmp_path: Path) -> None:
    p = tmp_path / "policy.yaml"
    _write(p, _security_policy())
    report = ComplianceEngine(policy_path=str(p)).check("nist_ai_100_2")
    assert len(report.checks) == 4


def test_nist_ai_100_2_four_attack_types(tmp_path: Path) -> None:
    p = tmp_path / "policy.yaml"
    _write(p, _security_policy())
    report = ComplianceEngine(policy_path=str(p)).check("nist_ai_100_2")
    assert {item.id for item in report.checks} == {
        "NIST-AML-EVASION",
        "NIST-AML-POISONING",
        "NIST-AML-PRIVACY",
        "NIST-AML-MISUSE",
    }


def test_check_all_returns_9_frameworks(tmp_path: Path) -> None:
    p = tmp_path / "policy.yaml"
    _write(p, _security_policy())
    reports = ComplianceEngine(policy_path=str(p)).check_all()
    assert len(reports) == 9


def test_cross_reference_tool_access() -> None:
    cross = FrameworkCrossReference()
    refs = cross.get_coverage("tool_access_control")
    assert "owasp_asi:ASI-02" in refs
    assert "mitre_atlas:AML-T0051" in refs


def test_cross_reference_coverage_matrix() -> None:
    cross = FrameworkCrossReference()
    matrix = cross.generate_coverage_matrix()
    assert matrix["covered_checks"] > 0
    assert matrix["total_checks"] >= 9
    assert 0.0 < matrix["coverage_ratio"] <= 1.0


def test_compliance_cli_owasp_asi(tmp_path: Path) -> None:
    p = tmp_path / "policy.yaml"
    _write(p, _security_policy())
    runner = CliRunner()
    result = runner.invoke(main, ["compliance", "owasp_asi", "--policy", str(p)])
    assert result.exit_code == 0
    assert "OWASP_ASI Compliance Check" in result.output


def test_compliance_cli_all_9_frameworks(tmp_path: Path) -> None:
    p = tmp_path / "policy.yaml"
    _write(p, _security_policy())
    runner = CliRunner()
    result = runner.invoke(main, ["compliance", "all", "--policy", str(p)])
    assert result.exit_code == 0
    assert "OWASP ASI Top 10" in result.output
    assert "NIST AI 100-2" in result.output


def test_framework_scores_calculation(tmp_path: Path) -> None:
    p = tmp_path / "policy.yaml"
    _write(p, _security_policy())
    engine = ComplianceEngine(policy_path=str(p))
    report = engine.check("owasp_asi")
    assert 0.0 <= report.score <= 1.0
