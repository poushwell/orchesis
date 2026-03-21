from __future__ import annotations

from tests.cli_test_utils import CliRunner

from orchesis.cli import main
from orchesis.compliance.fce import (
    ALL_RULES,
    ComplianceStatus,
    FleetComplianceEngine,
)


def _base_state() -> dict:
    return {
        "logging_enabled": True,
        "monitoring_enabled": True,
        "security_scanning_enabled": True,
        "incident_db_enabled": True,
        "agents": [{"id": "a-1"}],
        "risk_assessment_path": "docs/risk_assessment.md",
    }


def test_art9_compliant() -> None:
    engine = FleetComplianceEngine(fleet_state=_base_state())
    assert engine._check_art9_risk_management() is None


def test_art9_missing_scanning() -> None:
    state = _base_state()
    state["security_scanning_enabled"] = False
    engine = FleetComplianceEngine(fleet_state=state)
    violation = engine._check_art9_risk_management()
    assert violation is not None
    assert violation.rule_id == "EU-ART9-001"


def test_art9_missing_incidents() -> None:
    state = _base_state()
    state["incident_db_enabled"] = False
    engine = FleetComplianceEngine(fleet_state=state)
    violation = engine._check_art9_risk_management()
    assert violation is not None
    assert "incident database" in violation.description


def test_art12_compliant() -> None:
    engine = FleetComplianceEngine(fleet_state=_base_state())
    assert engine._check_art12_record_keeping() is None


def test_art12_non_compliant() -> None:
    state = _base_state()
    state["logging_enabled"] = False
    engine = FleetComplianceEngine(fleet_state=state)
    violation = engine._check_art12_record_keeping()
    assert violation is not None
    assert "logging" in violation.description.lower()
    assert violation.remediation


def test_art72_compliant() -> None:
    engine = FleetComplianceEngine(fleet_state=_base_state())
    assert engine._check_art72_monitoring() is None


def test_art72_no_monitoring() -> None:
    state = _base_state()
    state["monitoring_enabled"] = False
    engine = FleetComplianceEngine(fleet_state=state)
    violation = engine._check_art72_monitoring()
    assert violation is not None
    assert "monitoring not enabled" in violation.description


def test_art72_no_agents() -> None:
    state = _base_state()
    state["agents"] = []
    engine = FleetComplianceEngine(fleet_state=state)
    violation = engine._check_art72_monitoring()
    assert violation is not None
    assert "no agents registered" in violation.description


def test_evaluate_fully_compliant() -> None:
    engine = FleetComplianceEngine(fleet_state=_base_state())
    report = engine.evaluate()
    assert report.status == ComplianceStatus.COMPLIANT
    assert report.passed_rules == 4


def test_evaluate_partial() -> None:
    state = _base_state()
    state["monitoring_enabled"] = False
    state["risk_assessment_path"] = None
    engine = FleetComplianceEngine(fleet_state=state)
    report = engine.evaluate()
    assert report.status == ComplianceStatus.PARTIAL
    assert report.passed_rules == 2


def test_evaluate_non_compliant() -> None:
    state = {
        "logging_enabled": False,
        "monitoring_enabled": False,
        "security_scanning_enabled": False,
        "incident_db_enabled": False,
        "agents": [],
        "risk_assessment_path": None,
    }
    engine = FleetComplianceEngine(fleet_state=state)
    report = engine.evaluate()
    assert report.status == ComplianceStatus.NON_COMPLIANT
    assert report.passed_rules == 0


def test_evaluate_report_fields() -> None:
    engine = FleetComplianceEngine(fleet_state=_base_state())
    report = engine.evaluate()
    assert report.checked_rules == 4
    assert isinstance(report.violations, list)
    assert report.timestamp > 0
    assert report.fleet_size == 1


def test_evaluate_empty_state() -> None:
    engine = FleetComplianceEngine(fleet_state={})
    report = engine.evaluate()
    assert report.status == ComplianceStatus.NON_COMPLIANT


def test_comply_help() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["comply", "--help"])
    assert result.exit_code == 0
    assert "Run EU AI Act compliance check on fleet." in result.output


def test_compliance_report_summary() -> None:
    engine = FleetComplianceEngine(fleet_state={})
    report = engine.evaluate()
    text = report.summary()
    assert isinstance(text, str)
    assert len(text.strip()) > 0


def test_all_rules_defined() -> None:
    assert len(ALL_RULES) == 4
    ids = [rule.rule_id for rule in ALL_RULES]
    assert len(ids) == len(set(ids))
