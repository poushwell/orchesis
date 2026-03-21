from __future__ import annotations

from orchesis.casura.api_v2 import Incident
from orchesis.models.ecosystem import (
    Alert,
    BenchmarkEntry,
    Finding,
    IncidentRecord,
    ReliabilityReport,
    SLOTarget,
    Severity,
)


def _sample_incident() -> Incident:
    return Incident(
        incident_id="casura-abc123",
        title="Prompt injection sample",
        severity=7.8,
        category="prompt_injection",
        description="Injected prompt altered model behavior",
        source="unit-test",
        timestamp="2026-03-21T00:00:00+00:00",
        tags=["prompt", "injection"],
        cve_ids=["CVE-2026-9999"],
        affected_systems=["gateway-a"],
    )


def test_finding_defaults() -> None:
    row = Finding()
    assert row.finding_id.startswith("f-")
    assert isinstance(row.timestamp, float)
    assert row.severity == "MEDIUM"


def test_incident_record_defaults() -> None:
    row = IncidentRecord()
    assert row.incident_id.startswith("inc-")
    assert row.status == "open"


def test_alert_defaults() -> None:
    row = Alert()
    assert row.alert_id.startswith("alert-")
    assert row.acknowledged is False


def test_slo_target_defaults() -> None:
    row = SLOTarget()
    assert row.target == 0.99
    assert row.window_hours == 720


def test_reliability_report_defaults() -> None:
    row = ReliabilityReport()
    assert row.error_budget_remaining == 1.0


def test_benchmark_entry_defaults() -> None:
    row = BenchmarkEntry()
    assert row.overall_score == 0.0


def test_severity_values() -> None:
    assert {item.value for item in Severity} == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def test_severity_string() -> None:
    assert Severity.HIGH == "HIGH"


def test_casura_incident_to_canonical() -> None:
    incident = _sample_incident()
    canonical = incident.to_canonical()
    assert isinstance(canonical, IncidentRecord)
    assert canonical.incident_id == incident.incident_id


def test_casura_incident_from_canonical() -> None:
    record = IncidentRecord(
        incident_id="inc-1",
        title="Test",
        severity=9.0,
        category="prompt_injection",
        description="desc",
        source="test",
        timestamp=1710000000.0,
        tags=["a"],
        cve_ids=["CVE-1"],
        affected_systems=["x"],
    )
    incident = Incident.from_canonical(record)
    assert isinstance(incident, Incident)
    assert incident.incident_id == "inc-1"


def test_roundtrip() -> None:
    original = _sample_incident()
    rebuilt = Incident.from_canonical(original.to_canonical())
    assert rebuilt.incident_id == original.incident_id
    assert rebuilt.title == original.title
    assert rebuilt.severity == original.severity
    assert rebuilt.category == original.category


def test_canonical_has_all_fields() -> None:
    incident = _sample_incident()
    canonical = incident.to_canonical()
    assert canonical.title == incident.title
    assert canonical.severity == incident.severity
    assert canonical.category == incident.category
    assert canonical.tags == incident.tags
    assert canonical.cve_ids == incident.cve_ids


def test_casura_incident_still_works() -> None:
    incident = _sample_incident()
    assert incident.title
    assert incident.severity > 0


def test_existing_tests_unbroken() -> None:
    from orchesis.casura.api_v2 import Incident as ExistingIncident

    assert ExistingIncident is Incident

from datetime import datetime

from orchesis.models import Decision


def test_decision_defaults() -> None:
    decision = Decision()
    assert decision.allowed is True
    assert decision.reasons == []


def test_decision_with_deny_reasons() -> None:
    reasons = ["sql_restriction: DROP is denied"]
    decision = Decision(allowed=False, reasons=reasons)
    assert decision.allowed is False
    assert decision.reasons == reasons


def test_timestamp_is_auto_generated_with_timezone() -> None:
    decision = Decision()
    parsed = datetime.fromisoformat(decision.timestamp)
    assert parsed.tzinfo is not None
