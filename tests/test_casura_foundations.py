from __future__ import annotations

from orchesis.casura.incident_db import CASURAIncidentDB


def _sample_payload() -> dict:
    return {
        "title": "Prompt Injection against tool chain",
        "description": "Agent received malicious prompt injection and attempted policy bypass.",
        "factors": {"attack_vector": 0.9, "impact": 0.8, "exploitability": 0.7},
        "tags": ["prompt_injection", "policy_bypass"],
    }


def test_incident_created_with_aiss_id(tmp_path) -> None:
    db = CASURAIncidentDB(storage_path=str(tmp_path / ".casura" / "incidents"))
    incident = db.create_incident(_sample_payload())
    assert incident["incident_id"].startswith("CASURA-")


def test_aiss_score_computed_correctly(tmp_path) -> None:
    db = CASURAIncidentDB(storage_path=str(tmp_path / ".casura" / "incidents"))
    score = db.compute_aiss_score({"attack_vector": 1.0, "impact": 1.0, "exploitability": 1.0})
    assert score == 10.0


def test_severity_level_assigned(tmp_path) -> None:
    db = CASURAIncidentDB(storage_path=str(tmp_path / ".casura" / "incidents"))
    incident = db.create_incident(
        {
            "title": "Critical exploit",
            "description": "Credential exfiltration with full compromise",
            "factors": {"attack_vector": 1.0, "impact": 1.0, "exploitability": 1.0},
            "tags": ["credential"],
        }
    )
    assert incident["severity"] == "CRITICAL"


def test_framework_mappings_populated(tmp_path) -> None:
    db = CASURAIncidentDB(storage_path=str(tmp_path / ".casura" / "incidents"))
    incident = db.create_incident(_sample_payload())
    mappings = incident["framework_mappings"]
    assert isinstance(mappings, dict)
    assert "owasp_agentic" in mappings
    assert "mitre_atlas" in mappings


def test_search_returns_results(tmp_path) -> None:
    db = CASURAIncidentDB(storage_path=str(tmp_path / ".casura" / "incidents"))
    _ = db.create_incident(_sample_payload())
    rows = db.search("prompt injection")
    assert len(rows) >= 1


def test_stats_accurate(tmp_path) -> None:
    db = CASURAIncidentDB(storage_path=str(tmp_path / ".casura" / "incidents"))
    _ = db.create_incident(_sample_payload())
    _ = db.create_incident(
        {
            "title": "Loop overrun",
            "description": "Resource loop consumed tokens rapidly",
            "factors": {"attack_vector": 0.7, "impact": 0.5, "exploitability": 0.6},
            "tags": ["loop"],
        }
    )
    stats = db.get_stats()
    assert stats["total_incidents"] == 2
    assert stats["aiss_avg"] > 0.0


def test_incident_storage_roundtrip(tmp_path) -> None:
    storage = tmp_path / ".casura" / "incidents"
    db = CASURAIncidentDB(storage_path=str(storage))
    created = db.create_incident(_sample_payload())
    db2 = CASURAIncidentDB(storage_path=str(storage))
    rows = db2.search(created["incident_id"])
    assert len(rows) == 1
    assert rows[0]["incident_id"] == created["incident_id"]


def test_aiss_version_correct(tmp_path) -> None:
    _ = tmp_path
    assert CASURAIncidentDB.AISS_VERSION == "2.0"
