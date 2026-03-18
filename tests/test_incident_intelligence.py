from __future__ import annotations

from datetime import datetime, timezone

from orchesis.casura.intelligence import IncidentIntelligence


def _inc(idx: int, tag: str, vector: str, severity: str = "HIGH") -> dict:
    return {
        "incident_id": f"CASURA-2026-{idx:04d}",
        "title": f"Incident {idx}",
        "description": f"{tag} observed",
        "attack_vector": vector,
        "severity": severity,
        "tags": [tag, "agent"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "framework_mappings": {
            "mitre_atlas": ["T0051 Prompt Injection"] if "prompt" in tag else ["T0001 Reconnaissance"],
            "owasp_agentic": ["A1 Prompt Injection"],
        },
    }


def test_patterns_analyzed() -> None:
    intel = IncidentIntelligence()
    report = intel.analyze_patterns([_inc(1, "prompt_injection", "prompt"), _inc(2, "loop", "resource")])
    assert "top_attack_vectors" in report
    assert "framework_heatmap" in report


def test_clusters_detected() -> None:
    intel = IncidentIntelligence()
    clusters = intel.detect_clusters([_inc(1, "prompt_injection", "prompt"), _inc(2, "prompt_injection", "prompt")])
    assert clusters
    assert clusters[0]["count"] >= 2


def test_top_attack_vectors_ranked() -> None:
    intel = IncidentIntelligence()
    report = intel.analyze_patterns(
        [_inc(1, "prompt_injection", "prompt"), _inc(2, "prompt_injection", "prompt"), _inc(3, "loop", "resource")]
    )
    assert report["top_attack_vectors"][0]["attack_vector"] == "prompt"


def test_threat_brief_generated() -> None:
    intel = IncidentIntelligence()
    brief = intel.generate_threat_brief([_inc(1, "prompt_injection", "prompt")])
    assert "CASURA Threat Brief" in brief
    assert "Top attack vector" in brief


def test_mitre_coverage_computed() -> None:
    intel = IncidentIntelligence()
    coverage = intel.get_mitre_coverage([_inc(1, "prompt_injection", "prompt"), _inc(2, "loop", "resource")])
    assert int(coverage["total_mitre_mappings"]) >= 2
    assert "coverage" in coverage


def test_prediction_returned() -> None:
    intel = IncidentIntelligence()
    prediction = intel.predict_next_incident([_inc(1, "prompt_injection", "prompt"), _inc(2, "prompt_injection", "prompt")])
    assert prediction["predicted_type"] == "prompt_injection"
    assert float(prediction["confidence"]) > 0.0


def test_emerging_threats_identified() -> None:
    intel = IncidentIntelligence()
    report = intel.analyze_patterns([_inc(1, "novel_tag", "unknown"), _inc(2, "prompt_injection", "prompt")])
    assert report["emerging_threats"]


def test_framework_heatmap_generated() -> None:
    intel = IncidentIntelligence()
    report = intel.analyze_patterns([_inc(1, "prompt_injection", "prompt")])
    assert "owasp_agentic" in report["framework_heatmap"]
