from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from orchesis import __version__
from orchesis.casura.api_v2 import BulkImporter, Incident
from orchesis.casura.stix_export import StixExporter


def _incident(**overrides) -> dict:
    row = {
        "title": "Prompt override in summarizer",
        "severity": 7.5,
        "category": "prompt_injection",
        "description": "Agent ignored safety policy after crafted prompt",
        "source": "unit-test",
        "timestamp": "2026-03-21T00:00:00Z",
        "tags": ["prompt", "policy-bypass"],
        "cve_ids": [],
        "affected_systems": ["gateway-a"],
    }
    row.update(overrides)
    return row


def test_bulk_import_single() -> None:
    importer = BulkImporter()
    result = importer.import_incidents([_incident()])
    assert result.imported_count == 1
    assert result.failed_count == 0


def test_bulk_import_batch() -> None:
    importer = BulkImporter()
    rows = [_incident(incident_id=f"casura-batch-{idx}", title=f"case-{idx}") for idx in range(50)]
    result = importer.import_incidents(rows)
    assert result.imported_count == 50
    assert result.failed_count == 0
    assert len(importer.get_all_incidents()) == 50


def test_bulk_import_validation_error_missing_title() -> None:
    importer = BulkImporter()
    result = importer.import_incidents([_incident(title="")])
    assert result.failed_count == 1
    assert any(error.field == "title" for error in result.errors)


def test_bulk_import_invalid_severity() -> None:
    importer = BulkImporter()
    result = importer.import_incidents([_incident(severity=15)])
    assert result.failed_count == 1
    assert any(error.field == "severity" for error in result.errors)


def test_bulk_import_invalid_category() -> None:
    importer = BulkImporter()
    result = importer.import_incidents([_incident(category="unknown_category")])
    assert result.failed_count == 1
    assert any(error.field == "category" for error in result.errors)


def test_bulk_import_dedup() -> None:
    importer = BulkImporter()
    rows = [_incident(incident_id="casura-fixed-1"), _incident(incident_id="casura-fixed-1", title="duplicate")]
    result = importer.import_incidents(rows)
    assert result.imported_count == 1
    assert result.deduped_count == 1


def test_bulk_import_max_batch_exceeded() -> None:
    importer = BulkImporter(max_batch_size=1000)
    rows = [_incident(incident_id=f"id-{idx}") for idx in range(1001)]
    result = importer.import_incidents(rows)
    assert result.imported_count == 0
    assert result.failed_count == 1001
    assert any(error.field == "batch" for error in result.errors)


def test_bulk_import_partial_failure() -> None:
    importer = BulkImporter()
    rows = [
        _incident(incident_id="ok-1"),
        _incident(incident_id="ok-2"),
        _incident(title=""),
        _incident(category="invalid"),
    ]
    result = importer.import_incidents(rows)
    assert result.imported_count == 2
    assert result.failed_count == 2


def test_stix_bundle_structure() -> None:
    exporter = StixExporter()
    incidents = [Incident(**_incident(incident_id="stix-1"))]
    bundle = exporter.export_bundle(incidents)
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    assert isinstance(bundle["objects"], list)


def test_stix_attack_pattern() -> None:
    exporter = StixExporter()
    incident = Incident(**_incident(incident_id="stix-2", title="Tool misuse attempt", category="tool_misuse"))
    attack = exporter._incident_to_attack_pattern(incident)
    assert attack["type"] == "attack-pattern"
    assert attack["spec_version"] == "2.1"
    assert attack["name"] == "Tool misuse attempt"


def test_stix_severity_mapping() -> None:
    exporter = StixExporter()
    incident = Incident(**_incident(incident_id="stix-3", severity=9.2))
    attack = exporter._incident_to_attack_pattern(incident)
    assert "x_aiss_severity" in attack
    assert isinstance(attack["x_aiss_severity"], float)
    assert attack["x_aiss_severity"] == 9.2


def test_stix_cve_references() -> None:
    exporter = StixExporter()
    incident = Incident(**_incident(incident_id="stix-4", cve_ids=["CVE-2026-1111"]))
    attack = exporter._incident_to_attack_pattern(incident)
    refs = attack.get("external_references", [])
    assert refs
    assert refs[0]["external_id"] == "CVE-2026-1111"
    assert "nvd.nist.gov" in refs[0]["url"]


def test_stix_export_to_file(tmp_path: Path) -> None:
    exporter = StixExporter()
    incidents = [Incident(**_incident(incident_id="stix-5"))]
    target = tmp_path / "casura_bundle.json"
    exporter.export_to_file(incidents, str(target))
    assert target.exists()
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["type"] == "bundle"


def test_stix_empty_export() -> None:
    exporter = StixExporter()
    bundle = exporter.export_bundle([])
    assert bundle["objects"] == []


def test_version_is_0_5_0() -> None:
    assert __version__ == "0.5.0"


def test_pyproject_version_matches() -> None:
    pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'version\s*=\s*"([^"]+)"', pyproject)
    assert match is not None
    assert match.group(1) == __version__
    parsed = tomllib.loads(pyproject)
    assert parsed["project"]["version"] == __version__
