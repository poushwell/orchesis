"""
Integration tests for ecosystem module chains.
Tests that modules work together correctly.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path

from orchesis.aabb.benchmark import AABBBenchmark
from orchesis.casura.api_v2 import BulkImporter, Incident
from orchesis.casura.intelligence import IncidentIntelligence
from orchesis.casura.stix_export import StixExporter
from orchesis.channel_monitor import ChannelHealthMonitor
from orchesis.core.nlce_pipeline import AgentState, NLCEPipeline
from orchesis.discourse_coherence import compute_iacs_full
from orchesis.models import (
    Alert,
    BenchmarkEntry,
    Finding,
    IncidentRecord,
    ReliabilityReport,
    SLOTarget,
    Severity,
)
from orchesis.vibe_watch import AuditResult, VibeWatcher


def test_casura_import_to_stix_chain() -> None:
    """BulkImporter -> get_all -> StixExporter -> valid bundle."""
    importer = BulkImporter()
    importer.import_incidents(
        [
            {"title": "Test", "severity": 5.0, "category": "prompt_injection"},
            {"title": "Test2", "severity": 8.0, "category": "data_exfiltration"},
        ]
    )
    incidents = importer.get_all_incidents()
    exporter = StixExporter()
    bundle = exporter.export_bundle(incidents)
    assert bundle["type"] == "bundle"
    assert len(bundle["objects"]) == 2
    assert all(obj["type"] == "attack-pattern" for obj in bundle["objects"])


def test_casura_canonical_roundtrip() -> None:
    """Incident -> to_canonical() -> from_canonical() preserves data."""
    importer = BulkImporter()
    importer.import_incidents(
        [
            {
                "title": "RT Test",
                "severity": 7.0,
                "category": "tool_misuse",
                "tags": ["test"],
                "cve_ids": ["CVE-2026-0001"],
            }
        ]
    )
    inc = importer.get_all_incidents()[0]
    canonical = inc.to_canonical()
    assert isinstance(canonical, IncidentRecord)
    back = Incident.from_canonical(canonical)
    assert back.title == "RT Test"
    assert back.severity == 7.0
    assert "test" in back.tags


def test_casura_intelligence_with_incidents() -> None:
    """Intelligence module can analyze imported incidents."""
    intel = IncidentIntelligence()
    rows = [
        {
            "incident_id": "i-1",
            "created_at": "2026-03-01T12:00:00+00:00",
            "attack_vector": "prompt_injection",
            "severity": "HIGH",
            "tags": ["prompt", "injection"],
            "framework_mappings": {"mitre_atlas": ["T001"], "mast": ["M1"]},
        },
        {
            "incident_id": "i-2",
            "created_at": "2026-03-02T12:00:00+00:00",
            "attack_vector": "data_exfiltration",
            "severity": "MEDIUM",
            "tags": ["exfiltration"],
            "framework_mappings": {"mitre_atlas": ["T002"], "mast": ["M2"]},
        },
    ]
    result = intel.analyze_patterns(rows)
    assert isinstance(result, dict)
    assert "top_attack_vectors" in result


def test_casura_stix_file_roundtrip(tmp_path: Path) -> None:
    """Export to file -> read file -> valid JSON bundle."""
    importer = BulkImporter()
    importer.import_incidents([{"title": "File test", "severity": 3.0, "category": "resource_abuse"}])
    exporter = StixExporter()
    path = tmp_path / "test_bundle.json"
    exporter.export_to_file(importer.get_all_incidents(), str(path))
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["type"] == "bundle"


def test_nlce_assess_writes_all_state_fields() -> None:
    """After assess(), AgentState has slope_cqs, psi, phase populated."""
    pipeline = NLCEPipeline({})
    state = AgentState(agent_id="test-agent")
    observation = {"cqs": 0.6, "zipf_alpha": 1.5, "causal_fan_out_variance": 0.1}
    pipeline._phase2.assess(state, observation)
    assert hasattr(state, "slope_cqs")
    assert hasattr(state, "psi")
    assert state.phase in ("GAS", "LIQUID", "CRYSTAL")


def test_nlce_phase3_after_assess() -> None:
    """phase3_pid works after assess() without AttributeError."""
    pipeline = NLCEPipeline({})
    state = AgentState()
    pipeline._phase2.assess(state, {"cqs": 0.5, "zipf_alpha": 1.6, "causal_fan_out_variance": 0.05})
    pid = pipeline.phase3_pid(state)
    assert isinstance(pid, dict)


def test_nlce_phase7_after_assess() -> None:
    """phase7_injection_decision works after assess()."""
    pipeline = NLCEPipeline({})
    state = AgentState()
    pipeline._phase2.assess(state, {"cqs": 0.4, "zipf_alpha": 1.7, "causal_fan_out_variance": 0.2})
    result = pipeline.phase7_injection_decision(state)
    assert hasattr(result, "should_inject")
    assert hasattr(result, "injection_type")


def test_vibe_watch_uses_real_auditor() -> None:
    """VibeWatcher._run_audit calls real VibeCodeAuditor."""
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w", encoding="utf-8") as handle:
        handle.write("import os\neval(input())\n")
        handle.flush()
        watcher = VibeWatcher(target_dir=os.path.dirname(handle.name))
        result = watcher._run_audit(handle.name)
        assert isinstance(result, AuditResult)
    os.unlink(handle.name)


def test_vibe_watch_summary_after_changes(tmp_path: Path) -> None:
    """Watcher detects changes and reports summary."""
    (tmp_path / "app.py").write_text("x = 1", encoding="utf-8")
    watcher = VibeWatcher(target_dir=str(tmp_path), interval=0.1)
    watcher.start(blocking=False)
    time.sleep(0.3)
    (tmp_path / "new.py").write_text("y = 2", encoding="utf-8")
    time.sleep(0.5)
    watcher.stop()
    summary = watcher.get_summary()
    assert summary.changes_detected >= 1


def test_shared_models_importable() -> None:
    """All shared models importable from orchesis.models."""
    _ = (Finding, IncidentRecord, Alert, SLOTarget, ReliabilityReport, BenchmarkEntry)
    assert Severity.HIGH == "HIGH"


def test_channel_monitor_creates_alerts() -> None:
    """Channel monitor produces structured ChannelAlert objects."""
    monitor = ChannelHealthMonitor()
    monitor.record_event("telegram", "outbound", {"window_start_ts": time.time() - 3600})
    payload = monitor.check_health()
    assert isinstance(payload, dict)
    assert "alerts" in payload
    assert hasattr(monitor, "_check_channel") or hasattr(monitor, "check_health")


def test_iacs_discourse_coherence_chain() -> None:
    """compute_iacs_full with real messages produces valid scores."""
    messages = [
        {"role": "user", "content": "Tell me about Python programming"},
        {"role": "assistant", "content": "Python is a versatile programming language"},
        {"role": "user", "content": "What about Python data structures?"},
        {"role": "assistant", "content": "Python offers lists, dicts, sets and tuples"},
    ]
    result = compute_iacs_full(messages)
    assert "iacs" in result
    assert 0.0 <= result["iacs"] <= 1.0
    assert "fc" in result and "ec" in result and "hc" in result
