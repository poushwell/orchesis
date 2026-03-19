from __future__ import annotations

import json
from pathlib import Path

from tests.cli_test_utils import CliRunner

from orchesis.audit_export import AuditTrailExporter
from orchesis.cli import main


def _write_decisions(path: Path) -> None:
    rows = [
        {
            "event_id": "evt-1",
            "timestamp": "2026-03-01T10:00:00+00:00",
            "agent_id": "research_01",
            "tool": "shell.exec",
            "decision": "DENY",
            "cost": 0.1,
            "reasons": ["policy:block"],
            "policy_version": "v1",
            "state_snapshot": {"session_id": "sess-a"},
        },
        {
            "event_id": "evt-2",
            "timestamp": "2026-03-05T12:00:00+00:00",
            "agent_id": "research_02",
            "tool": "chat",
            "decision": "ALLOW",
            "cost": 0.2,
            "reasons": [],
            "policy_version": "v1",
            "state_snapshot": {"session_id": "sess-b"},
        },
        {
            "event_id": "evt-3",
            "timestamp": "2026-03-10T09:30:00+00:00",
            "agent_id": "research_01",
            "tool": "web_fetch",
            "decision": "DENY",
            "cost": 0.3,
            "reasons": ["policy:ssrf"],
            "policy_version": "v1",
            "state_snapshot": {"session_id": "sess-c"},
        },
    ]
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")


def test_export_json_creates_file(tmp_path: Path) -> None:
    decisions = tmp_path / "decisions.jsonl"
    out = tmp_path / "audit.json"
    _write_decisions(decisions)
    count = AuditTrailExporter(str(decisions)).export_json(str(out))
    assert out.exists()
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert count == 3
    assert len(payload) == 3


def test_export_csv_creates_file(tmp_path: Path) -> None:
    decisions = tmp_path / "decisions.jsonl"
    out = tmp_path / "audit.csv"
    _write_decisions(decisions)
    count = AuditTrailExporter(str(decisions)).export_csv(str(out))
    text = out.read_text(encoding="utf-8")
    assert count == 3
    assert "timestamp,agent_id,session_id,tool,decision,cost,reasons,policy_version,event_id" in text


def test_filter_by_agent_id(tmp_path: Path) -> None:
    decisions = tmp_path / "decisions.jsonl"
    _write_decisions(decisions)
    rows = AuditTrailExporter(str(decisions)).filter_by(agent_id="research_01")
    assert len(rows) == 2
    assert {row["agent_id"] for row in rows} == {"research_01"}


def test_filter_by_date_range(tmp_path: Path) -> None:
    decisions = tmp_path / "decisions.jsonl"
    _write_decisions(decisions)
    rows = AuditTrailExporter(str(decisions)).filter_by(
        date_from="2026-03-02",
        date_to="2026-03-09",
    )
    assert len(rows) == 1
    assert rows[0]["event_id"] == "evt-2"


def test_filter_by_decision(tmp_path: Path) -> None:
    decisions = tmp_path / "decisions.jsonl"
    _write_decisions(decisions)
    rows = AuditTrailExporter(str(decisions)).filter_by(decision="DENY")
    assert len(rows) == 2
    assert all(row["decision"] == "DENY" for row in rows)


def test_summary_stats_correct(tmp_path: Path) -> None:
    decisions = tmp_path / "decisions.jsonl"
    _write_decisions(decisions)
    exporter = AuditTrailExporter(str(decisions))
    summary = exporter.get_summary(exporter.filter_by())
    assert summary["total_records"] == 3
    assert summary["allow_count"] == 1
    assert summary["deny_count"] == 2
    assert summary["unique_agents"] == 2
    assert summary["unique_sessions"] == 3
    assert abs(float(summary["total_cost_usd"]) - 0.6) < 1e-9


def test_cli_export_command() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        decisions = Path("decisions.jsonl")
        _write_decisions(decisions)
        result = runner.invoke(
            main,
            [
                "export",
                "--format",
                "json",
                "--agent",
                "research_01",
                "--decision",
                "DENY",
                "--output",
                "blocked.json",
            ],
        )
        assert result.exit_code == 0
        assert Path("blocked.json").exists()
        payload = json.loads(Path("blocked.json").read_text(encoding="utf-8"))
        assert len(payload) == 2
        assert "Exported 2 records to blocked.json" in result.output
