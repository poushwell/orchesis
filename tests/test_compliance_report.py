from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

from orchesis.api import create_api_app
from orchesis.cli import main
from orchesis.compliance_report import ComplianceReportGenerator
from tests.cli_test_utils import CliRunner


def _sample_events() -> list[dict]:
    return [
        {
            "agent_id": "agent_x",
            "decision": "DENY",
            "tool": "shell.exec",
            "reasons": ["prompt_injection", "rate_limit", "audit"],
            "rules_checked": ["budget_limit", "file_access", "sql_restriction"],
            "rules_triggered": ["rate_limit"],
            "state_snapshot": {"session_risk": "warn", "model": "gpt-4o"},
        },
        {
            "agent_id": "agent_x",
            "decision": "ALLOW",
            "tool": "web.search",
            "reasons": ["logging", "incident_response", "human_oversight"],
            "rules_checked": ["policy_version"],
            "rules_triggered": [],
            "state_snapshot": {"traceability": "enabled"},
        },
    ]


def _policy_yaml() -> str:
    return """
api:
  token: "orch_sk_test"
rules: []
"""


def _auth() -> dict[str, str]:
    return {"Authorization": "Bearer orch_sk_test"}


async def _client(app):
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


def _write_event(decisions_log: Path, *, agent_id: str, decision: str, reasons: list[str]) -> None:
    ts = datetime.now(timezone.utc) - timedelta(seconds=5)
    row = {
        "event_id": f"evt-{agent_id}-{decision.lower()}",
        "timestamp": ts.isoformat(),
        "agent_id": agent_id,
        "tool": "shell.exec",
        "params_hash": "abc123",
        "cost": 0.2,
        "decision": decision,
        "reasons": reasons,
        "rules_checked": ["budget_limit", "rate_limit"],
        "rules_triggered": ["rate_limit"] if decision == "DENY" else [],
        "evaluation_order": [],
        "evaluation_duration_us": 120,
        "policy_version": "v1",
        "state_snapshot": {"model": "gpt-4o", "session_risk": "warn"},
        "decision_reason": None,
        "credentials_injected": [],
        "signature": None,
    }
    decisions_log.parent.mkdir(parents=True, exist_ok=True)
    with decisions_log.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row) + "\n")


def _make_app(tmp_path: Path):
    policy_path = tmp_path / "policy.yaml"
    decisions_log = tmp_path / "decisions.jsonl"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(decisions_log),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    return app, decisions_log


def test_report_has_all_frameworks() -> None:
    report = ComplianceReportGenerator().generate("agent_x", _sample_events())
    assert set(report["frameworks"].keys()) == {"mast", "owasp", "eu_ai_act", "nist"}


def test_coverage_percent_correct() -> None:
    report = ComplianceReportGenerator().generate("agent_x", _sample_events())
    mast = report["frameworks"]["mast"]
    expected = round((mast["covered"] / mast["total"]) * 100.0, 2)
    assert mast["percent"] == pytest.approx(expected)


def test_critical_gaps_identified() -> None:
    report = ComplianceReportGenerator().generate("agent_x", [{"agent_id": "agent_x", "reasons": []}])
    assert isinstance(report["critical_gaps"], list)
    assert len(report["critical_gaps"]) > 0


def test_recommendations_generated() -> None:
    recs = ComplianceReportGenerator().get_recommendations(["OWASP-A01", "EU-12"])
    assert len(recs) >= 2
    assert any("prompt-injection" in rec.lower() or "logging" in rec.lower() for rec in recs)


@pytest.mark.asyncio
async def test_api_endpoint_returns_report(tmp_path: Path) -> None:
    app, decisions_log = _make_app(tmp_path)
    _write_event(decisions_log, agent_id="agent_x", decision="DENY", reasons=["prompt_injection", "audit"])
    _write_event(decisions_log, agent_id="other", decision="ALLOW", reasons=["normal"])
    async with await _client(app) as client:
        res = await client.get("/api/v1/compliance/report/agent_x", headers=_auth())
    assert res.status_code == 200
    payload = res.json()
    assert payload["agent_id"] == "agent_x"
    assert "frameworks" in payload
    assert "overall_score" in payload


def test_text_export_readable() -> None:
    report = ComplianceReportGenerator().generate("agent_x", _sample_events())
    text = ComplianceReportGenerator().export_text(report)
    assert "Compliance Coverage Report" in text
    assert "Overall Score" in text
    assert "Recommendations" in text


def test_cli_command_runs(tmp_path: Path) -> None:
    runner = CliRunner()
    decisions_path = tmp_path / "decisions.jsonl"
    out_path = tmp_path / "report.txt"
    _write_event(decisions_path, agent_id="agent_x", decision="DENY", reasons=["prompt_injection", "audit"])
    result = runner.invoke(
        main,
        [
            "compliance",
            "--agent",
            "agent_x",
            "--format",
            "text",
            "--decisions",
            str(decisions_path),
            "--output",
            str(out_path),
        ],
    )
    assert result.exit_code == 0
    assert out_path.exists()
    content = out_path.read_text(encoding="utf-8")
    assert "Agent ID: agent_x" in content
