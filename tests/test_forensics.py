from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from tests.cli_test_utils import CliRunner

from orchesis.api import create_api_app
from orchesis.cli import main
from orchesis.forensics import ForensicsEngine, Incident
from orchesis.integrations.forensics_emitter import ForensicsEmitter
from orchesis.telemetry import DecisionEvent


def _ts(offset_seconds: int = 0) -> str:
    base = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
    return (base + timedelta(seconds=offset_seconds)).isoformat().replace("+00:00", "Z")


def _event(
    event_id: str,
    *,
    ts_offset: int = 0,
    agent_id: str = "cursor",
    tool: str = "read_file",
    decision: str = "ALLOW",
    reasons: list[str] | None = None,
    latency_us: int = 100,
) -> dict:
    return {
        "event_id": event_id,
        "timestamp": _ts(ts_offset),
        "agent_id": agent_id,
        "tool": tool,
        "params_hash": "h",
        "cost": 0.1,
        "decision": decision,
        "reasons": reasons or [],
        "rules_checked": ["budget_limit"],
        "rules_triggered": [],
        "evaluation_order": ["budget_limit"],
        "evaluation_duration_us": latency_us,
        "policy_version": "v1",
        "state_snapshot": {"tool_counts": {}, "session_id": "s1"},
    }


def _write_events(path: Path, events: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(item) for item in events) + "\n", encoding="utf-8")


def _policy_yaml() -> str:
    return """
api:
  token: "orch_sk_test"
rules:
  - name: budget_limit
    max_cost_per_call: 1.0
    daily_budget: 10.0
  - name: file_access
    denied_paths: ["/etc", "/root"]
  - name: rate_limit
    max_requests_per_minute: 100
"""


def _auth() -> dict[str, str]:
    return {"Authorization": "Bearer orch_sk_test"}


async def _client(app):
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


def test_detect_deny_incident(tmp_path: Path) -> None:
    log = tmp_path / "decisions.jsonl"
    _write_events(log, [_event("1", decision="DENY", reasons=["bypass: unicode-encoded payload"])])
    incidents = ForensicsEngine(decisions_path=str(log)).detect_incidents()
    assert any(item.type == "bypass" and item.severity == "critical" for item in incidents)


def test_detect_brute_force(tmp_path: Path) -> None:
    log = tmp_path / "decisions.jsonl"
    events = [
        _event(f"{i}", ts_offset=i, decision="DENY", reasons=["file_access: path is denied"])
        for i in range(6)
    ]
    _write_events(log, events)
    incidents = ForensicsEngine(decisions_path=str(log)).detect_incidents()
    assert any(item.title.lower().startswith("brute force") for item in incidents)


def test_detect_privilege_escalation(tmp_path: Path) -> None:
    log = tmp_path / "decisions.jsonl"
    _write_events(
        log,
        [
            _event(
                "1",
                decision="DENY",
                tool="run_sql",
                reasons=["identity: agent 'intern-bot' lacks capability for tool 'run_sql'"],
            )
        ],
    )
    incidents = ForensicsEngine(decisions_path=str(log)).detect_incidents()
    assert any(item.type == "identity_violation" for item in incidents)


def test_detect_budget_breach(tmp_path: Path) -> None:
    log = tmp_path / "decisions.jsonl"
    _write_events(log, [_event("1", decision="DENY", reasons=["budget_limit: daily budget exceeded"])])
    incidents = ForensicsEngine(decisions_path=str(log)).detect_incidents()
    assert any(item.type == "budget_breach" and item.severity == "high" for item in incidents)


def test_detect_rate_limit_breach(tmp_path: Path) -> None:
    log = tmp_path / "decisions.jsonl"
    _write_events(log, [_event("1", decision="DENY", reasons=["rate_limit: exceeded 100 requests/min"])])
    incidents = ForensicsEngine(decisions_path=str(log)).detect_incidents()
    assert any(item.type == "rate_limit_breach" and item.severity == "medium" for item in incidents)


def test_detect_unknown_agent(tmp_path: Path) -> None:
    log = tmp_path / "decisions.jsonl"
    _write_events(log, [_event("1", agent_id="unknown-bot", decision="ALLOW")])
    incidents = ForensicsEngine(decisions_path=str(log)).detect_incidents()
    assert any(item.title.lower().startswith("unknown agent") for item in incidents)


def test_incident_severity_levels(tmp_path: Path) -> None:
    log = tmp_path / "decisions.jsonl"
    events: list[dict] = [
        _event("a", decision="DENY", reasons=["bypass: marker"]),
        _event("b", decision="DENY", reasons=["budget_limit: daily budget exceeded"]),
        _event("c", decision="DENY", reasons=["rate_limit: exceeded 100 requests/min"]),
    ]
    events.extend(_event(f"base-{i}", decision="ALLOW", latency_us=100) for i in range(10))
    events.append(_event("latency-spike", decision="ALLOW", latency_us=100_000))
    _write_events(log, events)
    severities = {item.severity for item in ForensicsEngine(decisions_path=str(log)).detect_incidents()}
    assert {"critical", "high", "medium", "low"}.issubset(severities)


def test_build_report_summary(tmp_path: Path) -> None:
    log = tmp_path / "decisions.jsonl"
    _write_events(
        log,
        [
            _event("1", decision="DENY", reasons=["bypass: marker"]),
            _event("2", decision="DENY", reasons=["budget_limit: daily budget exceeded"], agent_id="cursor"),
        ],
    )
    report = ForensicsEngine(decisions_path=str(log)).build_report()
    assert report.summary["total"] >= 2
    assert "by_severity" in report.summary
    assert "by_type" in report.summary
    assert "by_agent" in report.summary


def test_agent_risk_profile(tmp_path: Path) -> None:
    log = tmp_path / "decisions.jsonl"
    _write_events(
        log,
        [
            _event("1", agent_id="cursor", decision="ALLOW"),
            _event("2", agent_id="cursor", decision="DENY", tool="write_file", reasons=["path_denied"]),
            _event("3", agent_id="cursor", decision="DENY", tool="run_sql", reasons=["sql_blocked"]),
            _event("4", agent_id="other", decision="ALLOW"),
        ],
    )
    profile = ForensicsEngine(decisions_path=str(log)).agent_risk_profile("cursor")
    assert profile["agent_id"] == "cursor"
    assert profile["total_requests"] == 3
    assert profile["denied"] == 2
    assert 0.0 <= profile["risk_score"] <= 1.0


def test_agent_risk_score_calculation(tmp_path: Path) -> None:
    log = tmp_path / "decisions.jsonl"
    events = []
    for i in range(10):
        events.append(_event(f"a{i}", agent_id="cursor", decision="ALLOW"))
    events[0]["decision"] = "DENY"
    events[0]["reasons"] = ["bypass: marker"]
    events[1]["decision"] = "DENY"
    events[1]["reasons"] = ["bypass: marker"]
    _write_events(log, events)
    profile = ForensicsEngine(decisions_path=str(log)).agent_risk_profile("cursor")
    deny_rate = 2 / 10
    incident_density = 2 / 10
    expected = round((deny_rate * 0.6) + (incident_density * 0.4), 4)
    assert profile["risk_score"] == expected


def test_attack_timeline_ordering(tmp_path: Path) -> None:
    log = tmp_path / "decisions.jsonl"
    _write_events(
        log,
        [
            _event("1", ts_offset=60),
            _event("2", ts_offset=10),
            _event("3", ts_offset=30),
        ],
    )
    timeline = ForensicsEngine(decisions_path=str(log)).attack_timeline(last_n=10)
    timestamps = [item["ts"] for item in timeline]
    assert timestamps == sorted(timestamps)


def test_export_json(tmp_path: Path) -> None:
    log = tmp_path / "decisions.jsonl"
    _write_events(log, [_event("1", decision="DENY", reasons=["bypass: marker"])])
    engine = ForensicsEngine(decisions_path=str(log))
    payload = json.loads(engine.export_json(engine.build_report()))
    assert "incidents" in payload
    assert "summary" in payload


def test_export_markdown(tmp_path: Path) -> None:
    log = tmp_path / "decisions.jsonl"
    _write_events(log, [_event("1", decision="DENY", reasons=["bypass: marker"])])
    engine = ForensicsEngine(decisions_path=str(log))
    md = engine.export_markdown(engine.build_report())
    assert md.startswith("# Incident Report:")
    assert "## Summary" in md
    assert "## Agent Risk Profiles" in md


def test_forensics_emitter_realtime(tmp_path: Path) -> None:
    incidents_path = tmp_path / "incidents.jsonl"
    emitter = ForensicsEmitter(incidents_path=str(incidents_path))
    event = DecisionEvent(**_event("evt-1", decision="DENY", reasons=["bypass: marker"]))
    emitter.emit(event)
    assert incidents_path.exists()
    lines = incidents_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert payload["type"] == "bypass"


def test_forensics_emitter_chains_alert(tmp_path: Path) -> None:
    seen: list[Incident] = []
    emitter = ForensicsEmitter(
        incidents_path=str(tmp_path / "incidents.jsonl"),
        alert_callback=lambda incident: seen.append(incident),
    )
    event = DecisionEvent(**_event("evt-2", decision="DENY", reasons=["bypass: marker"]))
    emitter.emit(event)
    assert len(seen) == 1
    assert seen[0].severity == "critical"


@pytest.mark.asyncio
async def test_incidents_api_endpoint(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    decisions_path = tmp_path / "decisions.jsonl"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    _write_events(decisions_path, [_event("1", decision="DENY", reasons=["bypass: marker"])])
    app = create_api_app(
        policy_path=str(policy_path),
        decisions_log=str(decisions_path),
        state_persist=str(tmp_path / "state.jsonl"),
        history_path=str(tmp_path / "history.jsonl"),
    )
    async with await _client(app) as client:
        response = await client.get("/api/v1/incidents", headers=_auth())
    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] >= 1
    assert payload["incidents"]


@pytest.mark.asyncio
async def test_incident_detail_endpoint(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    decisions_path = tmp_path / "decisions.jsonl"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    _write_events(decisions_path, [_event("1", decision="DENY", reasons=["bypass: marker"])])
    app = create_api_app(
        policy_path=str(policy_path),
        decisions_log=str(decisions_path),
        state_persist=str(tmp_path / "state.jsonl"),
        history_path=str(tmp_path / "history.jsonl"),
    )
    async with await _client(app) as client:
        listed = await client.get("/api/v1/incidents", headers=_auth())
        incident_id = listed.json()["incidents"][0]["id"]
        detail = await client.get(f"/api/v1/incidents/{incident_id}", headers=_auth())
    assert detail.status_code == 200
    assert detail.json()["id"] == incident_id


@pytest.mark.asyncio
async def test_risk_api_endpoint(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    decisions_path = tmp_path / "decisions.jsonl"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    _write_events(
        decisions_path,
        [
            _event("1", agent_id="cursor", decision="ALLOW"),
            _event("2", agent_id="cursor", decision="DENY", reasons=["path_denied"]),
        ],
    )
    app = create_api_app(
        policy_path=str(policy_path),
        decisions_log=str(decisions_path),
        state_persist=str(tmp_path / "state.jsonl"),
        history_path=str(tmp_path / "history.jsonl"),
    )
    async with await _client(app) as client:
        res = await client.get("/api/v1/agents/cursor/risk", headers=_auth())
    assert res.status_code == 200
    assert res.json()["agent_id"] == "cursor"


def test_cli_incidents_list() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        _write_events(Path("decisions.jsonl"), [_event("1", decision="DENY", reasons=["bypass: marker"])])
        result = runner.invoke(main, ["incidents"])
    assert result.exit_code == 0
    assert "Incidents:" in result.output
    assert "Total:" in result.output


def test_cli_incidents_report() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        _write_events(Path("decisions.jsonl"), [_event("1", decision="DENY", reasons=["bypass: marker"])])
        result = runner.invoke(main, ["incidents", "report", "--format", "md"])
    assert result.exit_code == 0
    assert "# Incident Report:" in result.output
