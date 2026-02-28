from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from orchesis.audit import AuditEngine, AuditQuery


def _event(
    idx: int,
    *,
    agent_id: str,
    tool: str,
    decision: str,
    timestamp: str,
    reasons: list[str] | None = None,
    session_id: str = "__default__",
    policy_version: str = "v1",
    evaluation_duration_us: int = 50,
) -> dict:
    return {
        "event_id": f"evt-{idx}",
        "timestamp": timestamp,
        "agent_id": agent_id,
        "tool": tool,
        "params_hash": f"hash-{idx}",
        "cost": 0.1,
        "decision": decision,
        "reasons": reasons or [],
        "rules_checked": ["budget_limit"],
        "rules_triggered": [],
        "evaluation_order": ["budget_limit"],
        "evaluation_duration_us": evaluation_duration_us,
        "policy_version": policy_version,
        "state_snapshot": {"session_id": session_id, "tool_counts": {}},
    }


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")


def test_load_events_from_jsonl(tmp_path: Path) -> None:
    now = datetime.now(timezone.utc).isoformat()
    log = tmp_path / "decisions.jsonl"
    _write_jsonl(
        log,
        [
            _event(1, agent_id="a", tool="read_file", decision="ALLOW", timestamp=now),
            _event(2, agent_id="b", tool="write_file", decision="DENY", timestamp=now),
        ],
    )
    engine = AuditEngine(str(log))
    assert len(engine.query(AuditQuery(limit=1000))) == 2


def test_query_filter_by_agent(tmp_path: Path) -> None:
    now = datetime.now(timezone.utc).isoformat()
    log = tmp_path / "decisions.jsonl"
    _write_jsonl(
        log,
        [
            _event(1, agent_id="bot", tool="read_file", decision="ALLOW", timestamp=now),
            _event(2, agent_id="x", tool="read_file", decision="ALLOW", timestamp=now),
            _event(3, agent_id="y", tool="read_file", decision="ALLOW", timestamp=now),
        ],
    )
    events = AuditEngine(str(log)).query(AuditQuery(agent_id="bot", limit=100))
    assert len(events) == 1
    assert all(event.agent_id == "bot" for event in events)


def test_query_filter_by_decision(tmp_path: Path) -> None:
    now = datetime.now(timezone.utc).isoformat()
    log = tmp_path / "decisions.jsonl"
    _write_jsonl(
        log,
        [
            _event(1, agent_id="a", tool="read_file", decision="ALLOW", timestamp=now),
            _event(2, agent_id="a", tool="write_file", decision="DENY", timestamp=now),
            _event(3, agent_id="a", tool="delete_file", decision="DENY", timestamp=now),
        ],
    )
    events = AuditEngine(str(log)).query(AuditQuery(decision="DENY", limit=100))
    assert len(events) == 2
    assert all(event.decision == "DENY" for event in events)


def test_query_filter_by_time(tmp_path: Path) -> None:
    now = datetime.now(timezone.utc)
    log = tmp_path / "decisions.jsonl"
    _write_jsonl(
        log,
        [
            _event(
                1,
                agent_id="a",
                tool="read_file",
                decision="ALLOW",
                timestamp=(now - timedelta(hours=2)).isoformat(),
            ),
            _event(
                2,
                agent_id="a",
                tool="read_file",
                decision="ALLOW",
                timestamp=(now - timedelta(minutes=30)).isoformat(),
            ),
        ],
    )
    events = AuditEngine(str(log)).query(AuditQuery(since_hours=1, limit=100))
    assert len(events) == 1


def test_stats_computation(tmp_path: Path) -> None:
    now = datetime.now(timezone.utc).isoformat()
    log = tmp_path / "decisions.jsonl"
    _write_jsonl(
        log,
        [
            _event(1, agent_id="a", tool="read_file", decision="ALLOW", timestamp=now, session_id="s1"),
            _event(
                2,
                agent_id="b",
                tool="delete_file",
                decision="DENY",
                timestamp=now,
                reasons=["file_access: denied"],
                session_id="s2",
                evaluation_duration_us=100,
            ),
            _event(
                3,
                agent_id="b",
                tool="delete_file",
                decision="DENY",
                timestamp=now,
                reasons=["file_access: denied"],
                session_id="s3",
                evaluation_duration_us=200,
            ),
        ],
    )
    stats = AuditEngine(str(log)).stats()
    assert stats.total_events == 3
    assert stats.allow_count == 1
    assert stats.deny_count == 2
    assert stats.unique_agents == 2
    assert stats.unique_tools == 2
    assert stats.unique_sessions == 3
    assert stats.top_denied_tools[0][0] == "delete_file"
    assert stats.top_denied_agents[0][0] == "b"
    assert stats.top_deny_reasons[0][0] == "file_access: denied"
    assert stats.avg_evaluation_us > 0
    assert stats.p95_evaluation_us >= 50


def test_stats_with_filter(tmp_path: Path) -> None:
    now = datetime.now(timezone.utc).isoformat()
    log = tmp_path / "decisions.jsonl"
    _write_jsonl(
        log,
        [
            _event(1, agent_id="a", tool="read_file", decision="ALLOW", timestamp=now),
            _event(2, agent_id="b", tool="write_file", decision="DENY", timestamp=now),
        ],
    )
    stats = AuditEngine(str(log)).stats(AuditQuery(agent_id="b", limit=100))
    assert stats.total_events == 1
    assert stats.deny_count == 1


def test_anomaly_high_deny_rate(tmp_path: Path) -> None:
    now = datetime.now(timezone.utc)
    log = tmp_path / "decisions.jsonl"
    rows = []
    for idx in range(10):
        decision = "DENY" if idx < 9 else "ALLOW"
        rows.append(
            _event(
                idx,
                agent_id="probe_bot",
                tool="delete_file",
                decision=decision,
                timestamp=(now + timedelta(seconds=idx)).isoformat(),
            )
        )
    _write_jsonl(log, rows)
    anomalies = AuditEngine(str(log)).anomalies()
    assert any(item["rule"] == "high_deny_rate" and item["agent_id"] == "probe_bot" for item in anomalies)


def test_anomaly_rate_limit_hammering(tmp_path: Path) -> None:
    now = datetime.now(timezone.utc)
    log = tmp_path / "decisions.jsonl"
    rows = [
        _event(
            idx,
            agent_id="hammer_bot",
            tool="read_file",
            decision="DENY",
            timestamp=(now + timedelta(minutes=1, seconds=idx)).isoformat(),
            reasons=["rate_limit: exceeded"],
        )
        for idx in range(6)
    ]
    _write_jsonl(log, rows)
    anomalies = AuditEngine(str(log)).anomalies()
    assert any(
        item["rule"] == "rate_limit_hammering" and item["agent_id"] == "hammer_bot"
        for item in anomalies
    )


def test_anomaly_tool_persistence(tmp_path: Path) -> None:
    now = datetime.now(timezone.utc)
    log = tmp_path / "decisions.jsonl"
    rows = [
        _event(
            idx,
            agent_id="untrusted_bot",
            tool="delete_file",
            decision="DENY",
            timestamp=(now + timedelta(seconds=idx)).isoformat(),
            reasons=["file_access: denied"],
        )
        for idx in range(25)
    ]
    _write_jsonl(log, rows)
    anomalies = AuditEngine(str(log)).anomalies()
    assert any(item["rule"] == "tool_persistence" and item["agent_id"] == "untrusted_bot" for item in anomalies)


def test_anomaly_no_false_positives(tmp_path: Path) -> None:
    now = datetime.now(timezone.utc)
    log = tmp_path / "decisions.jsonl"
    rows = [
        _event(
            idx,
            agent_id="normal_bot",
            tool="read_file",
            decision="ALLOW",
            timestamp=(now + timedelta(minutes=idx)).isoformat(),
        )
        for idx in range(12)
    ]
    _write_jsonl(log, rows)
    anomalies = AuditEngine(str(log)).anomalies()
    assert anomalies == []


def test_export_csv(tmp_path: Path) -> None:
    now = datetime.now(timezone.utc).isoformat()
    log = tmp_path / "decisions.jsonl"
    _write_jsonl(
        log,
        [_event(1, agent_id="a", tool="read_file", decision="ALLOW", timestamp=now, session_id="abc")],
    )
    engine = AuditEngine(str(log))
    events = engine.query(AuditQuery(limit=100))
    out = tmp_path / "report.csv"
    engine.export_csv(events, str(out))
    content = out.read_text(encoding="utf-8")
    assert "event_id,timestamp,agent_id,session_id,tool,decision,policy_version" in content
    assert "abc" in content


def test_corrupt_jsonl_handled(tmp_path: Path) -> None:
    now = datetime.now(timezone.utc).isoformat()
    log = tmp_path / "decisions.jsonl"
    valid = _event(1, agent_id="a", tool="read_file", decision="ALLOW", timestamp=now)
    log.write_text(
        json.dumps(valid) + "\n" + "not-json\n" + '{"broken": true}\n',
        encoding="utf-8",
    )
    events = AuditEngine(str(log)).query(AuditQuery(limit=100))
    assert len(events) == 1
