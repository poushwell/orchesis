from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tests.cli_test_utils import CliRunner

from orchesis.cli import main
from orchesis.engine import evaluate
from orchesis.replay import ReplayEngine, read_events_from_jsonl
from orchesis.state import RateLimitTracker
from orchesis.telemetry import DecisionEvent, InMemoryEmitter, JsonlEmitter


def _policy() -> dict[str, object]:
    return {
        "rules": [
            {"name": "budget_limit", "max_cost_per_call": 1.0},
            {"name": "rate_limit", "max_requests_per_minute": 100},
        ]
    }


def _request(agent: str, cost: float = 0.2) -> dict[str, object]:
    return {"tool": "api_call", "cost": cost, "params": {"x": 1}, "context": {"agent": agent}}


def test_replay_single_event_matches() -> None:
    policy = _policy()
    emitter = InMemoryEmitter()
    _ = evaluate(_request("a"), policy, state=RateLimitTracker(persist_path=None), emitter=emitter)

    result = ReplayEngine().replay_event(emitter.get_events()[0], policy)
    assert result.match is True


def test_replay_multiple_events_all_match() -> None:
    policy = _policy()
    tracker = RateLimitTracker(persist_path=None)
    emitter = InMemoryEmitter()
    for i in range(50):
        _ = evaluate(_request(f"agent_{i % 5}", cost=0.1), policy, state=tracker, emitter=emitter)

    report = ReplayEngine().replay_log(emitter.get_events(), policy)
    assert report.total == 50
    assert report.deterministic is True


def test_replay_detects_policy_drift() -> None:
    policy_a = {"rules": [{"name": "budget_limit", "max_cost_per_call": 1.0}]}
    policy_b = {"rules": [{"name": "budget_limit", "max_cost_per_call": 0.1}]}
    emitter = InMemoryEmitter()
    _ = evaluate(
        _request("a", cost=0.5),
        policy_a,
        emitter=emitter,
        state=RateLimitTracker(persist_path=None),
    )
    event = emitter.get_events()[0]

    result = ReplayEngine().replay_event(event, policy_b, strict=True)
    assert result.match is False
    assert result.drift_reasons


def test_replay_handles_params_unavailable() -> None:
    policy = {"rules": [{"name": "file_access", "denied_paths": ["/etc"]}]}
    request = {"tool": "read_file", "params": {"path": "/etc/passwd"}, "cost": 0.0}
    emitter = InMemoryEmitter()
    _ = evaluate(request, policy, state=RateLimitTracker(persist_path=None), emitter=emitter)
    event = emitter.get_events()[0]

    result = ReplayEngine().replay_event(event, policy, strict=False)
    assert result.match is True
    assert any("params_unavailable" in reason for reason in result.drift_reasons)


def test_replay_from_jsonl_file(tmp_path: Path) -> None:
    policy = _policy()
    log_path = tmp_path / "decisions.jsonl"
    emitter = JsonlEmitter(log_path)
    _ = evaluate(_request("a"), policy, state=RateLimitTracker(persist_path=None), emitter=emitter)

    report = ReplayEngine().replay_file(str(log_path), policy)
    assert report.total == 1
    assert report.matches == 1


def test_replay_with_state_reconstruction() -> None:
    policy = {"rules": [{"name": "rate_limit", "max_requests_per_minute": 100}]}
    event = DecisionEvent(
        event_id="event-1",
        timestamp="2026-01-01T00:00:00+00:00",
        agent_id="agent-a",
        tool="read_file",
        params_hash="x",
        cost=0.0,
        decision="ALLOW",
        reasons=[],
        rules_checked=["rate_limit"],
        rules_triggered=[],
        evaluation_order=["rate_limit"],
        evaluation_duration_us=100,
        policy_version="v1",
        state_snapshot={"tool_counts": {"read_file": 99}},
    )

    result = ReplayEngine().replay_event(event, policy)
    assert result.match is True
    assert result.replayed_decision.allowed is True


def test_forensic_agent_timeline(tmp_path: Path) -> None:
    now = datetime.now(timezone.utc)
    events = [
        {
            "event_id": "1",
            "timestamp": (now - timedelta(minutes=2)).isoformat(),
            "agent_id": "trusted_bot",
            "tool": "read_file",
            "params_hash": "a",
            "cost": 0.1,
            "decision": "ALLOW",
            "reasons": [],
            "rules_checked": ["budget_limit"],
            "rules_triggered": [],
            "evaluation_order": ["budget_limit"],
            "evaluation_duration_us": 1,
            "policy_version": "v",
            "state_snapshot": {"tool_counts": {}},
        },
        {
            "event_id": "2",
            "timestamp": (now - timedelta(minutes=1)).isoformat(),
            "agent_id": "untrusted_bot",
            "tool": "delete_file",
            "params_hash": "b",
            "cost": 0.1,
            "decision": "DENY",
            "reasons": ["context_rules: denied"],
            "rules_checked": ["context_rules"],
            "rules_triggered": ["context_rules"],
            "evaluation_order": ["context_rules"],
            "evaluation_duration_us": 1,
            "policy_version": "v",
            "state_snapshot": {"tool_counts": {}},
        },
        {
            "event_id": "3",
            "timestamp": now.isoformat(),
            "agent_id": "untrusted_bot",
            "tool": "run_sql",
            "params_hash": "c",
            "cost": 0.1,
            "decision": "DENY",
            "reasons": ["context_rules: denied"],
            "rules_checked": ["context_rules"],
            "rules_triggered": ["context_rules"],
            "evaluation_order": ["context_rules"],
            "evaluation_duration_us": 1,
            "policy_version": "v",
            "state_snapshot": {"tool_counts": {}},
        },
    ]

    log_path = tmp_path / "decisions.jsonl"
    log_path.write_text("\n".join(json.dumps(item) for item in events) + "\n", encoding="utf-8")
    parsed = read_events_from_jsonl(log_path)
    assert len(parsed) == 3

    runner = CliRunner()
    with runner.isolated_filesystem():
        local_log = Path("decisions.jsonl")
        local_log.write_text(log_path.read_text(encoding="utf-8"), encoding="utf-8")
        result = runner.invoke(
            main, ["forensic", "--agent", "untrusted_bot", "--log", "decisions.jsonl"]
        )

    assert result.exit_code == 0
    assert "Agent: untrusted_bot" in result.output
    assert "delete_file" in result.output
    assert "run_sql" in result.output
    assert "Agent: trusted_bot" not in result.output


def test_forensic_since_filter(tmp_path: Path) -> None:
    now = datetime.now(timezone.utc)
    old_event = {
        "event_id": "1",
        "timestamp": (now - timedelta(hours=2)).isoformat(),
        "agent_id": "untrusted_bot",
        "tool": "read_file",
        "params_hash": "a",
        "cost": 0.1,
        "decision": "ALLOW",
        "reasons": [],
        "rules_checked": ["budget_limit"],
        "rules_triggered": [],
        "evaluation_order": ["budget_limit"],
        "evaluation_duration_us": 1,
        "policy_version": "v",
        "state_snapshot": {"tool_counts": {}},
    }
    recent_event = dict(old_event)
    recent_event["event_id"] = "2"
    recent_event["timestamp"] = (now - timedelta(minutes=30)).isoformat()
    recent_event["tool"] = "run_sql"

    log_path = tmp_path / "decisions.jsonl"
    log_path.write_text(
        json.dumps(old_event) + "\n" + json.dumps(recent_event) + "\n",
        encoding="utf-8",
    )

    runner = CliRunner()
    with runner.isolated_filesystem():
        local_log = Path("decisions.jsonl")
        local_log.write_text(log_path.read_text(encoding="utf-8"), encoding="utf-8")
        result = runner.invoke(
            main,
            ["forensic", "--agent", "untrusted_bot", "--since", "1", "--log", "decisions.jsonl"],
        )

    assert result.exit_code == 0
    assert "run_sql" in result.output
    assert "read_file" not in result.output
