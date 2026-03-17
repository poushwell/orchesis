from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from tests.cli_test_utils import CliRunner
from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.cli import main
from orchesis.session_replay import SessionReplay


def _event(
    *,
    event_id: str,
    session_id: str,
    decision: str = "ALLOW",
    cost: float = 0.1,
    agent_id: str = "agent-a",
) -> dict:
    return {
        "event_id": event_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent_id": agent_id,
        "tool": "web_search",
        "params_hash": "abc",
        "cost": cost,
        "decision": decision,
        "reasons": [] if decision == "ALLOW" else ["budget_limit: exceeded"],
        "rules_checked": ["budget_limit"],
        "rules_triggered": [],
        "evaluation_order": ["budget_limit"],
        "evaluation_duration_us": 100,
        "policy_version": "v1",
        "state_snapshot": {"session_id": session_id, "tool_counts": {"web_search": 1}},
    }


def _write_log(path: Path, events: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(item) for item in events) + "\n", encoding="utf-8")


def test_load_session_returns_decisions(tmp_path: Path) -> None:
    log = tmp_path / "decisions.jsonl"
    _write_log(
        log,
        [
            _event(event_id="e1", session_id="s1"),
            _event(event_id="e2", session_id="s1"),
            _event(event_id="e3", session_id="s2"),
        ],
    )
    replay = SessionReplay(str(log))
    rows = replay.load_session("s1")
    assert len(rows) == 2
    assert all(item["state_snapshot"]["session_id"] == "s1" for item in rows)


def test_replay_same_policy_no_changes(tmp_path: Path) -> None:
    log = tmp_path / "decisions.jsonl"
    _write_log(log, [_event(event_id="e1", session_id="s1", decision="ALLOW", cost=0.05)])
    replay = SessionReplay(str(log))
    result = replay.replay("s1", policy={"rules": []})
    assert result.summary["total"] == 1
    assert result.summary["changed"] == 0


def test_replay_stricter_policy_more_blocks(tmp_path: Path) -> None:
    log = tmp_path / "decisions.jsonl"
    _write_log(log, [_event(event_id="e1", session_id="s1", decision="ALLOW", cost=0.5)])
    replay = SessionReplay(str(log))
    result = replay.replay(
        "s1",
        policy={"rules": [{"name": "budget_limit", "max_cost_per_call": 0.1}]},
    )
    assert result.summary["changed"] >= 1
    assert result.summary["newly_blocked"] >= 1


def test_diff_identifies_changes() -> None:
    replay = SessionReplay("unused.jsonl")
    diffs = replay.diff(
        [{"event_id": "e1", "decision": "ALLOW", "reasons": []}],
        [{"event_id": "e1", "decision": "DENY", "reasons": ["budget_limit: exceeded"]}],
    )
    assert len(diffs) == 1
    assert diffs[0]["original_decision"] == "ALLOW"
    assert diffs[0]["replayed_decision"] == "DENY"


def test_api_replay_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    decisions = tmp_path / "decisions.jsonl"
    _write_log(decisions, [_event(event_id="e1", session_id="sess-api", decision="ALLOW", cost=0.1)])
    app = create_api_app(policy_path=str(policy_path), decisions_log=str(decisions))
    client = TestClient(app)
    response = client.get("/api/v1/sessions/sess-api/replay", headers={"Authorization": "Bearer test-token"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["session_id"] == "sess-api"
    assert payload["summary"]["total"] == 1


def test_cli_replay_command(tmp_path: Path) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        log = Path("decisions.jsonl")
        _write_log(log, [_event(event_id="e1", session_id="sess-cli", decision="ALLOW", cost=0.5)])
        policy = Path("policy.yaml")
        policy.write_text(
            "rules:\n  - name: budget_limit\n    max_cost_per_call: 0.1\n",
            encoding="utf-8",
        )
        result = runner.invoke(
            main,
            ["replay", "--session", "sess-cli", "--policy", "policy.yaml", "--diff-only"],
        )
        assert result.exit_code == 0
        assert "Session replay summary" in result.output
        assert "Changed:" in result.output

