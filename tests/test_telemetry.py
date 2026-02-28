from __future__ import annotations

import hashlib
import json

from orchesis.engine import evaluate
from orchesis.state import GLOBAL_AGENT_ID, RateLimitTracker
from orchesis.telemetry import DecisionEvent, InMemoryEmitter, JsonlEmitter


def _policy() -> dict[str, object]:
    return {"rules": [{"name": "budget_limit", "max_cost_per_call": 1.0}]}


def _request() -> dict[str, object]:
    return {
        "tool": "read_file",
        "params": {"path": "/data/report.csv"},
        "cost": 0.1,
    }


def test_decision_event_has_all_fields() -> None:
    emitter = InMemoryEmitter()
    decision = evaluate(
        _request(), _policy(), emitter=emitter, state=RateLimitTracker(persist_path=None)
    )
    event = emitter.get_events()[0]

    assert event.event_id
    assert event.timestamp == decision.timestamp
    assert event.agent_id == GLOBAL_AGENT_ID
    assert event.tool == "read_file"
    assert event.params_hash
    assert event.cost == 0.1
    assert event.decision == "ALLOW"
    assert isinstance(event.reasons, list)
    assert isinstance(event.rules_checked, list)
    assert isinstance(event.rules_triggered, list)
    assert isinstance(event.evaluation_order, list)
    assert isinstance(event.evaluation_duration_us, int)
    assert event.policy_version
    assert isinstance(event.state_snapshot, dict)


def test_jsonl_emitter_writes_valid_json(tmp_path) -> None:
    emitter = JsonlEmitter(tmp_path / "events.jsonl")
    event = DecisionEvent(
        event_id="id-1",
        timestamp="2026-01-01T00:00:00+00:00",
        agent_id="a",
        tool="read_file",
        params_hash="abc",
        cost=0.1,
        decision="ALLOW",
        reasons=[],
        rules_checked=["budget_limit"],
        rules_triggered=[],
        evaluation_order=["budget_limit"],
        evaluation_duration_us=10,
        policy_version="v1",
        state_snapshot={"x": 1},
    )
    emitter.emit(event)

    payload = json.loads((tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert payload["event_id"] == "id-1"
    assert payload["decision"] == "ALLOW"


def test_in_memory_emitter_collects_events() -> None:
    emitter = InMemoryEmitter()
    evaluate(_request(), _policy(), emitter=emitter)
    evaluate(_request(), _policy(), emitter=emitter)
    assert len(emitter.get_events()) == 2


def test_evaluation_duration_is_measured() -> None:
    emitter = InMemoryEmitter()
    evaluate(_request(), _policy(), emitter=emitter)
    event = emitter.get_events()[0]
    assert event.evaluation_duration_us >= 0


def test_policy_version_changes_on_different_policy() -> None:
    emitter_a = InMemoryEmitter()
    emitter_b = InMemoryEmitter()
    evaluate(
        _request(),
        {"rules": [{"name": "budget_limit", "max_cost_per_call": 1.0}]},
        emitter=emitter_a,
    )
    evaluate(
        _request(),
        {"rules": [{"name": "budget_limit", "max_cost_per_call": 2.0}]},
        emitter=emitter_b,
    )
    assert emitter_a.get_events()[0].policy_version != emitter_b.get_events()[0].policy_version


def test_params_hash_is_sha256_not_raw_params() -> None:
    emitter = InMemoryEmitter()
    request = _request()
    evaluate(request, _policy(), emitter=emitter)
    event = emitter.get_events()[0]
    expected_hash = hashlib.sha256(
        json.dumps(
            request["params"], ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()

    assert event.params_hash == expected_hash
    assert "/data/report.csv" not in event.params_hash
