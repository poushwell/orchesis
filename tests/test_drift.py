from __future__ import annotations

import json
from pathlib import Path

from orchesis.drift import DriftDetector
from orchesis.engine import evaluate
from orchesis.invariants import InvariantChecker
from orchesis.state import RateLimitTracker
from orchesis.telemetry import JsonlEmitter


def test_counter_integrity_correct() -> None:
    tracker = RateLimitTracker(persist_path=None)
    for _ in range(5):
        tracker.record("read_file", agent_id="agent-a")
    detector = DriftDetector()
    assert (
        detector.check_counter_integrity(tracker, "agent-a", "read_file", expected_count=5) is None
    )


def test_counter_integrity_mismatch() -> None:
    tracker = RateLimitTracker(persist_path=None)
    for _ in range(7):
        tracker.record("read_file", agent_id="agent-a")
    detector = DriftDetector()
    event = detector.check_counter_integrity(tracker, "agent-a", "read_file", expected_count=5)
    assert event is not None
    assert event.drift_type == "counter_mismatch"


def test_budget_integrity_correct() -> None:
    tracker = RateLimitTracker(persist_path=None)
    for _ in range(10):
        tracker.record_spend("agent-a", 1.0)
    detector = DriftDetector()
    assert detector.check_budget_integrity(tracker, "agent-a", expected_spent=10.0) is None


def test_budget_integrity_mismatch() -> None:
    tracker = RateLimitTracker(persist_path=None)
    for _ in range(5):
        tracker.record_spend("agent-a", 2.5)
    detector = DriftDetector()
    event = detector.check_budget_integrity(tracker, "agent-a", expected_spent=10.0)
    assert event is not None
    assert event.drift_type == "budget_mismatch"


def test_latency_spike_detection() -> None:
    detector = DriftDetector()
    assert detector.check_latency_anomaly(50) is None
    event = detector.check_latency_anomaly(5000)
    assert event is not None
    assert event.drift_type == "latency_spike"


def test_replay_divergence_detection(tmp_path: Path) -> None:
    policy_old = {"rules": [{"name": "budget_limit", "max_cost_per_call": 1.0}]}
    policy_new = {"rules": [{"name": "budget_limit", "max_cost_per_call": 0.05}]}
    log_path = tmp_path / "decisions.jsonl"
    emitter = JsonlEmitter(log_path)
    evaluate(
        {"tool": "read_file", "params": {"path": "/data/a.txt"}, "cost": 0.1},
        policy_old,
        state=RateLimitTracker(persist_path=None),
        emitter=emitter,
    )
    payload = json.loads(log_path.read_text(encoding="utf-8").splitlines()[0])
    from orchesis.telemetry import DecisionEvent

    event = DecisionEvent(**payload)
    detector = DriftDetector()
    drift = detector.check_replay_consistency(event, policy_new)
    assert drift is not None
    assert drift.drift_type == "replay_divergence"


def test_no_critical_drift_on_clean_run(tmp_path: Path) -> None:
    detector = DriftDetector()
    tracker = RateLimitTracker(persist_path=None)
    events = detector.run_all_checks(
        tracker=tracker,
        policy={"rules": [{"name": "budget_limit", "max_cost_per_call": 1.0}]},
        decisions_log=tmp_path / "missing.jsonl",
    )
    assert events == []
    assert detector.has_critical_drift is False


def test_drift_in_invariants(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
rules:
  - name: budget_limit
    max_cost_per_call: 1.0
""".strip(),
        encoding="utf-8",
    )
    checker = InvariantChecker(
        policy_path=str(policy_path), decisions_log=str(tmp_path / "empty.jsonl")
    )
    result = checker.check_no_state_drift()
    assert result.passed is True
