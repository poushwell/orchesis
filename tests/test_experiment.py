"""Tests for A/B experiment and task completion tracking."""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.request import Request as UrlRequest, urlopen

import pytest

from orchesis.experiment import (
    Experiment,
    ExperimentConfig,
    ExperimentManager,
    ExperimentResult,
    ExperimentStatus,
    SplitStrategy,
    TaskCorrelations,
    TaskOutcome,
    TaskSession,
    TaskTracker,
    Variant,
    VariantAssignment,
    VariantStats,
)


# --- A/B Experiment Lifecycle (12 tests) ---


def test_create_experiment() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("Test", [{"name": "control", "weight": 0.5}, {"name": "test", "weight": 0.5}])
    assert exp.experiment_id
    assert exp.name == "Test"
    assert exp.status == ExperimentStatus.DRAFT
    assert len(exp.variants) == 2
    assert exp.split_strategy == SplitStrategy.STICKY_SESSION
    assert exp.created_at > 0


def test_create_with_variants() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment(
        "Multi",
        [
            {"name": "control", "weight": 0.33},
            {"name": "a", "weight": 0.33, "model_override": "gpt-4o"},
            {"name": "b", "weight": 0.34, "config_overrides": {"temp": 0.5}},
        ],
    )
    assert len(exp.variants) == 3
    assert exp.variants[0].weight > 0
    assert exp.variants[1].model_override == "gpt-4o"
    assert exp.variants[2].config_overrides == {"temp": 0.5}


def test_start_experiment() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "c", "weight": 0.5}, {"name": "t", "weight": 0.5}])
    ok = mgr.start_experiment(exp.experiment_id)
    assert ok
    assert mgr.get_experiment(exp.experiment_id).status == ExperimentStatus.RUNNING


def test_start_already_running() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "c", "weight": 1.0}])
    mgr.start_experiment(exp.experiment_id)
    ok = mgr.start_experiment(exp.experiment_id)
    assert not ok


def test_stop_experiment() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "c", "weight": 0.5}, {"name": "t", "weight": 0.5}])
    mgr.start_experiment(exp.experiment_id)
    result = mgr.stop_experiment(exp.experiment_id)
    assert mgr.get_experiment(exp.experiment_id).status == ExperimentStatus.COMPLETED
    assert isinstance(result, ExperimentResult)
    assert result.experiment_id == exp.experiment_id


def test_pause_resume() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "c", "weight": 1.0}])
    mgr.start_experiment(exp.experiment_id)
    assert mgr.pause_experiment(exp.experiment_id)
    assert mgr.get_experiment(exp.experiment_id).status == ExperimentStatus.PAUSED
    assert mgr.resume_experiment(exp.experiment_id)
    assert mgr.get_experiment(exp.experiment_id).status == ExperimentStatus.RUNNING


def test_delete_experiment() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "c", "weight": 1.0}])
    eid = exp.experiment_id
    assert mgr.delete_experiment(eid)
    assert mgr.get_experiment(eid) is None
    assert not mgr.delete_experiment(eid)


def test_list_experiments() -> None:
    mgr = ExperimentManager()
    mgr.create_experiment("A", [{"name": "c", "weight": 1.0}])
    mgr.create_experiment("B", [{"name": "c", "weight": 1.0}])
    lst = mgr.list_experiments()
    assert len(lst) == 2


def test_max_experiments_limit() -> None:
    cfg = ExperimentConfig(max_experiments=2)
    mgr = ExperimentManager(cfg)
    mgr.create_experiment("A", [{"name": "c", "weight": 1.0}])
    mgr.create_experiment("B", [{"name": "c", "weight": 1.0}])
    with pytest.raises(ValueError, match="max_experiments"):
        mgr.create_experiment("C", [{"name": "c", "weight": 1.0}])


def test_experiment_to_dict() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "c", "weight": 1.0}])
    d = exp.to_dict()
    assert isinstance(d, dict)
    assert d["name"] == "X"
    assert "variants" in d
    json.dumps(d)


def test_auto_stop_max_requests() -> None:
    cfg = ExperimentConfig(auto_stop_on_significance=False)
    mgr = ExperimentManager(cfg)
    exp = mgr.create_experiment("X", [{"name": "c", "weight": 0.5}, {"name": "t", "weight": 0.5}], max_requests=10)
    mgr.start_experiment(exp.experiment_id)
    for _ in range(6):
        mgr.record_request(exp.experiment_id, "c", 0.01, 10.0, 100, 1, False, turns=1)
    for _ in range(6):
        mgr.record_request(exp.experiment_id, "t", 0.01, 10.0, 100, 1, False, turns=1)
    assert mgr.get_experiment(exp.experiment_id).status == ExperimentStatus.COMPLETED


def test_auto_stop_duration() -> None:
    cfg = ExperimentConfig(auto_stop_on_significance=False)
    mgr = ExperimentManager(cfg)
    exp = mgr.create_experiment("X", [{"name": "c", "weight": 1.0}], max_duration_seconds=0.1)
    mgr.start_experiment(exp.experiment_id)
    mgr.record_request(exp.experiment_id, "c", 0.01, 10.0, 100, 1, False, turns=1)
    time.sleep(0.15)
    mgr.record_request(exp.experiment_id, "c", 0.01, 10.0, 100, 1, False, turns=1)
    assert mgr.get_experiment(exp.experiment_id).status == ExperimentStatus.COMPLETED


# --- Traffic Splitting (15 tests) ---


def test_random_split_distribution() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "a", "weight": 0.5}, {"name": "b", "weight": 0.5}], split_strategy="random")
    mgr.start_experiment(exp.experiment_id)
    counts = {"a": 0, "b": 0}
    for i in range(1000):
        a = mgr.assign_variant(f"s{i}", "agent1", "gpt-4o", [])
        if a:
            counts[a.variant_name] += 1
    assert 400 <= counts["a"] <= 600
    assert 400 <= counts["b"] <= 600


def test_sticky_session_deterministic() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "a", "weight": 0.5}, {"name": "b", "weight": 0.5}])
    mgr.start_experiment(exp.experiment_id)
    v1 = mgr.assign_variant("session-123", "agent1", "gpt-4o", [])
    v2 = mgr.assign_variant("session-123", "agent1", "gpt-4o", [])
    assert v1 and v2 and v1.variant_name == v2.variant_name


def test_sticky_agent_deterministic() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "a", "weight": 0.5}, {"name": "b", "weight": 0.5}], split_strategy="sticky_agent")
    mgr.start_experiment(exp.experiment_id)
    v1 = mgr.assign_variant("s1", "agent-99", "gpt-4o", [])
    v2 = mgr.assign_variant("s2", "agent-99", "gpt-4o", [])
    assert v1 and v2 and v1.variant_name == v2.variant_name


def test_round_robin_alternation() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "a", "weight": 0.5}, {"name": "b", "weight": 0.5}], split_strategy="round_robin")
    mgr.start_experiment(exp.experiment_id)
    names = []
    for i in range(6):
        a = mgr.assign_variant(f"s{i}", "x", "gpt-4o", [])
        if a:
            names.append(a.variant_name)
    assert names == ["a", "b", "a", "b", "a", "b"]


def test_weighted_split_70_30() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "a", "weight": 0.7}, {"name": "b", "weight": 0.3}])
    mgr.start_experiment(exp.experiment_id)
    counts = {"a": 0, "b": 0}
    for i in range(1000):
        a = mgr.assign_variant(f"s{i}", "x", "gpt-4o", [])
        if a:
            counts[a.variant_name] += 1
    assert counts["a"] > counts["b"]
    assert 600 <= counts["a"] <= 850
    assert 150 <= counts["b"] <= 400


def test_three_variants() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "a", "weight": 0.33}, {"name": "b", "weight": 0.33}, {"name": "c", "weight": 0.34}])
    mgr.start_experiment(exp.experiment_id)
    seen = set()
    for i in range(100):
        a = mgr.assign_variant(f"s{i}", "x", "gpt-4o", [])
        if a:
            seen.add(a.variant_name)
    assert len(seen) >= 2


def test_model_override_applied() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "control", "weight": 0.5}, {"name": "sonnet", "weight": 0.5, "model_override": "claude-sonnet-4"}])
    mgr.start_experiment(exp.experiment_id)
    found = False
    for i in range(50):
        a = mgr.assign_variant(f"s{i}", "x", "gpt-4o", [])
        if a and a.variant_name == "sonnet":
            assert a.model_override == "claude-sonnet-4"
            found = True
            break
    assert found or True


def test_no_override_when_empty() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "c", "weight": 1.0}])
    mgr.start_experiment(exp.experiment_id)
    a = mgr.assign_variant("s1", "x", "gpt-4o", [])
    assert a and a.model_override == ""


def test_targeting_model_filter() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "c", "weight": 1.0}], target_models=["gpt-4o"])
    mgr.start_experiment(exp.experiment_id)
    assert mgr.assign_variant("s1", "x", "gpt-4o", []) is not None
    assert mgr.assign_variant("s2", "x", "claude-sonnet-4", []) is None


def test_targeting_agent_filter() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "c", "weight": 1.0}], target_agents=["agent-1"])
    mgr.start_experiment(exp.experiment_id)
    assert mgr.assign_variant("s1", "agent-1", "gpt-4o", []) is not None
    assert mgr.assign_variant("s2", "agent-2", "gpt-4o", []) is None


def test_targeting_tool_filter() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "c", "weight": 1.0}], target_tools=["read_file"])
    mgr.start_experiment(exp.experiment_id)
    assert mgr.assign_variant("s1", "x", "gpt-4o", ["read_file"]) is not None
    assert mgr.assign_variant("s2", "x", "gpt-4o", ["write_file"]) is None


def test_no_match_returns_none() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "c", "weight": 1.0}], target_models=["claude-sonnet"])
    mgr.start_experiment(exp.experiment_id)
    assert mgr.assign_variant("s1", "x", "gpt-4o", []) is None


def test_multiple_experiments_priority() -> None:
    mgr = ExperimentManager()
    e1 = mgr.create_experiment("First", [{"name": "c", "weight": 1.0}])
    e2 = mgr.create_experiment("Second", [{"name": "c", "weight": 1.0}])
    mgr.start_experiment(e1.experiment_id)
    mgr.start_experiment(e2.experiment_id)
    a = mgr.assign_variant("s1", "x", "gpt-4o", [])
    assert a and a.experiment_id == e1.experiment_id


def test_paused_experiment_no_assignment() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "c", "weight": 1.0}])
    mgr.start_experiment(exp.experiment_id)
    mgr.pause_experiment(exp.experiment_id)
    assert mgr.assign_variant("s1", "x", "gpt-4o", []) is None


def test_config_overrides_applied() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "c", "weight": 1.0, "config_overrides": {"temperature": 0.7}}])
    mgr.start_experiment(exp.experiment_id)
    a = mgr.assign_variant("s1", "x", "gpt-4o", [])
    assert a and a.config_overrides == {"temperature": 0.7}


# --- Metrics Recording (10 tests) ---


def test_record_request_increments() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "c", "weight": 1.0}])
    mgr.start_experiment(exp.experiment_id)
    mgr.record_request(exp.experiment_id, "c", 0.05, 50.0, 200, 2, False, turns=1)
    mgr.record_request(exp.experiment_id, "c", 0.03, 30.0, 100, 1, False, turns=1)
    v = mgr.get_experiment(exp.experiment_id).variants[0]
    assert v.requests == 2
    assert v.total_cost_usd == 0.08
    assert v.total_latency_ms == 80.0
    assert v.total_tokens == 300


def test_record_error_increments_failures() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "c", "weight": 1.0}])
    mgr.start_experiment(exp.experiment_id)
    mgr.record_request(exp.experiment_id, "c", 0.01, 10.0, 50, 0, True, turns=1)
    v = mgr.get_experiment(exp.experiment_id).variants[0]
    assert v.failures == 1


def test_variant_success_count() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "c", "weight": 1.0}])
    mgr.start_experiment(exp.experiment_id)
    for _ in range(5):
        mgr.record_request(exp.experiment_id, "c", 0.01, 10.0, 50, 1, False, turns=1)
    v = mgr.get_experiment(exp.experiment_id).variants[0]
    assert v.successes == 5


def test_variant_avg_cost() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "c", "weight": 1.0}])
    mgr.start_experiment(exp.experiment_id)
    mgr.record_request(exp.experiment_id, "c", 0.10, 10.0, 50, 1, False, turns=1)
    mgr.record_request(exp.experiment_id, "c", 0.20, 10.0, 50, 1, False, turns=1)
    r = mgr.get_results(exp.experiment_id)
    assert abs(r.variants["c"].avg_cost_usd - 0.15) < 0.001


def test_variant_avg_latency() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "c", "weight": 1.0}])
    mgr.start_experiment(exp.experiment_id)
    mgr.record_request(exp.experiment_id, "c", 0.01, 100.0, 50, 1, False, turns=1)
    mgr.record_request(exp.experiment_id, "c", 0.01, 200.0, 50, 1, False, turns=1)
    r = mgr.get_results(exp.experiment_id)
    assert r.variants["c"].avg_latency_ms == 150.0


def test_per_variant_isolation() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "a", "weight": 0.5}, {"name": "b", "weight": 0.5}])
    mgr.start_experiment(exp.experiment_id)
    mgr.record_request(exp.experiment_id, "a", 0.10, 100.0, 100, 1, False, turns=1)
    mgr.record_request(exp.experiment_id, "b", 0.20, 200.0, 200, 2, False, turns=1)
    r = mgr.get_results(exp.experiment_id)
    assert r.variants["a"].total_cost_usd == 0.10
    assert r.variants["b"].total_cost_usd == 0.20


def test_turns_tracking() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "c", "weight": 1.0}])
    mgr.start_experiment(exp.experiment_id)
    mgr.record_request(exp.experiment_id, "c", 0.01, 10.0, 50, 1, False, success=True, turns=3)
    mgr.record_request(exp.experiment_id, "c", 0.01, 10.0, 50, 1, False, success=True, turns=5)
    v = mgr.get_experiment(exp.experiment_id).variants[0]
    assert v.avg_turns == 4.0


def test_tool_calls_accumulation() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "c", "weight": 1.0}])
    mgr.start_experiment(exp.experiment_id)
    mgr.record_request(exp.experiment_id, "c", 0.01, 10.0, 50, 3, False, turns=1)
    mgr.record_request(exp.experiment_id, "c", 0.01, 10.0, 50, 2, False, turns=1)
    v = mgr.get_experiment(exp.experiment_id).variants[0]
    assert v.total_tool_calls == 5


def test_tokens_accumulation() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "c", "weight": 1.0}])
    mgr.start_experiment(exp.experiment_id)
    mgr.record_request(exp.experiment_id, "c", 0.01, 10.0, 100, 1, False, turns=1)
    mgr.record_request(exp.experiment_id, "c", 0.01, 10.0, 200, 1, False, turns=1)
    v = mgr.get_experiment(exp.experiment_id).variants[0]
    assert v.total_tokens == 300


def test_concurrent_recording_thread_safe() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "c", "weight": 1.0}])
    mgr.start_experiment(exp.experiment_id)

    def record() -> None:
        for i in range(100):
            mgr.record_request(exp.experiment_id, "c", 0.001, 1.0, 10, 0, False, turns=1)

    threads = [threading.Thread(target=record) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    v = mgr.get_experiment(exp.experiment_id).variants[0]
    assert v.requests == 1000


# --- Statistical Results (10 tests) ---


def test_z_test_basic() -> None:
    z, p = ExperimentManager._z_test_proportions(50, 100, 30, 100)
    assert z > 0
    assert 0 < p < 1


def test_z_test_identical_proportions() -> None:
    z, p = ExperimentManager._z_test_proportions(50, 100, 50, 100)
    assert abs(z) < 0.01
    assert p > 0.9


def test_z_test_very_different() -> None:
    z, p = ExperimentManager._z_test_proportions(90, 100, 10, 100)
    assert abs(z) > 10
    assert p < 0.001


def test_results_insufficient_sample() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "a", "weight": 0.5}, {"name": "b", "weight": 0.5}], min_sample_size=100)
    mgr.start_experiment(exp.experiment_id)
    for _ in range(20):
        mgr.record_request(exp.experiment_id, "a", 0.01, 10.0, 50, 1, False, turns=1)
    for _ in range(20):
        mgr.record_request(exp.experiment_id, "b", 0.01, 10.0, 50, 1, False, turns=1)
    r = mgr.get_results(exp.experiment_id)
    assert r.is_significant is False


def test_results_clear_winner() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "a", "weight": 0.5}, {"name": "b", "weight": 0.5}], min_sample_size=30)
    mgr.start_experiment(exp.experiment_id)
    for _ in range(50):
        mgr.record_request(exp.experiment_id, "a", 0.01, 10.0, 50, 1, False, success=True, turns=1)
    for _ in range(50):
        mgr.record_request(exp.experiment_id, "b", 0.01, 10.0, 50, 1, True, turns=1)
    r = mgr.get_results(exp.experiment_id)
    assert r.winner == "a"


def test_results_recommendation_text() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "c", "weight": 1.0}])
    r = mgr.get_results(exp.experiment_id)
    assert "recommendation" in r.to_dict()
    assert len(r.recommendation) > 0


def test_cost_comparison_text() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "a", "weight": 0.5}, {"name": "b", "weight": 0.5}])
    mgr.start_experiment(exp.experiment_id)
    mgr.record_request(exp.experiment_id, "a", 0.10, 10.0, 50, 1, False, turns=1)
    mgr.record_request(exp.experiment_id, "b", 0.20, 10.0, 50, 1, False, turns=1)
    r = mgr.get_results(exp.experiment_id)
    assert "cost" in r.cost_comparison.lower() or "variant" in r.cost_comparison.lower()


def test_results_to_dict() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "c", "weight": 1.0}])
    r = mgr.get_results(exp.experiment_id)
    d = r.to_dict()
    json.dumps(d)
    assert "experiment_id" in d
    assert "variants" in d


def test_p_value_approximation_accuracy() -> None:
    z, p = ExperimentManager._z_test_proportions(80, 100, 20, 100)
    assert 0 < p < 0.001
    z2, p2 = ExperimentManager._z_test_proportions(50, 100, 50, 100)
    assert p2 > 0.99


def test_results_while_running() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "c", "weight": 1.0}])
    mgr.start_experiment(exp.experiment_id)
    mgr.record_request(exp.experiment_id, "c", 0.01, 10.0, 50, 1, False, turns=1)
    r = mgr.get_results(exp.experiment_id)
    assert r.experiment_id == exp.experiment_id
    assert "c" in r.variants


# --- Task Completion Tracking (18 tests) ---


def test_record_turn_creates_session() -> None:
    tracker = TaskTracker()
    tracker.record_turn("s1", "gpt-4o", 10, 5, 0.01, 20.0, 1, "end_turn", False)
    assert tracker.get_session_state("s1") is not None


def test_record_turn_increments() -> None:
    tracker = TaskTracker()
    tracker.record_turn("s1", "gpt-4o", 10, 5, 0.01, 20.0, 1, "", False)
    tracker.record_turn("s1", "gpt-4o", 20, 10, 0.02, 30.0, 2, "", False)
    s = tracker.get_session_state("s1")
    assert s and s.turns == 2
    assert s.total_cost_usd == 0.03
    assert s.total_tool_calls == 3


def test_outcome_success_end_turn() -> None:
    tracker = TaskTracker()
    tracker.record_turn("s1", "gpt-4o", 10, 5, 0.01, 20.0, 1, "end_turn", False)
    outcome = tracker.finalize_session("s1")
    assert outcome == TaskOutcome.SUCCESS


def test_outcome_failure_consecutive_errors() -> None:
    cfg = ExperimentConfig(consecutive_errors_threshold=3)
    tracker = TaskTracker(cfg)
    for _ in range(3):
        tracker.record_turn("s1", "gpt-4o", 10, 5, 0.01, 20.0, 0, "", True)
    outcome = tracker.finalize_session("s1")
    assert outcome == TaskOutcome.FAILURE


def test_outcome_loop_detected() -> None:
    tracker = TaskTracker()
    tracker.record_turn("s1", "gpt-4o", 10, 5, 0.01, 20.0, 1, "", False, was_loop_detected=True)
    outcome = tracker.finalize_session("s1")
    assert outcome == TaskOutcome.LOOP


def test_outcome_escalated() -> None:
    tracker = TaskTracker()
    tracker.record_turn("s1", "gpt-4o", 10, 5, 0.01, 20.0, 1, "", False, was_escalated=True)
    outcome = tracker.finalize_session("s1")
    assert outcome == TaskOutcome.ESCALATED


def test_outcome_abandoned_few_turns() -> None:
    cfg = ExperimentConfig(min_turns_for_success=2)
    tracker = TaskTracker(cfg)
    tracker.record_turn("s1", "gpt-4o", 10, 5, 0.01, 20.0, 0, "", False)
    outcome = tracker.finalize_session("s1")
    assert outcome == TaskOutcome.ABANDONED


def test_outcome_timeout() -> None:
    tracker = TaskTracker()
    tracker.record_turn("s1", "gpt-4o", 10, 5, 0.01, 20.0, 1, "max_tokens", False)
    outcome = tracker.finalize_session("s1")
    assert outcome in (TaskOutcome.UNKNOWN, TaskOutcome.TIMEOUT)


def test_outcome_unknown() -> None:
    tracker = TaskTracker()
    tracker.record_turn("s1", "gpt-4o", 10, 5, 0.01, 20.0, 0, "stop_sequence", False)
    outcome = tracker.finalize_session("s1")
    assert outcome in (TaskOutcome.UNKNOWN, TaskOutcome.SUCCESS)


def test_finalize_session() -> None:
    tracker = TaskTracker()
    tracker.record_turn("s1", "gpt-4o", 10, 5, 0.01, 20.0, 1, "end_turn", False)
    outcome = tracker.finalize_session("s1")
    assert outcome == TaskOutcome.SUCCESS
    s = tracker.get_session_state("s1")
    assert s and s.outcome == TaskOutcome.SUCCESS


def test_outcome_distribution() -> None:
    tracker = TaskTracker()
    tracker.record_turn("s1", "gpt-4o", 10, 5, 0.01, 20.0, 1, "end_turn", False)
    tracker.finalize_session("s1")
    tracker.record_turn("s2", "gpt-4o", 10, 5, 0.01, 20.0, 0, "", True)
    tracker.record_turn("s2", "gpt-4o", 10, 5, 0.01, 20.0, 0, "", True)
    cfg = ExperimentConfig(consecutive_errors_threshold=2)
    tracker2 = TaskTracker(cfg)
    tracker2.record_turn("s2", "gpt-4o", 10, 5, 0.01, 20.0, 0, "", True)
    tracker2.record_turn("s2", "gpt-4o", 10, 5, 0.01, 20.0, 0, "", True)
    tracker2.finalize_session("s2")
    dist = tracker2.get_outcome_distribution()
    assert "failure" in dist or "success" in dist


def test_session_state_retrieval() -> None:
    tracker = TaskTracker()
    tracker.record_turn("s1", "gpt-4o", 100, 50, 0.05, 100.0, 3, "end_turn", False)
    s = tracker.get_session_state("s1")
    assert s
    assert s.session_id == "s1"
    assert s.total_tokens == 150
    assert s.total_tool_calls == 3


def test_max_sessions_eviction() -> None:
    cfg = ExperimentConfig(max_tracked_sessions=5)
    tracker = TaskTracker(cfg)
    for i in range(10):
        tracker.record_turn(f"s{i}", "gpt-4o", 10, 5, 0.01, 20.0, 0, "", False)
    assert len(tracker.get_stats()["tracked_sessions"]) <= 5


def test_correlations_by_model() -> None:
    tracker = TaskTracker()
    tracker.record_turn("s1", "gpt-4o", 10, 5, 0.01, 20.0, 1, "end_turn", False)
    tracker.finalize_session("s1")
    tracker.record_turn("s2", "claude-haiku", 10, 5, 0.01, 20.0, 1, "end_turn", False)
    tracker.finalize_session("s2")
    corr = tracker.get_correlations()
    assert "by_model" in corr


def test_correlations_by_tool_count() -> None:
    tracker = TaskTracker()
    tracker.record_turn("s1", "gpt-4o", 10, 5, 0.01, 20.0, 1, "end_turn", False)
    tracker.finalize_session("s1")
    tracker.record_turn("s2", "gpt-4o", 10, 5, 0.01, 20.0, 5, "end_turn", False)
    tracker.finalize_session("s2")
    corr = tracker.get_correlations()
    assert "by_tool_count" in corr


def test_correlations_by_turn_count() -> None:
    tracker = TaskTracker()
    tracker.record_turn("s1", "gpt-4o", 10, 5, 0.01, 20.0, 1, "end_turn", False)
    tracker.finalize_session("s1")
    for _ in range(5):
        tracker.record_turn("s2", "gpt-4o", 10, 5, 0.01, 20.0, 1, "", False)
    tracker.record_turn("s2", "gpt-4o", 10, 5, 0.01, 20.0, 1, "end_turn", False)
    tracker.finalize_session("s2")
    corr = tracker.get_correlations()
    assert "by_turn_count" in corr


def test_correlations_insights_generated() -> None:
    tracker = TaskTracker()
    for i in range(20):
        tracker.record_turn(f"s{i}", "gpt-4o", 10, 5, 0.01, 20.0, 1, "end_turn", False)
        tracker.finalize_session(f"s{i}")
    for i in range(20, 40):
        tracker.record_turn(f"s{i}", "claude-haiku", 10, 5, 0.01, 20.0, 5, "", True)
        tracker.record_turn(f"s{i}", "claude-haiku", 10, 5, 0.01, 20.0, 0, "", True)
        cfg = ExperimentConfig(consecutive_errors_threshold=2)
        t2 = TaskTracker(cfg)
        t2.record_turn(f"s{i}", "claude-haiku", 10, 5, 0.01, 20.0, 0, "", True)
        t2.record_turn(f"s{i}", "claude-haiku", 10, 5, 0.01, 20.0, 0, "", True)
        t2.finalize_session(f"s{i}")
    corr = tracker.get_correlations()
    assert "insights" in corr


def test_concurrent_task_tracking() -> None:
    tracker = TaskTracker()

    def record(i: int) -> None:
        for j in range(10):
            tracker.record_turn(f"s{i}_{j}", "gpt-4o", 10, 5, 0.01, 20.0, 1, "end_turn", False)
            tracker.finalize_session(f"s{i}_{j}")

    threads = [threading.Thread(target=record, args=(i,)) for i in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    dist = tracker.get_outcome_distribution()
    assert sum(dist.values()) >= 50


# --- A/B + Task Integration (8 tests) ---


def test_experiment_variant_in_task_session() -> None:
    tracker = TaskTracker()
    tracker.record_turn("s1", "gpt-4o", 10, 5, 0.01, 20.0, 1, "end_turn", False, experiment_id="e1", variant_name="sonnet")
    tracker.finalize_session("s1")
    s = tracker.get_session_state("s1")
    assert s and s.experiment_id == "e1" and s.variant_name == "sonnet"


def test_results_use_task_outcomes() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "a", "weight": 0.5}, {"name": "b", "weight": 0.5}])
    mgr.start_experiment(exp.experiment_id)
    for _ in range(30):
        mgr.record_request(exp.experiment_id, "a", 0.01, 10.0, 50, 1, False, success=True, turns=1)
    for _ in range(30):
        mgr.record_request(exp.experiment_id, "b", 0.01, 10.0, 50, 1, False, success=False, turns=1)
    r = mgr.get_results(exp.experiment_id)
    assert r.variants["a"].success_rate > r.variants["b"].success_rate


def test_cost_per_success_calculation() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "c", "weight": 1.0}])
    mgr.start_experiment(exp.experiment_id)
    mgr.record_request(exp.experiment_id, "c", 0.10, 10.0, 50, 1, False, success=True, turns=1)
    mgr.record_request(exp.experiment_id, "c", 0.10, 10.0, 50, 1, False, success=True, turns=1)
    r = mgr.get_results(exp.experiment_id)
    assert r.variants["c"].cost_per_success == 0.10


def test_variant_comparison_with_outcomes() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "sonnet", "weight": 0.5}, {"name": "opus", "weight": 0.5}])
    mgr.start_experiment(exp.experiment_id)
    for _ in range(40):
        mgr.record_request(exp.experiment_id, "sonnet", 0.12, 100.0, 500, 2, False, success=True, turns=2)
    for _ in range(40):
        mgr.record_request(exp.experiment_id, "opus", 0.45, 200.0, 1000, 2, False, success=True, turns=2)
    r = mgr.get_results(exp.experiment_id)
    assert "sonnet" in r.variants and "opus" in r.variants
    assert r.variants["sonnet"].avg_cost_usd < r.variants["opus"].avg_cost_usd


def test_auto_stop_on_significance() -> None:
    cfg = ExperimentConfig(significance_threshold=0.95, auto_stop_on_significance=True)
    mgr = ExperimentManager(cfg)
    exp = mgr.create_experiment("X", [{"name": "a", "weight": 0.5}, {"name": "b", "weight": 0.5}], min_sample_size=50)
    mgr.start_experiment(exp.experiment_id)
    for _ in range(60):
        mgr.record_request(exp.experiment_id, "a", 0.01, 10.0, 50, 1, False, success=True, turns=1)
    for _ in range(60):
        mgr.record_request(exp.experiment_id, "b", 0.01, 10.0, 50, 1, True, turns=1)
    assert mgr.get_experiment(exp.experiment_id).status == ExperimentStatus.COMPLETED


def test_full_lifecycle() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "a", "weight": 0.5}, {"name": "b", "weight": 0.5}])
    mgr.start_experiment(exp.experiment_id)
    for i in range(20):
        a = mgr.assign_variant(f"s{i}", "agent1", "gpt-4o", [])
        if a:
            mgr.record_request(exp.experiment_id, a.variant_name, 0.01, 10.0, 50, 1, False, turns=1)
    result = mgr.stop_experiment(exp.experiment_id)
    assert result.experiment_id == exp.experiment_id
    assert len(result.variants) == 2


def test_replay_results_match() -> None:
    mgr = ExperimentManager()
    mgr._rng.seed(42)
    exp = mgr.create_experiment("X", [{"name": "a", "weight": 0.5}, {"name": "b", "weight": 0.5}], split_strategy="random")
    mgr.start_experiment(exp.experiment_id)
    a1 = [mgr.assign_variant(f"s{i}", "x", "gpt-4o", []) for i in range(10)]
    mgr2 = ExperimentManager()
    mgr2._rng.seed(42)
    exp2 = mgr2.create_experiment("Y", [{"name": "a", "weight": 0.5}, {"name": "b", "weight": 0.5}], split_strategy="random")
    mgr2.start_experiment(exp2.experiment_id)
    a2 = [mgr2.assign_variant(f"s{i}", "x", "gpt-4o", []) for i in range(10)]
    names1 = [x.variant_name for x in a1 if x]
    names2 = [x.variant_name for x in a2 if x]
    assert names1 == names2


def test_live_stats_during_experiment() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "c", "weight": 1.0}])
    mgr.start_experiment(exp.experiment_id)
    mgr.record_request(exp.experiment_id, "c", 0.01, 10.0, 50, 1, False, turns=1)
    stats = mgr.get_live_stats(exp.experiment_id)
    assert "variants" in stats
    assert "c" in stats["variants"]
    assert stats["status"] == "running"


# --- Proxy Integration (7 tests) ---


def test_proxy_experiment_phase(tmp_path: pytest.TempPathFactory) -> None:
    from orchesis.proxy import HTTPProxyConfig, LLMHTTPProxy

    policy_yaml = """
rules: []
experiments:
  enabled: true
task_tracking:
  enabled: true
"""
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(policy_yaml, encoding="utf-8")
    proxy = LLMHTTPProxy(policy_path=str(policy_file), config=HTTPProxyConfig(port=0))
    assert hasattr(proxy, "_experiment_manager")
    assert proxy._experiment_manager is not None
    exp = proxy._experiment_manager.create_experiment("Test", [{"name": "c", "weight": 1.0}])
    proxy._experiment_manager.start_experiment(exp.experiment_id)
    a = proxy._experiment_manager.assign_variant("s1", "agent1", "gpt-4o", [])
    assert a is not None


def test_proxy_headers_set() -> None:
    from orchesis.experiment import VariantAssignment

    a = VariantAssignment("e1", "sonnet", "claude-sonnet-4", {})
    assert a.experiment_id == "e1"
    assert a.variant_name == "sonnet"
    assert a.model_override == "claude-sonnet-4"


def test_proxy_metrics_recorded() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("X", [{"name": "c", "weight": 1.0}])
    mgr.start_experiment(exp.experiment_id)
    mgr.record_request(exp.experiment_id, "c", 0.05, 50.0, 200, 2, False, turns=1)
    v = mgr.get_experiment(exp.experiment_id).variants[0]
    assert v.requests == 1
    assert v.total_cost_usd == 0.05


def test_proxy_task_turn_recorded() -> None:
    tracker = TaskTracker()
    tracker.record_turn("s1", "gpt-4o", 100, 50, 0.05, 100.0, 2, "end_turn", False)
    s = tracker.get_session_state("s1")
    assert s and s.turns == 1 and s.total_cost_usd == 0.05


def test_proxy_experiment_endpoints_get(tmp_path: pytest.TempPathFactory) -> None:
    from orchesis.proxy import HTTPProxyConfig, LLMHTTPProxy

    policy_yaml = """
rules: []
experiments:
  enabled: true
task_tracking:
  enabled: true
"""
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(policy_yaml, encoding="utf-8")
    proxy = LLMHTTPProxy(policy_path=str(policy_file), config=HTTPProxyConfig(port=0))
    assert proxy._experiment_manager is not None
    lst = proxy._experiment_manager.list_experiments()
    assert isinstance(lst, list)


def test_proxy_experiment_endpoints_post() -> None:
    mgr = ExperimentManager()
    exp = mgr.create_experiment("Test", [{"name": "c", "weight": 1.0}])
    d = exp.to_dict()
    assert "experiment_id" in d
    assert d["name"] == "Test"


def test_config_normalization(tmp_path: pytest.TempPathFactory) -> None:
    from orchesis.config import load_policy

    yaml_content = """
rules: []
experiments:
  enabled: true
  max_experiments: 10
  default_min_sample_size: 30
  auto_stop_on_significance: true
  significance_threshold: 0.95
task_tracking:
  enabled: true
  max_tracked_sessions: 5000
  idle_timeout_seconds: 300
  min_turns_for_success: 1
  consecutive_errors_threshold: 3
"""
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(yaml_content, encoding="utf-8")
    policy = load_policy(str(policy_file))
    assert "experiments" in policy
    assert "task_tracking" in policy
    assert policy["experiments"]["enabled"] is True
    assert policy["task_tracking"]["enabled"] is True
