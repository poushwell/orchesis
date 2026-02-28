from __future__ import annotations

import json
from pathlib import Path

from orchesis.engine import evaluate
from orchesis.invariants import InvariantChecker, InvariantReport
from orchesis.state import RateLimitTracker
from orchesis.telemetry import JsonlEmitter


def _write_policy(path: Path) -> None:
    path.write_text(
        """
rules:
  - name: budget_limit
    max_cost_per_call: 2.0
    daily_budget: 100.0
  - name: file_access
    allowed_paths: ["/data", "/tmp"]
    denied_paths: ["/etc", "/root", "/var"]
  - name: sql_restriction
    denied_operations: ["DROP", "DELETE", "TRUNCATE", "ALTER", "GRANT"]
  - name: rate_limit
    max_requests_per_minute: 60
""".strip(),
        encoding="utf-8",
    )


def _checker(tmp_path: Path) -> InvariantChecker:
    policy_path = tmp_path / "policy.yaml"
    _write_policy(policy_path)
    decisions = tmp_path / "decisions.jsonl"
    return InvariantChecker(policy_path=str(policy_path), decisions_log=str(decisions))


def test_never_fail_open(tmp_path: Path) -> None:
    result = _checker(tmp_path).check_never_fail_open()
    assert result.passed is True


def test_deterministic_replay_invariant(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    _write_policy(policy_path)
    log_path = tmp_path / "decisions.jsonl"
    emitter = JsonlEmitter(log_path)
    policy = json.loads(json.dumps({"rules": [
        {"name": "budget_limit", "max_cost_per_call": 2.0}
    ]}))
    request = {"tool": "read_file", "params": {"path": "/data/safe.txt"}, "cost": 0.1}
    for _ in range(5):
        evaluate(request, policy, emitter=emitter, state=RateLimitTracker(persist_path=None))
    checker = InvariantChecker(policy_path=str(policy_path), decisions_log=str(log_path))
    result = checker.check_deterministic_replay()
    assert result.passed is True


def test_state_isolation_invariant(tmp_path: Path) -> None:
    result = _checker(tmp_path).check_state_isolation()
    assert result.passed is True


def test_fail_closed_invariant(tmp_path: Path) -> None:
    result = _checker(tmp_path).check_fail_closed_on_error()
    assert result.passed is True


def test_evaluation_order_invariant(tmp_path: Path) -> None:
    result = _checker(tmp_path).check_evaluation_order_stable()
    assert result.passed is True


def test_identity_enforcement_invariant(tmp_path: Path) -> None:
    result = _checker(tmp_path).check_identity_enforcement()
    assert result.passed is True


def test_rate_limit_atomic_invariant(tmp_path: Path) -> None:
    result = _checker(tmp_path).check_rate_limit_atomic()
    assert result.passed is True


def test_all_invariants_pass(tmp_path: Path) -> None:
    report = _checker(tmp_path).check_all()
    assert report.all_passed is True
    assert len(report.results) == 10


def test_invariant_report_format(tmp_path: Path) -> None:
    report = _checker(tmp_path).check_all()
    assert isinstance(report, InvariantReport)
    assert isinstance(report.results, list)
    assert isinstance(report.all_passed, bool)
    assert isinstance(report.duration_seconds, float)
