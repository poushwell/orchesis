"""Formal runtime invariant checks for Orchesis."""

from __future__ import annotations

import random
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from orchesis.config import load_policy
from orchesis.drift import DriftDetector
from orchesis.engine import RULE_EVALUATION_ORDER, evaluate
from orchesis.identity import AgentIdentity, AgentRegistry, TrustTier
from orchesis.replay import ReplayEngine, read_events_from_jsonl
from orchesis.state import RateLimitTracker


@dataclass
class InvariantResult:
    name: str
    passed: bool
    detail: str
    checked_at: str


@dataclass
class InvariantReport:
    results: list[InvariantResult]
    all_passed: bool
    duration_seconds: float


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class InvariantChecker:
    """Verifies formal runtime invariants."""

    def __init__(self, policy_path: str, decisions_log: str = ".orchesis/decisions.jsonl"):
        self._policy_path = policy_path
        self._decisions_log = Path(decisions_log)
        self._policy = load_policy(policy_path)

    def check_all(self) -> InvariantReport:
        started = time.perf_counter()
        checks = [
            self.check_never_fail_open,
            self.check_deterministic_replay,
            self.check_state_isolation,
            self.check_no_cross_session_leak,
            self.check_fail_closed_on_error,
            self.check_evaluation_order_stable,
            self.check_identity_enforcement,
            self.check_cost_never_negative_allow,
            self.check_rate_limit_atomic,
            self.check_no_state_drift,
        ]
        results = [check() for check in checks]
        return InvariantReport(
            results=results,
            all_passed=all(item.passed for item in results),
            duration_seconds=max(0.0, time.perf_counter() - started),
        )

    def check_never_fail_open(self) -> InvariantResult:
        dangerous_requests = [
            {"tool": "read_file", "params": {"path": "/etc/passwd"}, "cost": 0.1},
            {"tool": "run_sql", "params": {"query": "DROP TABLE users"}, "cost": 0.1},
            {"tool": "api_call", "params": {}, "cost": -1.0},
        ]
        failed = 0
        for request in dangerous_requests:
            decision = evaluate(request, self._policy)
            if decision.allowed:
                failed += 1
        passed = failed == 0
        detail = "dangerous probes denied" if passed else f"{failed} dangerous probes were allowed"
        return InvariantResult("never_fail_open", passed, detail, _now_iso())

    def check_deterministic_replay(self) -> InvariantResult:
        events = read_events_from_jsonl(self._decisions_log)
        if not events:
            return InvariantResult("deterministic_replay", True, "no events to replay", _now_iso())
        rng = random.Random(42)
        sample_size = min(100, len(events))
        sampled = [events[index] for index in rng.sample(range(len(events)), sample_size)]
        replay = ReplayEngine()
        mismatches = 0
        for event in sampled:
            result = replay.replay_event(event, self._policy, strict=False)
            if not result.match:
                mismatches += 1
        passed = mismatches == 0
        detail = "sampled replay matches" if passed else f"{mismatches} replay mismatches"
        return InvariantResult("deterministic_replay", passed, detail, _now_iso())

    def check_state_isolation(self) -> InvariantResult:
        tracker = RateLimitTracker(persist_path=None)
        policy = {"rules": [{"name": "rate_limit", "max_requests_per_minute": 2}]}
        request_a = {
            "tool": "read_file",
            "params": {"path": "/data/a.txt"},
            "context": {"agent": "agent_a"},
        }
        request_b = {
            "tool": "read_file",
            "params": {"path": "/data/b.txt"},
            "context": {"agent": "agent_b"},
        }
        _ = evaluate(request_a, policy, state=tracker)
        _ = evaluate(request_a, policy, state=tracker)
        denied_a = evaluate(request_a, policy, state=tracker)
        allow_b = evaluate(request_b, policy, state=tracker)
        passed = (not denied_a.allowed) and allow_b.allowed
        detail = "per-agent rate isolation OK" if passed else "cross-agent contamination detected"
        return InvariantResult("state_isolation", passed, detail, _now_iso())

    def check_no_cross_session_leak(self) -> InvariantResult:
        tracker = RateLimitTracker(persist_path=None)
        policy = {"rules": [{"name": "rate_limit", "max_requests_per_minute": 2}]}
        s1 = {
            "tool": "read_file",
            "params": {"path": "/data/a.txt"},
            "context": {"agent": "agent", "session": "s1"},
        }
        s2 = {
            "tool": "read_file",
            "params": {"path": "/data/a.txt"},
            "context": {"agent": "agent", "session": "s2"},
        }
        _ = evaluate(s1, policy, state=tracker)
        _ = evaluate(s1, policy, state=tracker)
        deny_s1 = evaluate(s1, policy, state=tracker)
        allow_s2 = evaluate(s2, policy, state=tracker)
        passed = (not deny_s1.allowed) and allow_s2.allowed
        detail = "session isolation OK" if passed else "session leak detected"
        return InvariantResult("no_cross_session_leak", passed, detail, _now_iso())

    def check_fail_closed_on_error(self) -> InvariantResult:
        class BrokenTracker(RateLimitTracker):
            def check_and_record(self, *args, **kwargs):  # noqa: ANN002, ANN003
                raise RuntimeError("broken state")

        tracker = BrokenTracker(persist_path=None)
        policy = {"rules": [{"name": "rate_limit", "max_requests_per_minute": 1}]}
        decision = evaluate(
            {"tool": "read_file", "params": {"path": "/data/a"}}, policy, state=tracker
        )
        passed = not decision.allowed
        detail = "state error denied" if passed else "state error allowed request"
        return InvariantResult("fail_closed_on_error", passed, detail, _now_iso())

    def check_evaluation_order_stable(self) -> InvariantResult:
        policy = {
            "rules": [
                {"name": "budget_limit", "max_cost_per_call": 10.0},
                {"name": "rate_limit", "max_requests_per_minute": 100},
                {"name": "file_access", "denied_paths": ["/etc"]},
                {"name": "sql_restriction", "denied_operations": ["DROP"]},
                {
                    "name": "regex",
                    "type": "regex_match",
                    "field": "params.query",
                    "deny_patterns": ["DROP"],
                },
                {
                    "name": "ctx",
                    "type": "context_rules",
                    "rules": [{"agent": "*", "max_cost_per_call": 100.0}],
                },
                {
                    "name": "combo",
                    "type": "composite",
                    "operator": "AND",
                    "conditions": [{"rule": "budget_limit"}],
                },
            ]
        }
        request = {
            "tool": "run_sql",
            "params": {"query": "SELECT 1", "path": "/data/x.txt"},
            "cost": 0.1,
            "context": {"agent": "cursor"},
        }
        decision = evaluate(request, policy, state=RateLimitTracker(persist_path=None))
        expected = [name for name in RULE_EVALUATION_ORDER if name != "identity_check"]
        passed = decision.rules_checked == expected
        detail = "rule order stable" if passed else "rule order mismatch"
        return InvariantResult("evaluation_order_stable", passed, detail, _now_iso())

    def check_identity_enforcement(self) -> InvariantResult:
        registry = AgentRegistry(
            agents={
                "blocked": AgentIdentity(
                    agent_id="blocked", name="Blocked", trust_tier=TrustTier.BLOCKED
                ),
                "intern": AgentIdentity(
                    agent_id="intern", name="Intern", trust_tier=TrustTier.INTERN
                ),
            }
        )
        policy = {"rules": [{"name": "budget_limit", "max_cost_per_call": 10.0}]}
        blocked = evaluate(
            {
                "tool": "read_file",
                "params": {"path": "/data/x.txt"},
                "context": {"agent": "blocked"},
            },
            policy,
            registry=registry,
        )
        intern_read = evaluate(
            {
                "tool": "read_file",
                "params": {"path": "/data/x.txt"},
                "context": {"agent": "intern"},
            },
            policy,
            registry=registry,
        )
        intern_write = evaluate(
            {
                "tool": "write_file",
                "params": {"path": "/data/x.txt"},
                "context": {"agent": "intern"},
            },
            policy,
            registry=registry,
        )
        passed = (not blocked.allowed) and intern_read.allowed and (not intern_write.allowed)
        detail = "identity controls enforced" if passed else "identity control mismatch"
        return InvariantResult("identity_enforcement", passed, detail, _now_iso())

    def check_cost_never_negative_allow(self) -> InvariantResult:
        policy = {"rules": [{"name": "budget_limit", "max_cost_per_call": 1.0}]}
        decision = evaluate(
            {"tool": "read_file", "params": {"path": "/data/safe.txt"}, "cost": -1.0}, policy
        )
        passed = not decision.allowed
        detail = "negative cost denied" if passed else "negative cost allowed"
        return InvariantResult("cost_never_negative_allow", passed, detail, _now_iso())

    def check_rate_limit_atomic(self) -> InvariantResult:
        tracker = RateLimitTracker(persist_path=None)
        policy = {"rules": [{"name": "rate_limit", "max_requests_per_minute": 20}]}
        request = {
            "tool": "read_file",
            "params": {"path": "/data/a.txt"},
            "context": {"agent": "atomic"},
        }

        def _call() -> bool:
            return evaluate(request, policy, state=tracker).allowed

        with ThreadPoolExecutor(max_workers=50) as pool:
            results = list(pool.map(lambda _: _call(), range(100)))
        allowed = sum(1 for item in results if item)
        passed = allowed == 20
        detail = "atomic boundary respected" if passed else f"expected 20 allow, got {allowed}"
        return InvariantResult("rate_limit_atomic", passed, detail, _now_iso())

    def check_no_state_drift(self) -> InvariantResult:
        detector = DriftDetector()
        tracker = RateLimitTracker(persist_path=None)
        events = detector.run_all_checks(
            tracker=tracker,
            policy=self._policy,
            decisions_log=self._decisions_log,
        )
        passed = not detector.has_critical_drift
        detail = "no critical drift events" if passed else f"{len(events)} drift events detected"
        return InvariantResult("no_state_drift", passed, detail, _now_iso())
