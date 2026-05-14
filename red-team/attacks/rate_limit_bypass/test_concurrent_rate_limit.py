from __future__ import annotations

import concurrent.futures
from datetime import datetime, timezone

from config import AttackReport, AttackResult, run_attack
from orchesis.engine import PolicyEngine
from orchesis.state import RateLimitTracker


@run_attack
def attack_concurrent_rate_limit() -> AttackReport:
    policy = {"rules": [{"name": "rate_limit", "max_requests_per_minute": 5}]}
    tracker = RateLimitTracker(persist_path=None)
    engine = PolicyEngine(policy, state=tracker)
    now = datetime.now(timezone.utc)

    def _call() -> bool:
        d = engine.evaluate({"tool": "read_file", "params": {"path": "/tmp/a"}, "context": {"agent": "rt"}}, now=now)
        return d.allowed

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        outcomes = list(ex.map(lambda _: _call(), range(50)))
    denied = sum(1 for ok in outcomes if not ok)
    result = AttackResult.PASS if denied > 0 else AttackResult.FAIL
    return AttackReport(
        name="concurrent_rate_limit",
        category="rate_limit_bypass",
        description="Concurrent calls should still trigger rate limits atomically.",
        result=result,
        details=f"denied={denied}",
        vectors_tested=len(outcomes),
        vectors_blocked=denied,
        vectors_bypassed=0 if denied else 1,
        severity="HIGH" if result == AttackResult.FAIL else "LOW",
        fix_suggestion="Keep lock-scoped check+record atomic in rate limiter.",
    )
