from __future__ import annotations

from datetime import datetime, timedelta, timezone

from config import AttackReport, AttackResult, run_attack
from orchesis.engine import PolicyEngine
from orchesis.state import RateLimitTracker


@run_attack
def attack_burst_then_wait() -> AttackReport:
    policy = {"rules": [{"name": "rate_limit", "max_requests_per_minute": 3}]}
    tracker = RateLimitTracker(persist_path=None)
    engine = PolicyEngine(policy, state=tracker)
    base = datetime.now(timezone.utc)
    seq = [
        engine.evaluate({"tool": "read_file", "params": {}, "context": {"agent": "rt"}}, now=base + timedelta(seconds=i))
        for i in (0, 1, 2, 3)
    ]
    post_wait = engine.evaluate(
        {"tool": "read_file", "params": {}, "context": {"agent": "rt"}},
        now=base + timedelta(seconds=65),
    )
    first_denied = not seq[-1].allowed
    recovered = post_wait.allowed
    result = AttackResult.PASS if first_denied and recovered else AttackResult.FAIL
    return AttackReport(
        name="burst_then_wait",
        category="rate_limit_bypass",
        description="Burst then wait should enforce then reset sliding window.",
        result=result,
        details=f"first_denied={first_denied}, recovered={recovered}",
        vectors_tested=2,
        vectors_blocked=1 if first_denied else 0,
        vectors_bypassed=0 if first_denied and recovered else 1,
        severity="HIGH" if result == AttackResult.FAIL else "LOW",
        fix_suggestion="Verify window pruning and timestamp handling in rate limiter.",
    )
