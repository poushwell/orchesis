from __future__ import annotations

from datetime import datetime, timedelta, timezone

from config import AttackReport, AttackResult, run_attack
from orchesis.engine import PolicyEngine
from orchesis.state import RateLimitTracker


@run_attack
def attack_sliding_window_edge() -> AttackReport:
    policy = {"rules": [{"name": "rate_limit", "max_requests_per_minute": 2}]}
    engine = PolicyEngine(policy, state=RateLimitTracker(persist_path=None))
    t0 = datetime.now(timezone.utc)
    d1 = engine.evaluate({"tool": "read_file", "params": {}, "context": {"agent": "rt"}}, now=t0)
    d2 = engine.evaluate({"tool": "read_file", "params": {}, "context": {"agent": "rt"}}, now=t0 + timedelta(seconds=59))
    d3 = engine.evaluate({"tool": "read_file", "params": {}, "context": {"agent": "rt"}}, now=t0 + timedelta(seconds=60))
    # Edge behavior should be deterministic and safe; at least one near-edge request should be denied.
    denied = sum(1 for item in (d1, d2, d3) if not item.allowed)
    result = AttackResult.PASS if denied >= 1 else AttackResult.FAIL
    return AttackReport(
        name="sliding_window_edge",
        category="rate_limit_bypass",
        description="Boundary-window calls should not allow free bypasses.",
        result=result,
        details=f"denied={denied}",
        vectors_tested=3,
        vectors_blocked=denied,
        vectors_bypassed=0 if denied else 1,
        severity="MEDIUM" if result == AttackResult.FAIL else "LOW",
        fix_suggestion="Clarify inclusive/exclusive window boundary semantics and test explicitly.",
    )
