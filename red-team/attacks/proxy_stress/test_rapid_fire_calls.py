from __future__ import annotations

from config import AttackReport, AttackResult, run_attack
from orchesis.engine import PolicyEngine


@run_attack
def attack_rapid_fire_calls() -> AttackReport:
    policy = {"rules": [{"name": "rate_limit", "max_requests_per_minute": 20}]}
    engine = PolicyEngine(policy)
    allowed = 0
    denied = 0
    for _ in range(1000):
        decision = engine.evaluate({"tool": "read_file", "params": {"path": "/tmp/a"}, "context": {"agent": "rt"}})
        if decision.allowed:
            allowed += 1
        else:
            denied += 1
    if denied == 0:
        result = AttackResult.FAIL
        suggestion = "Ensure rate limiter always applies under high call volume."
    else:
        result = AttackResult.PASS
        suggestion = ""
    return AttackReport(
        name="rapid_fire_calls",
        category="proxy_stress",
        description="High-rate evaluate() loop should activate rate limiting and remain stable.",
        result=result,
        details=f"allowed={allowed}, denied={denied}",
        vectors_tested=1000,
        vectors_blocked=denied,
        vectors_bypassed=allowed if denied == 0 else 0,
        severity="HIGH" if result == AttackResult.FAIL else "LOW",
        fix_suggestion=suggestion,
    )
