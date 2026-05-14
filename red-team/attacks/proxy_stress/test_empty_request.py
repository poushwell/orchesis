from __future__ import annotations

from config import AttackReport, AttackResult, run_attack
from orchesis.engine import PolicyEngine


@run_attack
def attack_empty_request() -> AttackReport:
    samples = [{}, {"tool": "", "params": {}}, {"tool": None, "params": None}]
    engine = PolicyEngine({"tool_access": {"mode": "allowlist", "allowed": ["read_file"]}, "rules": []})
    blocked = 0
    bypassed = 0
    for req in samples:
        decision = engine.evaluate(req)
        if decision.allowed:
            bypassed += 1
        else:
            blocked += 1
    result = AttackResult.FAIL if bypassed else AttackResult.PASS
    return AttackReport(
        name="empty_request",
        category="proxy_stress",
        description="Empty requests should be denied and never crash evaluation.",
        result=result,
        vectors_tested=len(samples),
        vectors_blocked=blocked,
        vectors_bypassed=bypassed,
        severity="MEDIUM" if bypassed else "LOW",
        fix_suggestion="Add explicit required-field validation for tool and params.",
    )
