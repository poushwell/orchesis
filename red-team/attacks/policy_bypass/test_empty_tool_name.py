from __future__ import annotations

from config import AttackReport, AttackResult, run_attack
from orchesis.engine import PolicyEngine


@run_attack
def attack_empty_tool_name() -> AttackReport:
    vectors = [
        {"tool": "", "params": {}, "context": {"agent": "rt"}},
        {"tool": " ", "params": {}, "context": {"agent": "rt"}},
        {"tool": None, "params": {}, "context": {"agent": "rt"}},
        {"params": {}, "context": {"agent": "rt"}},
    ]
    policy = {"tool_access": {"mode": "allowlist", "allowed": ["read_file"]}, "rules": []}
    engine = PolicyEngine(policy)
    blocked = 0
    bypassed = 0
    for request in vectors:
        decision = engine.evaluate(request)
        if decision.allowed:
            bypassed += 1
        else:
            blocked += 1
    result = AttackResult.FAIL if bypassed else AttackResult.PASS
    return AttackReport(
        name="empty_tool_name",
        category="policy_bypass",
        description="Empty/missing tool names should never pass policy checks.",
        result=result,
        vectors_tested=len(vectors),
        vectors_blocked=blocked,
        vectors_bypassed=bypassed,
        severity="MEDIUM" if bypassed else "LOW",
        fix_suggestion="Require non-empty normalized tool name at the start of evaluation.",
    )
