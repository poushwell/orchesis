from __future__ import annotations

from config import AttackReport, AttackResult, run_attack
from orchesis.engine import PolicyEngine


@run_attack
def attack_missing_fields() -> AttackReport:
    requests = [{}, {"tool": "read_file"}, {"params": {}}, {"context": {"agent": "rt"}}]
    engine = PolicyEngine({"tool_access": {"mode": "allowlist", "allowed": ["read_file"]}, "rules": []})
    bypassed = 0
    blocked = 0
    for req in requests:
        decision = engine.evaluate(req)
        if decision.allowed and req.get("tool") not in {"read_file"}:
            bypassed += 1
        else:
            blocked += 1
    result = AttackResult.FAIL if bypassed else AttackResult.PASS
    return AttackReport(
        name="missing_fields",
        category="proxy_stress",
        description="Requests missing mandatory fields should be denied or safely handled.",
        result=result,
        vectors_tested=len(requests),
        vectors_blocked=blocked,
        vectors_bypassed=bypassed,
        severity="MEDIUM" if bypassed else "LOW",
        fix_suggestion="Reject malformed request objects before evaluation.",
    )
