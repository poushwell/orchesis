from __future__ import annotations

from config import AttackReport, AttackResult, run_attack
from orchesis.engine import PolicyEngine


@run_attack
def attack_binary_payload() -> AttackReport:
    req = {"tool": b"\xff\xfe", "params": {"blob": b"\x00\x01\x02"}, "context": {"agent": "rt"}}
    engine = PolicyEngine({"rules": []})
    try:
        decision = engine.evaluate(req)
        result = AttackResult.PASS if not decision.allowed else AttackResult.PARTIAL
        bypassed = 1 if decision.allowed else 0
    except Exception:
        result = AttackResult.PASS
        bypassed = 0
    return AttackReport(
        name="binary_payload",
        category="proxy_stress",
        description="Binary values in request fields should be safely rejected.",
        result=result,
        vectors_tested=1,
        vectors_blocked=1 if bypassed == 0 else 0,
        vectors_bypassed=bypassed,
        severity="MEDIUM" if bypassed else "LOW",
        fix_suggestion="Validate request field types and reject bytes payloads before evaluation.",
    )
