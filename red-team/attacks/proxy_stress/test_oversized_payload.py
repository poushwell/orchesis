from __future__ import annotations

from config import AttackReport, AttackResult, run_attack
from orchesis.engine import PolicyEngine


@run_attack
def attack_oversized_payload() -> AttackReport:
    payload = "A" * (10 * 1024 * 1024)
    policy = {"tool_access": {"mode": "allowlist", "allowed": ["read_file"]}, "rules": []}
    engine = PolicyEngine(policy)
    try:
        decision = engine.evaluate({"tool": "read_file", "params": {"path": payload}, "context": {"agent": "rt"}})
        if decision.allowed:
            result = AttackResult.PARTIAL
            bypassed = 1
            blocked = 0
            details = "Engine accepted oversized payload without explicit limit."
        else:
            result = AttackResult.PASS
            blocked = 1
            bypassed = 0
            details = "Oversized payload blocked by policy checks."
    except Exception as error:  # noqa: BLE001
        result = AttackResult.FAIL
        blocked = 0
        bypassed = 1
        details = f"Crash on oversized payload: {error}"
    return AttackReport(
        name="oversized_payload",
        category="proxy_stress",
        description="Very large params payload should not crash evaluator.",
        result=result,
        details=details,
        vectors_tested=1,
        vectors_blocked=blocked,
        vectors_bypassed=bypassed,
        severity="HIGH" if result == AttackResult.FAIL else "MEDIUM",
        fix_suggestion="Enforce request-size limits before deep evaluation.",
    )
