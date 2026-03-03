from __future__ import annotations

from config import AttackReport, AttackResult, run_attack
from orchesis.engine import PolicyEngine


def _nested(levels: int) -> dict:
    node = {"leaf": "x"}
    for i in range(levels):
        node = {f"n{i}": node}
    return node


@run_attack
def attack_deeply_nested_json() -> AttackReport:
    payload = _nested(1000)
    engine = PolicyEngine({"tool_access": {"mode": "allowlist", "allowed": ["read_file"]}, "rules": []})
    try:
        decision = engine.evaluate({"tool": "read_file", "params": payload, "context": {"agent": "rt"}})
        result = AttackResult.PASS if isinstance(decision.allowed, bool) else AttackResult.FAIL
        bypassed = 0 if result == AttackResult.PASS else 1
    except RecursionError:
        result = AttackResult.FAIL
        bypassed = 1
    return AttackReport(
        name="deeply_nested_json",
        category="proxy_stress",
        description="Extremely nested params should not trigger stack overflows.",
        result=result,
        vectors_tested=1,
        vectors_blocked=1 if result == AttackResult.PASS else 0,
        vectors_bypassed=bypassed,
        severity="HIGH" if result == AttackResult.FAIL else "LOW",
        fix_suggestion="Limit recursion depth and normalize nested structures iteratively.",
    )
