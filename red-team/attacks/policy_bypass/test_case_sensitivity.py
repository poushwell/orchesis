from __future__ import annotations

from config import AttackReport, AttackResult, run_attack
from orchesis.engine import PolicyEngine


@run_attack
def attack_case_sensitivity() -> AttackReport:
    vectors = ["Shell_Execute", "SHELL_EXECUTE", "sHeLL_eXeCuTe", "READ_FILE"]
    policy = {"tool_access": {"mode": "allowlist", "allowed": ["read_file"], "denied": ["shell_execute"]}, "rules": []}
    engine = PolicyEngine(policy)
    blocked = 0
    bypassed = 0
    details: list[str] = []
    for tool in vectors:
        decision = engine.evaluate({"tool": tool, "params": {}, "context": {"agent": "rt"}})
        is_shell_variant = "shell" in tool.lower()
        if is_shell_variant and decision.allowed:
            bypassed += 1
            details.append(f"allowed shell variant `{tool}`")
        else:
            blocked += 1
    result = AttackResult.FAIL if bypassed else AttackResult.PASS
    return AttackReport(
        name="case_sensitivity",
        category="policy_bypass",
        description="Case variants should not bypass deny rules.",
        result=result,
        details="; ".join(details),
        vectors_tested=len(vectors),
        vectors_blocked=blocked,
        vectors_bypassed=bypassed,
        severity="MEDIUM" if bypassed else "LOW",
        fix_suggestion="Normalize case consistently for tool allow/deny matching.",
    )
