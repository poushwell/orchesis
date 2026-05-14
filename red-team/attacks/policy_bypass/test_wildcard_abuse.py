from __future__ import annotations

from config import AttackReport, AttackResult, run_attack
from orchesis.engine import PolicyEngine


@run_attack
def attack_wildcard_abuse() -> AttackReport:
    vectors = [
        {"mode": "allowlist", "allowed": ["*"]},
        {"mode": "allowlist", "allowed": ["shell_*"]},
        {"mode": "allowlist", "allowed": ["../../etc/*"]},
        {"mode": "allowlist", "allowed": ["a" * 10000]},
    ]
    blocked = 0
    bypassed = 0
    details: list[str] = []
    for cfg in vectors:
        policy = {"tool_access": cfg, "rules": []}
        engine = PolicyEngine(policy)
        decision = engine.evaluate({"tool": "shell_execute", "params": {}, "context": {"agent": "rt"}})
        if decision.allowed:
            bypassed += 1
            details.append(f"wildcard policy allowed shell_execute: {cfg['allowed'][0][:40]}")
        else:
            blocked += 1
    result = AttackResult.FAIL if bypassed else AttackResult.PASS
    return AttackReport(
        name="wildcard_abuse",
        category="policy_bypass",
        description="Wildcard-like patterns should not accidentally allow dangerous tools.",
        result=result,
        details="; ".join(details[:4]),
        vectors_tested=len(vectors),
        vectors_blocked=blocked,
        vectors_bypassed=bypassed,
        severity="HIGH" if bypassed else "LOW",
        fix_suggestion="Disallow wildcard entries or treat them explicitly with safe semantics.",
    )
