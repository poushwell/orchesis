from __future__ import annotations

import unicodedata

from config import AttackReport, AttackResult, run_attack
from orchesis.engine import PolicyEngine


@run_attack
def attack_unicode_normalization() -> AttackReport:
    variants = [
        "ｓｈｅｌｌ＿ｅｘｅｃｕｔｅ",
        unicodedata.normalize("NFKD", "shell_execute"),
        "shell_exe\u0301cute",
        "ѕhеll_ехесutе",
        "shеll_execuтe",
    ]
    policy = {"tool_access": {"mode": "denylist", "denied": ["shell_execute"]}, "rules": []}
    engine = PolicyEngine(policy)
    blocked = 0
    bypassed = 0
    details: list[str] = []
    for variant in variants:
        decision = engine.evaluate({"tool": variant, "params": {}, "context": {"agent": "rt"}})
        if decision.allowed:
            bypassed += 1
            details.append(f"allowed variant `{variant}`")
        else:
            blocked += 1
    result = AttackResult.FAIL if bypassed else AttackResult.PASS
    severity = "CRITICAL" if bypassed else "LOW"
    return AttackReport(
        name="unicode_normalization",
        category="policy_bypass",
        description="Unicode tool-name variants should not bypass denylist.",
        result=result,
        details="; ".join(details[:5]),
        vectors_tested=len(variants),
        vectors_blocked=blocked,
        vectors_bypassed=bypassed,
        severity=severity,
        fix_suggestion="Apply Unicode NFKC normalization before tool-name comparisons in engine tool access checks.",
    )
