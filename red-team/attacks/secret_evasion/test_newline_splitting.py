from __future__ import annotations

from config import AttackReport, AttackResult, run_attack
from orchesis.contrib.secret_scanner import SecretScanner


@run_attack
def attack_newline_splitting() -> AttackReport:
    secret = "AKIAIOSFODNN7EXAMPLE"
    variants = [secret[:i] + "\n" + secret[i:] for i in (4, 8, 12)]
    scanner = SecretScanner()
    blocked = sum(1 for item in variants if scanner.scan_text(item))
    bypassed = len(variants) - blocked
    result = AttackResult.PASS if bypassed == 0 else AttackResult.FAIL
    return AttackReport(
        name="newline_splitting",
        category="secret_evasion",
        description="Split secrets with newline characters.",
        result=result,
        vectors_tested=len(variants),
        vectors_blocked=blocked,
        vectors_bypassed=bypassed,
        severity="HIGH" if bypassed else "LOW",
        fix_suggestion="Normalize/remove newline separators before secret pattern evaluation.",
    )
