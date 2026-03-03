from __future__ import annotations

from config import AttackReport, AttackResult, run_attack
from orchesis.contrib.secret_scanner import SecretScanner


@run_attack
def attack_zero_width_chars() -> AttackReport:
    secret = "AKIAIOSFODNN7EXAMPLE"
    mutated = "\u200b".join(list(secret))
    scanner = SecretScanner()
    detected = bool(scanner.scan_text(mutated))
    result = AttackResult.PASS if detected else AttackResult.FAIL
    return AttackReport(
        name="zero_width_chars",
        category="secret_evasion",
        description="Zero-width separators between secret characters.",
        result=result,
        vectors_tested=1,
        vectors_blocked=1 if detected else 0,
        vectors_bypassed=0 if detected else 1,
        severity="HIGH" if not detected else "LOW",
        fix_suggestion="Strip zero-width characters before pattern matching.",
    )
