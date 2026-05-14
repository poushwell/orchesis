from __future__ import annotations

from config import AttackReport, AttackResult, run_attack
from orchesis.contrib.secret_scanner import SecretScanner


@run_attack
def attack_unicode_escapes() -> AttackReport:
    secret = "AKIAIOSFODNN7EXAMPLE"
    escaped = "".join(f"\\u{ord(ch):04x}" for ch in secret)
    scanner = SecretScanner()
    detected = bool(scanner.scan_text(escaped))
    result = AttackResult.PASS if detected else AttackResult.FAIL
    return AttackReport(
        name="unicode_escapes",
        category="secret_evasion",
        description="Unicode-escaped secret text.",
        result=result,
        vectors_tested=1,
        vectors_blocked=1 if detected else 0,
        vectors_bypassed=0 if detected else 1,
        severity="MEDIUM" if not detected else "LOW",
        fix_suggestion="Decode unicode escapes in suspicious text before scanning.",
    )
