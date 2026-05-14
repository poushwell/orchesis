from __future__ import annotations

from config import AttackReport, AttackResult, run_attack
from orchesis.contrib.secret_scanner import SecretScanner


@run_attack
def attack_hex_encoding() -> AttackReport:
    secret = "AKIAIOSFODNN7EXAMPLE"
    encoded = "".join(f"\\x{ord(ch):02x}" for ch in secret)
    scanner = SecretScanner()
    detected = bool(scanner.scan_text(encoded))
    result = AttackResult.PASS if detected else AttackResult.FAIL
    return AttackReport(
        name="hex_encoding",
        category="secret_evasion",
        description="Hex-escaped secret text.",
        result=result,
        vectors_tested=1,
        vectors_blocked=1 if detected else 0,
        vectors_bypassed=0 if detected else 1,
        severity="MEDIUM" if not detected else "LOW",
        fix_suggestion="Decode hex escape sequences before evaluating secret patterns.",
    )
