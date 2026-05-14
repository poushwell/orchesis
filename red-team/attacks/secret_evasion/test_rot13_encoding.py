from __future__ import annotations

import codecs

from config import AttackReport, AttackResult, run_attack
from orchesis.contrib.secret_scanner import SecretScanner


@run_attack
def attack_rot13_encoding() -> AttackReport:
    secret = "AKIAIOSFODNN7EXAMPLE"
    transformed = codecs.decode(secret, "rot_13")
    scanner = SecretScanner()
    detected = bool(scanner.scan_text(transformed))
    result = AttackResult.PASS if detected else AttackResult.FAIL
    return AttackReport(
        name="rot13_encoding",
        category="secret_evasion",
        description="ROT13-obfuscated secret values.",
        result=result,
        vectors_tested=1,
        vectors_blocked=1 if detected else 0,
        vectors_bypassed=0 if detected else 1,
        severity="LOW" if not detected else "LOW",
        fix_suggestion="Optional: add decoder heuristics for known weak obfuscation schemes like ROT13.",
    )
