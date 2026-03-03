from __future__ import annotations

from config import AttackReport, AttackResult, run_attack
from orchesis.contrib.secret_scanner import SecretScanner


@run_attack
def attack_homoglyph_substitution() -> AttackReport:
    secret = "AKIAIOSFODNN7EXAMPLE"
    mutated = secret.replace("A", "А").replace("E", "Е")  # Cyrillic lookalikes
    scanner = SecretScanner()
    detected = bool(scanner.scan_text(mutated))
    result = AttackResult.PASS if detected else AttackResult.FAIL
    return AttackReport(
        name="homoglyph_substitution",
        category="secret_evasion",
        description="Homoglyph secret obfuscation.",
        result=result,
        vectors_tested=1,
        vectors_blocked=1 if detected else 0,
        vectors_bypassed=0 if detected else 1,
        severity="HIGH" if not detected else "LOW",
        fix_suggestion="Normalize confusable Unicode characters before secret scanning.",
    )
