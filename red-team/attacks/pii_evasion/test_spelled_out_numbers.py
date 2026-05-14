from __future__ import annotations

from config import AttackReport, AttackResult, run_attack
from orchesis.contrib.pii_detector import PiiDetector


@run_attack
def attack_spelled_out_numbers() -> AttackReport:
    text = "one two three dash four five dash six seven eight nine"
    detector = PiiDetector(severity_threshold="low")
    detected = bool(detector.scan_text(text))
    result = AttackResult.PASS if detected else AttackResult.PARTIAL
    return AttackReport(
        name="spelled_out_numbers",
        category="pii_evasion",
        description="PII represented as words instead of digits.",
        result=result,
        vectors_tested=1,
        vectors_blocked=1 if detected else 0,
        vectors_bypassed=0 if detected else 1,
        severity="MEDIUM",
        fix_suggestion="Add optional NLP/word-number normalization for high-security contexts.",
    )
