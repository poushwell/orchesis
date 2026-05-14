from __future__ import annotations

from config import AttackReport, AttackResult, run_attack
from orchesis.contrib.pii_detector import PiiDetector


@run_attack
def attack_zero_width_in_pii() -> AttackReport:
    text = "123\u200b-\u200b45\u200b-\u200b6789"
    detector = PiiDetector(severity_threshold="low")
    detected = bool(detector.scan_text(text))
    result = AttackResult.PASS if detected else AttackResult.FAIL
    return AttackReport(
        name="zero_width_in_pii",
        category="pii_evasion",
        description="Zero-width chars inserted into SSN.",
        result=result,
        vectors_tested=1,
        vectors_blocked=1 if detected else 0,
        vectors_bypassed=0 if detected else 1,
        severity="HIGH" if not detected else "LOW",
        fix_suggestion="Remove zero-width codepoints before applying PII regexes.",
    )
