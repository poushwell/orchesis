from __future__ import annotations

from config import AttackReport, AttackResult, run_attack
from orchesis.contrib.pii_detector import PiiDetector


@run_attack
def attack_mixed_scripts() -> AttackReport:
    text = "SSN 12٣-45-6789 and card 4111-1111-1111-١١١١"
    detector = PiiDetector(severity_threshold="low")
    detected = bool(detector.scan_text(text))
    result = AttackResult.PASS if detected else AttackResult.FAIL
    return AttackReport(
        name="mixed_scripts",
        category="pii_evasion",
        description="PII with mixed Latin and Arabic-Indic digits.",
        result=result,
        vectors_tested=1,
        vectors_blocked=1 if detected else 0,
        vectors_bypassed=0 if detected else 1,
        severity="HIGH" if not detected else "LOW",
        fix_suggestion="Normalize script-specific digits to ASCII before regex matching.",
    )
