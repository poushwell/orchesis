from __future__ import annotations

from config import AttackReport, AttackResult, run_attack
from orchesis.contrib.pii_detector import PiiDetector


@run_attack
def attack_bidi_override() -> AttackReport:
    text = "\u202e123-45-6789\u202c"
    detector = PiiDetector(severity_threshold="low")
    detected = bool(detector.scan_text(text))
    result = AttackResult.PASS if detected else AttackResult.FAIL
    return AttackReport(
        name="bidi_override",
        category="pii_evasion",
        description="Bidi control chars around PII.",
        result=result,
        vectors_tested=1,
        vectors_blocked=1 if detected else 0,
        vectors_bypassed=0 if detected else 1,
        severity="HIGH" if not detected else "LOW",
        fix_suggestion="Strip or normalize bidi control characters before PII detection.",
    )
