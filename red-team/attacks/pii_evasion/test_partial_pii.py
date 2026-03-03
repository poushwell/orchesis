from __future__ import annotations

from config import AttackReport, AttackResult, run_attack
from orchesis.contrib.pii_detector import PiiDetector


@run_attack
def attack_partial_pii() -> AttackReport:
    text = "SSN ending in 6789, previous digits omitted."
    detector = PiiDetector(severity_threshold="low")
    detected = bool(detector.scan_text(text))
    if detected:
        result = AttackResult.PASS
    else:
        result = AttackResult.PARTIAL
    return AttackReport(
        name="partial_pii",
        category="pii_evasion",
        description="Partial PII disclosure patterns.",
        result=result,
        vectors_tested=1,
        vectors_blocked=1 if detected else 0,
        vectors_bypassed=0 if detected else 1,
        severity="LOW",
        fix_suggestion="Consider optional partial-PII heuristics (e.g., last4 + context terms).",
    )
