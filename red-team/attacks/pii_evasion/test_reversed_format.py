from __future__ import annotations

from config import AttackReport, AttackResult, run_attack
from orchesis.contrib.pii_detector import PiiDetector


@run_attack
def attack_reversed_format() -> AttackReport:
    samples = ["9876-54-321", "1111-1111-1111-1114"]
    detector = PiiDetector(severity_threshold="low")
    detected = any(detector.scan_text(item) for item in samples)
    result = AttackResult.PASS if detected else AttackResult.PARTIAL
    return AttackReport(
        name="reversed_format",
        category="pii_evasion",
        description="Reversed or reordered PII format.",
        result=result,
        vectors_tested=len(samples),
        vectors_blocked=1 if detected else 0,
        vectors_bypassed=0 if detected else 1,
        severity="MEDIUM",
        fix_suggestion="Consider checksum/context-aware detection for non-canonical ordering.",
    )
