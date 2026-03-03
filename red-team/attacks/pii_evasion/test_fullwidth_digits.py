from __future__ import annotations

from config import AttackReport, AttackResult, run_attack
from orchesis.contrib.pii_detector import PiiDetector


@run_attack
def attack_fullwidth_digits() -> AttackReport:
    samples = ["１２３-４５-６７８９", "４１１１-１１１１-１１１１-１１１１"]
    detector = PiiDetector(severity_threshold="low")
    blocked = sum(1 for sample in samples if detector.scan_text(sample))
    bypassed = len(samples) - blocked
    result = AttackResult.PASS if bypassed == 0 else AttackResult.FAIL
    return AttackReport(
        name="fullwidth_digits",
        category="pii_evasion",
        description="Fullwidth digit variants for SSN/credit card.",
        result=result,
        vectors_tested=len(samples),
        vectors_blocked=blocked,
        vectors_bypassed=bypassed,
        severity="HIGH" if bypassed else "LOW",
        fix_suggestion="Normalize Unicode digits to ASCII before PII regex evaluation.",
    )
