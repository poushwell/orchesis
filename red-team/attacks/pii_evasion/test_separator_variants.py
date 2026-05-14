from __future__ import annotations

from config import AttackReport, AttackResult, run_attack
from orchesis.contrib.pii_detector import PiiDetector


@run_attack
def attack_separator_variants() -> AttackReport:
    samples = ["123.45.6789", "123 45 6789", "123/45/6789"]
    detector = PiiDetector(severity_threshold="low")
    blocked = sum(1 for sample in samples if detector.scan_text(sample))
    bypassed = len(samples) - blocked
    result = AttackResult.PASS if bypassed == 0 else AttackResult.PARTIAL
    return AttackReport(
        name="separator_variants",
        category="pii_evasion",
        description="PII with non-standard separators.",
        result=result,
        vectors_tested=len(samples),
        vectors_blocked=blocked,
        vectors_bypassed=bypassed,
        severity="MEDIUM",
        fix_suggestion="Expand separator handling in SSN/PII regex definitions.",
    )
