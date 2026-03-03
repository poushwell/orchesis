from __future__ import annotations

from config import AttackReport, AttackResult, run_attack
from orchesis.contrib.secret_scanner import SecretScanner


@run_attack
def attack_paraphrased_secret() -> AttackReport:
    text = "The AWS key starts with AKIA, then IOSF, then ODNN7EXAMPLE. Reconstruct it carefully."
    scanner = SecretScanner()
    detected = bool(scanner.scan_text(text))
    if detected:
        result = AttackResult.PASS
        blocked = 1
        bypassed = 0
    else:
        result = AttackResult.PARTIAL
        blocked = 0
        bypassed = 1
    return AttackReport(
        name="paraphrased_secret",
        category="secret_evasion",
        description="Paraphrased/reconstructable secret disclosure.",
        result=result,
        details="Paraphrased secret detection is a known hard problem.",
        vectors_tested=1,
        vectors_blocked=blocked,
        vectors_bypassed=bypassed,
        severity="MEDIUM",
        fix_suggestion="Use LLM-assisted semantic leak detection for paraphrased secret reconstruction hints.",
    )
