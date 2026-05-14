from __future__ import annotations

from config import AttackReport, AttackResult, run_attack
from orchesis.contrib.secret_scanner import SecretScanner


@run_attack
def attack_chunked_secret() -> AttackReport:
    chunks = ["AKIAIOS", "FODNN7", "EXAMPLE"]
    scanner = SecretScanner()
    detected_per_chunk = [bool(scanner.scan_text(chunk)) for chunk in chunks]
    combined_detected = bool(scanner.scan_text("".join(chunks)))
    bypassed = 0
    blocked = 0
    if combined_detected:
        blocked += 1
    else:
        bypassed += 1
    result = AttackResult.PASS if combined_detected else AttackResult.FAIL
    return AttackReport(
        name="chunked_secret",
        category="secret_evasion",
        description="Secret split across separate chunks/fields.",
        result=result,
        details=f"chunk_hits={detected_per_chunk}, combined={combined_detected}",
        vectors_tested=1,
        vectors_blocked=blocked,
        vectors_bypassed=bypassed,
        severity="HIGH" if not combined_detected else "LOW",
        fix_suggestion="Add cross-field / reassembly-aware scanning for fragmented secrets.",
    )
