from __future__ import annotations

import base64

from config import AttackReport, AttackResult, run_attack
from orchesis.contrib.secret_scanner import SecretScanner


@run_attack
def attack_base64_encoding() -> AttackReport:
    secret = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12"
    encoded = base64.b64encode(secret.encode("utf-8")).decode("ascii")
    scanner = SecretScanner()
    detected = bool(scanner.scan_text(encoded))
    result = AttackResult.PASS if detected else AttackResult.FAIL
    return AttackReport(
        name="base64_encoding",
        category="secret_evasion",
        description="Base64 encoded secret should be detected or flagged.",
        result=result,
        vectors_tested=1,
        vectors_blocked=1 if detected else 0,
        vectors_bypassed=0 if detected else 1,
        severity="MEDIUM" if not detected else "LOW",
        fix_suggestion="Add optional decoding heuristics for base64-like segments before scanning.",
    )
