from __future__ import annotations

import urllib.parse

from config import AttackReport, AttackResult, run_attack
from orchesis.contrib.secret_scanner import SecretScanner


@run_attack
def attack_url_encoding() -> AttackReport:
    secret = "AKIAIOSFODNN7EXAMPLE"
    encoded = urllib.parse.quote(secret, safe="")
    scanner = SecretScanner()
    detected = bool(scanner.scan_text(encoded))
    result = AttackResult.PASS if detected else AttackResult.FAIL
    return AttackReport(
        name="url_encoding",
        category="secret_evasion",
        description="Percent-encoded secret strings.",
        result=result,
        vectors_tested=1,
        vectors_blocked=1 if detected else 0,
        vectors_bypassed=0 if detected else 1,
        severity="MEDIUM" if not detected else "LOW",
        fix_suggestion="Attempt URL-decoding candidate payloads before scanning.",
    )
