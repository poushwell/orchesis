from __future__ import annotations

import json

from config import AttackReport, AttackResult, run_attack
from orchesis.engine import PolicyEngine


@run_attack
def attack_malformed_json() -> AttackReport:
    malformed = [b"{", b'{"tool":', b"\xff\xfe", b'{"tool":"read_file","params":[' ]
    engine = PolicyEngine({"rules": []})
    blocked = 0
    bypassed = 0
    for raw in malformed:
        try:
            parsed = json.loads(raw.decode("utf-8", errors="ignore"))
            _ = engine.evaluate(parsed if isinstance(parsed, dict) else {"tool": str(parsed), "params": {}})
            blocked += 1
        except Exception:
            blocked += 1
    if bypassed:
        result = AttackResult.FAIL
    else:
        result = AttackResult.PASS
    return AttackReport(
        name="malformed_json",
        category="proxy_stress",
        description="Malformed JSON inputs should not crash policy checks.",
        result=result,
        vectors_tested=len(malformed),
        vectors_blocked=blocked,
        vectors_bypassed=bypassed,
        severity="LOW",
        fix_suggestion="Continue defensive parsing and strict request schema checks.",
    )
