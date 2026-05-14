from __future__ import annotations

import concurrent.futures

from config import AttackReport, AttackResult, run_attack
from orchesis.engine import PolicyEngine


@run_attack
def attack_concurrent_calls() -> AttackReport:
    policy = {"rules": [{"name": "rate_limit", "max_requests_per_minute": 10}]}
    engine = PolicyEngine(policy)

    def _call_once() -> bool:
        d = engine.evaluate({"tool": "read_file", "params": {"path": "/tmp/x"}, "context": {"agent": "rt"}})
        return d.allowed

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        results = list(ex.map(lambda _: _call_once(), range(200)))
    allowed = sum(1 for item in results if item)
    denied = len(results) - allowed
    result = AttackResult.PASS if denied > 0 else AttackResult.FAIL
    return AttackReport(
        name="concurrent_calls",
        category="proxy_stress",
        description="Concurrent evaluate calls should remain stable and enforce limits.",
        result=result,
        details=f"allowed={allowed}, denied={denied}",
        vectors_tested=len(results),
        vectors_blocked=denied,
        vectors_bypassed=1 if denied == 0 else 0,
        severity="HIGH" if denied == 0 else "LOW",
        fix_suggestion="Ensure atomic counter updates in concurrent rate-limit checks.",
    )
