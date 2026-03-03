from __future__ import annotations

from config import AttackReport, AttackResult, run_attack
from orchesis.engine import PolicyEngine


@run_attack
def attack_whitespace_padding() -> AttackReport:
    vectors = [
        {"tool": "  shell_execute  ", "params": {}, "context": {"agent": "rt"}},
        {"tool": "shell\texecute", "params": {}, "context": {"agent": "rt"}},
        {"tool": "shell\nexecute", "params": {}, "context": {"agent": "rt"}},
        {"tool": "read_file", "params": {"path": "/etc/passwd "}, "context": {"agent": "rt"}},
    ]
    policy = {
        "tool_access": {"mode": "denylist", "denied": ["shell_execute"]},
        "rules": [{"name": "file_access", "denied_paths": ["/etc"]}],
    }
    engine = PolicyEngine(policy)
    blocked = 0
    bypassed = 0
    details: list[str] = []
    for request in vectors:
        decision = engine.evaluate(request)
        if decision.allowed:
            bypassed += 1
            details.append(f"allowed `{request['tool']}`")
        else:
            blocked += 1
    result = AttackResult.FAIL if bypassed else AttackResult.PASS
    return AttackReport(
        name="whitespace_padding",
        category="policy_bypass",
        description="Whitespace-obfuscated tool/path inputs should not bypass controls.",
        result=result,
        details="; ".join(details),
        vectors_tested=len(vectors),
        vectors_blocked=blocked,
        vectors_bypassed=bypassed,
        severity="MEDIUM" if bypassed else "LOW",
        fix_suggestion="Normalize whitespace in tool names and paths before matching.",
    )
