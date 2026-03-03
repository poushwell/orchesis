from __future__ import annotations

from config import AttackReport, AttackResult, run_attack
from orchesis.engine import PolicyEngine


@run_attack
def attack_contradictory_rules() -> AttackReport:
    policy = {
        "tool_access": {
            "mode": "allowlist",
            "allowed": ["read_file", "shell_execute"],
            "denied": ["shell_execute"],
        },
        "rules": [
            {"name": "file_access", "allowed_paths": ["/tmp"], "denied_paths": ["/tmp"]},
            {"name": "file_access", "allowed_paths": ["/data"], "denied_paths": ["/etc"]},
        ],
    }
    engine = PolicyEngine(policy)
    samples = [
        {"tool": "shell_execute", "params": {}, "context": {"agent": "rt"}},
        {"tool": "read_file", "params": {"path": "/tmp/a"}, "context": {"agent": "rt"}},
        {"tool": "read_file", "params": {"path": "/etc/passwd"}, "context": {"agent": "rt"}},
    ]
    blocked = 0
    bypassed = 0
    details: list[str] = []
    for request in samples:
        decision = engine.evaluate(request)
        if request["tool"] == "shell_execute" and decision.allowed:
            bypassed += 1
            details.append("shell_execute allowed despite deny entry")
        elif request["tool"] == "read_file" and request["params"]["path"].startswith("/etc") and decision.allowed:
            bypassed += 1
            details.append("/etc read allowed despite denied path rule")
        else:
            blocked += 1
    result = AttackResult.FAIL if bypassed else AttackResult.PASS
    return AttackReport(
        name="contradictory_rules",
        category="policy_bypass",
        description="Contradictory policy entries should resolve deterministically to safe behavior.",
        result=result,
        details="; ".join(details),
        vectors_tested=len(samples),
        vectors_blocked=blocked,
        vectors_bypassed=bypassed,
        severity="HIGH" if bypassed else "LOW",
        fix_suggestion="Enforce deny-precedence and reject contradictory rules during validation.",
    )
