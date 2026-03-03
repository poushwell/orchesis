from __future__ import annotations

from config import AttackReport, AttackResult, run_attack
from orchesis.engine import PolicyEngine


@run_attack
def attack_null_byte_injection() -> AttackReport:
    vectors = [
        ("read_file\x00shell_execute", {"path": "/tmp/a"}),
        ("\x00shell_execute", {"path": "/tmp/a"}),
        ("shell_execute\x00", {"path": "/tmp/a"}),
        ("read_file", {"path": "/allowed/path\x00/etc/passwd"}),
    ]
    policy = {
        "tool_access": {"mode": "allowlist", "allowed": ["read_file"]},
        "rules": [{"name": "file_access", "denied_paths": ["/etc"]}],
    }
    engine = PolicyEngine(policy)
    blocked = 0
    bypassed = 0
    details: list[str] = []
    for tool, params in vectors:
        decision = engine.evaluate({"tool": tool, "params": params, "context": {"agent": "rt"}})
        if decision.allowed:
            bypassed += 1
            details.append(f"allowed `{tool}` with params={params}")
        else:
            blocked += 1
    result = AttackResult.FAIL if bypassed else AttackResult.PASS
    return AttackReport(
        name="null_byte_injection",
        category="policy_bypass",
        description="Null-byte payloads should be rejected or safely blocked.",
        result=result,
        details="; ".join(details[:4]),
        vectors_tested=len(vectors),
        vectors_blocked=blocked,
        vectors_bypassed=bypassed,
        severity="HIGH" if bypassed else "LOW",
        fix_suggestion="Reject control characters (including NUL) in tool names and paths before policy matching.",
    )
