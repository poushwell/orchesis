from __future__ import annotations

from config import AttackReport, AttackResult, run_attack
from orchesis.engine import PolicyEngine


@run_attack
def attack_path_normalization() -> AttackReport:
    paths = [
        "../../../../etc/passwd",
        "/etc/../etc/passwd",
        "/etc/./passwd",
        "//etc//passwd",
        "/ETC/PASSWD",
        "%2Fetc%2Fpasswd",
        "\\etc\\passwd",
    ]
    policy = {
        "tool_access": {"mode": "allowlist", "allowed": ["read_file"]},
        "rules": [{"name": "file_access", "denied_paths": ["/etc"]}],
    }
    engine = PolicyEngine(policy)
    blocked = 0
    bypassed = 0
    details: list[str] = []
    for path in paths:
        request = {"tool": "read_file", "params": {"path": path}, "context": {"agent": "rt"}}
        decision = engine.evaluate(request)
        if decision.allowed:
            bypassed += 1
            details.append(f"allowed path `{path}`")
        else:
            blocked += 1
    result = AttackResult.FAIL if bypassed else AttackResult.PASS
    return AttackReport(
        name="path_normalization",
        category="policy_bypass",
        description="Path canonicalization should prevent traversal and alias bypasses.",
        result=result,
        details="; ".join(details[:6]),
        vectors_tested=len(paths),
        vectors_blocked=blocked,
        vectors_bypassed=bypassed,
        severity="CRITICAL" if bypassed else "LOW",
        fix_suggestion="Canonicalize and decode paths before denied-path checks (including backslashes/URL encoding).",
    )
