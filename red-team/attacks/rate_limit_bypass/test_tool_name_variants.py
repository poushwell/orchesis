from __future__ import annotations

from datetime import datetime, timezone

from config import AttackReport, AttackResult, run_attack
from orchesis.engine import PolicyEngine
from orchesis.state import RateLimitTracker


@run_attack
def attack_tool_name_variants() -> AttackReport:
    policy = {
        "tool_access": {
            "mode": "allowlist",
            "allowed": ["read_file", "READ_FILE", " read_file "],
            "rate_limits": {"read_file": "2/minute"},
        },
        "rules": [],
    }
    tracker = RateLimitTracker(persist_path=None)
    engine = PolicyEngine(policy, state=tracker)
    now = datetime.now(timezone.utc)
    variants = ["read_file", "READ_FILE", " read_file "]
    decisions = [
        engine.evaluate({"tool": tool, "params": {"path": "/tmp/x"}, "context": {"agent": "rt"}}, now=now)
        for tool in variants
    ]
    denied = sum(1 for d in decisions if not d.allowed)
    # If variants are treated as different counters, all might pass.
    result = AttackResult.PASS if denied >= 1 else AttackResult.FAIL
    return AttackReport(
        name="tool_name_variants",
        category="rate_limit_bypass",
        description="Tool-name variants should not bypass per-tool counters.",
        result=result,
        details=f"denied={denied} across variants",
        vectors_tested=len(variants),
        vectors_blocked=denied,
        vectors_bypassed=0 if denied else 1,
        severity="MEDIUM" if result == AttackResult.FAIL else "LOW",
        fix_suggestion="Normalize tool names before rate-limit keying.",
    )
