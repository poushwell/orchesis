from __future__ import annotations

from datetime import datetime, timezone

from config import AttackReport, AttackResult, run_attack
from orchesis.engine import PolicyEngine
from orchesis.state import RateLimitTracker


@run_attack
def attack_per_tool_vs_global() -> AttackReport:
    policy = {
        "tool_access": {
            "mode": "allowlist",
            "allowed": ["read_file", "web_search"],
            "rate_limits": {"read_file": "2/minute", "web_search": "2/minute"},
        },
        "rules": [{"name": "rate_limit", "max_requests_per_minute": 3}],
    }
    engine = PolicyEngine(policy, state=RateLimitTracker(persist_path=None))
    now = datetime.now(timezone.utc)
    decisions = [
        engine.evaluate({"tool": "read_file", "params": {"path": "/tmp/a"}, "context": {"agent": "rt"}}, now=now),
        engine.evaluate({"tool": "read_file", "params": {"path": "/tmp/b"}, "context": {"agent": "rt"}}, now=now),
        engine.evaluate({"tool": "web_search", "params": {"query": "a"}, "context": {"agent": "rt"}}, now=now),
        engine.evaluate({"tool": "web_search", "params": {"query": "b"}, "context": {"agent": "rt"}}, now=now),
    ]
    denied = sum(1 for d in decisions if not d.allowed)
    result = AttackResult.PASS if denied >= 1 else AttackResult.FAIL
    return AttackReport(
        name="per_tool_vs_global",
        category="rate_limit_bypass",
        description="Per-tool and global limits should compose without bypass.",
        result=result,
        details=f"denied={denied}",
        vectors_tested=len(decisions),
        vectors_blocked=denied,
        vectors_bypassed=0 if denied else 1,
        severity="MEDIUM" if result == AttackResult.FAIL else "LOW",
        fix_suggestion="Ensure per-tool and global counters are both applied consistently.",
    )
