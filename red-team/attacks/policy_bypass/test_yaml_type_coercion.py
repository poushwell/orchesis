from __future__ import annotations

import tempfile
from pathlib import Path

import yaml

from config import AttackReport, AttackResult, run_attack
from orchesis.config import load_policy
from orchesis.engine import PolicyEngine


@run_attack
def attack_yaml_type_coercion() -> AttackReport:
    vectors = [
        "effect: on",
        "effect: off",
        "effect: yes",
        "effect: no",
        "effect: null",
        "effect: 1",
        "version: 1.0",
        'daily_budget: "50"',
    ]
    blocked = 0
    bypassed = 0
    details: list[str] = []
    for value in vectors:
        payload = f"tool_access:\n  mode: allowlist\n  allowed: [read_file]\n{value}\nrules: []\n"
        parsed = yaml.safe_load(payload)
        if not isinstance(parsed, dict):
            blocked += 1
            continue
        tmp = None
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as f:
                f.write(payload)
                tmp = Path(f.name)
            policy = load_policy(tmp)
            decision = PolicyEngine(policy).evaluate({"tool": "shell_execute", "params": {}, "context": {"agent": "rt"}})
            if decision.allowed:
                bypassed += 1
                details.append(f"allowed shell_execute for vector `{value}`")
            else:
                blocked += 1
        except Exception as error:  # noqa: BLE001
            blocked += 1
            details.append(f"{value}: handled with {type(error).__name__}")
        finally:
            if isinstance(tmp, Path) and tmp.exists():
                tmp.unlink()
    result = AttackResult.FAIL if bypassed else AttackResult.PASS
    return AttackReport(
        name="yaml_type_coercion",
        category="policy_bypass",
        description="YAML auto-typing should not cause policy misinterpretation.",
        result=result,
        details="; ".join(details[:6]),
        vectors_tested=len(vectors),
        vectors_blocked=blocked,
        vectors_bypassed=bypassed,
        severity="HIGH" if bypassed else "LOW",
        fix_suggestion="Validate and coerce policy types explicitly before evaluation.",
    )
