from __future__ import annotations

import tempfile
from pathlib import Path

import yaml

from config import AttackReport, AttackResult, run_attack
from orchesis.config import load_policy, validate_policy
from orchesis.engine import PolicyEngine


@run_attack
def attack_effect_type_confusion() -> AttackReport:
    values = ["1", "[allow]", "{action: allow}", "true", '""', ""]
    blocked = 0
    bypassed = 0
    details: list[str] = []
    for value in values:
        payload = (
            "tool_access:\n  mode: allowlist\n  allowed: [read_file]\n"
            f"rules:\n  - name: context_rules\n    effect: {value}\n"
        )
        tmp_path = None
        try:
            _ = yaml.safe_load(payload)
            with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as f:
                f.write(payload)
                tmp_path = Path(f.name)
            policy = load_policy(tmp_path)
            errors = validate_policy(policy)
            decision = PolicyEngine(policy).evaluate({"tool": "shell_execute", "params": {}, "context": {"agent": "rt"}})
            if decision.allowed and not errors:
                bypassed += 1
                details.append(f"effect={value} allowed dangerous call")
            else:
                blocked += 1
        except Exception as error:  # noqa: BLE001
            blocked += 1
            details.append(f"effect={value} rejected ({type(error).__name__})")
        finally:
            if isinstance(tmp_path, Path) and tmp_path.exists():
                tmp_path.unlink()
    result = AttackResult.FAIL if bypassed else AttackResult.PASS
    return AttackReport(
        name="effect_type_confusion",
        category="policy_bypass",
        description="Non-string effect values should be rejected or safely ignored.",
        result=result,
        details="; ".join(details[:6]),
        vectors_tested=len(values),
        vectors_blocked=blocked,
        vectors_bypassed=bypassed,
        severity="HIGH" if bypassed else "LOW",
        fix_suggestion="Enforce strict schema validation for effect fields and reject unknown types.",
    )
