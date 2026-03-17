from __future__ import annotations

import yaml

from orchesis.context_budget import ContextBudget


def _msg(role: str, content: str) -> dict[str, str]:
    return {"role": role, "content": content}


def test_l0_triggered_at_80_percent() -> None:
    budget = ContextBudget()
    assert budget.check_level(used_tokens=80, max_tokens=100) == "L0"


def test_l1_trims_old_turns() -> None:
    budget = ContextBudget()
    messages = [_msg("system", "You are helpful")] + [
        _msg("user" if i % 2 == 0 else "assistant", f"turn-{i}") for i in range(10)
    ]
    out = budget.apply(messages=messages, level="L1", max_tokens=100)
    assert out[0]["role"] == "system"
    assert len(out) <= 5
    contents = [item.get("content") for item in out if isinstance(item, dict)]
    assert "turn-9" in contents


def test_l2_keeps_only_system_prompt() -> None:
    budget = ContextBudget()
    messages = [
        _msg("system", "You are concise"),
        _msg("user", "question"),
        _msg("assistant", "answer"),
    ]
    out = budget.apply(messages=messages, level="L2", max_tokens=100)
    assert len(out) == 1
    assert out[0]["role"] == "system"
    assert out[0]["content"] == "You are concise"


def test_normal_below_threshold() -> None:
    budget = ContextBudget()
    assert budget.check_level(used_tokens=79, max_tokens=100) == "normal"


def test_degradation_stats_tracked() -> None:
    budget = ContextBudget()
    _ = budget.check_level(used_tokens=79, max_tokens=100)  # normal
    _ = budget.check_level(used_tokens=80, max_tokens=100)  # L0
    _ = budget.check_level(used_tokens=90, max_tokens=100)  # L1
    _ = budget.check_level(used_tokens=100, max_tokens=100)  # L2
    stats = budget.get_stats()
    assert stats["events"]["normal"] == 1
    assert stats["events"]["L0"] == 1
    assert stats["events"]["L1"] == 1
    assert stats["events"]["L2"] == 1


def test_config_from_yaml() -> None:
    raw = yaml.safe_load(
        """
context_budget:
  enabled: true
  model_context_windows:
    gpt-4o: 128000
    gpt-4o-mini: 128000
    claude-3-5-sonnet: 200000
  l0_threshold: 0.80
  l1_threshold: 0.90
  l2_threshold: 1.00
"""
    )
    cfg = raw["context_budget"]
    budget = ContextBudget(cfg)
    stats = budget.get_stats()
    assert budget.enabled is True
    assert budget.model_context_windows["gpt-4o"] == 128000
    assert stats["thresholds"]["L0"] == 0.80
    assert stats["thresholds"]["L1"] == 0.90
    assert stats["thresholds"]["L2"] == 1.00

