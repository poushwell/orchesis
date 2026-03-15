from __future__ import annotations

from datetime import date as _date, timedelta
from pathlib import Path

import orchesis.engine as engine_module
from orchesis import PolicyEngine
from orchesis.models import Decision


def test_policy_engine_import() -> None:
    assert PolicyEngine is not None


def test_policy_engine_evaluate() -> None:
    engine = PolicyEngine(policy={"rules": [{"name": "budget_limit", "max_cost_per_call": 1.0}]})
    decision = engine.evaluate({"cost": 0.2, "params": {}})
    assert isinstance(decision, Decision)
    assert decision.allowed is True


def test_no_duplicate_constants() -> None:
    engine_text = Path("src/orchesis/engine.py").read_text(encoding="utf-8")
    config_text = Path("src/orchesis/config.py").read_text(encoding="utf-8")
    assert engine_text.count("_TOOL_RATE_LIMIT_PATTERN =") == 0
    assert engine_text.count("_RATE_LIMIT_WINDOW_SECONDS =") == 0
    assert config_text.count("_TOOL_RATE_LIMIT_PATTERN =") == 1
    assert config_text.count("_RATE_LIMIT_WINDOW_SECONDS =") == 1


def test_daily_token_usage_resets(monkeypatch) -> None:  # noqa: ANN001
    engine_module._set_daily_token_usage("agent-reset-test", 123)
    assert engine_module._get_daily_token_usage("agent-reset-test") == 123

    next_day = _date.today() + timedelta(days=1)

    class _FakeDate(_date):
        @classmethod
        def today(cls):  # type: ignore[override]
            return next_day

    monkeypatch.setattr(engine_module, "date", _FakeDate)
    assert engine_module._get_daily_token_usage("agent-reset-test") == 0

