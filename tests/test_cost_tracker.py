from __future__ import annotations

import datetime as dt
from concurrent.futures import ThreadPoolExecutor
from datetime import date
from unittest.mock import patch

from orchesis.cost_tracker import CostTracker, DEFAULT_TOOL_COSTS, MODEL_COSTS


def test_record_single_tool_call() -> None:
    tracker = CostTracker()
    call = tracker.record_call("web_search")
    assert call.tool_name == "web_search"
    assert call.cost_usd == DEFAULT_TOOL_COSTS["web_search"]


def test_record_multiple_tools_and_breakdown() -> None:
    tracker = CostTracker()
    tracker.record_call("read_file")
    tracker.record_call("read_file")
    tracker.record_call("send_email")
    costs = tracker.get_tool_costs()
    assert costs["read_file"] > 0
    assert costs["send_email"] > 0
    assert costs["read_file"] > costs["send_email"] / 20


def test_track_by_task_id() -> None:
    tracker = CostTracker()
    tracker.record_call("web_search", task_id="task-1")
    tracker.record_call("read_file", task_id="task-1")
    tracker.record_call("read_file", task_id="task-2")
    assert tracker.get_task_cost("task-1") > tracker.get_task_cost("task-2")


def test_model_based_cost_calculation() -> None:
    tracker = CostTracker()
    call = tracker.record_call("llm_call", model="gpt-4o-mini", tokens_input=1000, tokens_output=1000)
    rates = MODEL_COSTS["gpt-4o-mini"]
    expected = rates["input"] + rates["output"]
    assert abs(call.cost_usd - expected) < 1e-9


def test_daily_totals_accumulate() -> None:
    tracker = CostTracker()
    tracker.record_call("web_search")
    tracker.record_call("web_search")
    assert tracker.get_daily_total() == DEFAULT_TOOL_COSTS["web_search"] * 2


def test_budget_under_limit() -> None:
    tracker = CostTracker()
    tracker.record_call("web_search")
    status = tracker.check_budget({"daily": 1.0, "soft_limit_percent": 80})
    assert status["over_budget"] is False
    assert status["soft_limit_reached"] is False


def test_budget_at_soft_limit() -> None:
    tracker = CostTracker(tool_costs={"web_search": 0.8})
    tracker.record_call("web_search")
    status = tracker.check_budget({"daily": 1.0, "soft_limit_percent": 80})
    assert status["soft_limit_reached"] is True
    assert status["over_budget"] is False


def test_budget_over_hard_limit() -> None:
    tracker = CostTracker(tool_costs={"web_search": 2.0})
    tracker.record_call("web_search")
    status = tracker.check_budget({"daily": 1.0})
    assert status["over_budget"] is True


def test_per_tool_budget_status() -> None:
    tracker = CostTracker(tool_costs={"web_search": 1.5})
    tracker.record_call("web_search")
    status = tracker.check_budget({"daily": 10.0, "per_tool": {"web_search": 1.0}})
    assert status["per_tool_status"]["web_search"]["over"] is True


def test_thread_safety_concurrent_recording() -> None:
    tracker = CostTracker()

    def worker() -> None:
        for _ in range(100):
            tracker.record_call("read_file")

    with ThreadPoolExecutor(max_workers=10) as pool:
        for _ in range(10):
            pool.submit(worker)
    assert tracker.get_daily_total() > 0
    assert tracker.get_tool_costs().get("read_file", 0.0) > 0


def test_reset_daily_clears_today() -> None:
    tracker = CostTracker()
    tracker.record_call("web_search")
    assert tracker.get_daily_total() > 0
    tracker.reset_daily()
    assert tracker.get_daily_total() == 0


def test_get_hourly_costs_returns_dict() -> None:
    tracker = CostTracker()
    tracker.record_call("read_file")
    hourly = tracker.get_hourly_costs()
    assert isinstance(hourly, dict)
    assert len(hourly) >= 1


def test_custom_tool_cost_overrides_default() -> None:
    tracker = CostTracker(tool_costs={"web_search": 0.123})
    call = tracker.record_call("web_search")
    assert call.cost_usd == 0.123


def test_unknown_tool_uses_default_cost() -> None:
    tracker = CostTracker()
    call = tracker.record_call("unknown_tool_123")
    assert call.cost_usd == DEFAULT_TOOL_COSTS["default"]


def test_to_dict_export_shape() -> None:
    tracker = CostTracker()
    tracker.record_call("read_file", task_id="x")
    payload = tracker.to_dict()
    assert "calls" in payload
    assert "daily_totals" in payload
    assert "tool_daily" in payload
    assert "task_totals" in payload


def test_get_daily_total_for_specific_day_missing() -> None:
    tracker = CostTracker()
    assert tracker.get_daily_total("1999-01-01") == 0.0


def test_get_tool_costs_for_specific_day_missing() -> None:
    tracker = CostTracker()
    assert tracker.get_tool_costs("1999-01-01") == {}


def test_record_call_with_cost_override() -> None:
    tracker = CostTracker()
    call = tracker.record_call("read_file", cost_override=3.14)
    assert call.cost_usd == 3.14


def test_record_call_with_float_tokens_casted() -> None:
    tracker = CostTracker()
    call = tracker.record_call("llm", model="gpt-4o", tokens_input=10.2, tokens_output=9.8)
    assert call.tokens_input == 10
    assert call.tokens_output == 9


def test_per_tool_percent_zero_when_limit_zero() -> None:
    tracker = CostTracker()
    tracker.record_call("web_search")
    status = tracker.check_budget({"daily": 10.0, "per_tool": {"web_search": 0.0}})
    assert status["per_tool_status"]["web_search"]["percent"] == 0.0


def test_soft_limit_false_when_daily_infinite() -> None:
    tracker = CostTracker()
    tracker.record_call("web_search")
    status = tracker.check_budget({})
    assert status["soft_limit_reached"] is False


def test_check_budget_rounding_fields() -> None:
    tracker = CostTracker(tool_costs={"x": 0.3333333})
    tracker.record_call("x")
    status = tracker.check_budget({"daily": 1.0})
    assert isinstance(status["daily_spent"], float)
    assert isinstance(status["daily_remaining"], float)


def test_task_cost_missing_returns_zero() -> None:
    tracker = CostTracker()
    assert tracker.get_task_cost("missing") == 0.0


def test_to_dict_limits_call_history_to_1000() -> None:
    tracker = CostTracker()
    for _ in range(1105):
        tracker.record_call("read_file")
    payload = tracker.to_dict()
    assert len(payload["calls"]) == 1000


def test_hourly_costs_for_custom_day() -> None:
    tracker = CostTracker()
    tracker.record_call("read_file")
    today = date.today().isoformat()
    assert isinstance(tracker.get_hourly_costs(today), dict)


def test_cost_tracker_trims_calls_at_max() -> None:
    tracker = CostTracker(max_call_history=30)
    for _ in range(45):
        tracker.record_call("read_file")
    with tracker._lock:
        assert len(tracker._calls) <= 30


def test_cost_tracker_prunes_old_days() -> None:
    days = [dt.date(2031, 4, i) for i in range(1, 9)]
    day_iter = iter(days)

    class _PatchedDate:
        @staticmethod
        def today() -> dt.date:
            return next(day_iter)

        @staticmethod
        def fromtimestamp(ts: float, tz: dt.tzinfo | None = None) -> dt.date:
            return dt.date.fromtimestamp(ts, tz)

    with patch("orchesis.cost_tracker.date", _PatchedDate):
        tracker = CostTracker(max_days=3)
        for _ in range(6):
            tracker.record_call("read_file")
    with tracker._lock:
        assert len(tracker._daily_total) <= 3
        assert len(tracker._tool_daily) <= 3

