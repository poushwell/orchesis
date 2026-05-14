from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from orchesis.integrations.budget_bridge import BudgetBridge


def test_compute_cost_gpt4o() -> None:
    bridge = BudgetBridge()
    # (1000 / 1_000_000 * 2.5) + (500 / 1_000_000 * 10) = 0.0075
    assert bridge.compute_cost("gpt-4o", 1000, 500) == pytest.approx(0.0075, abs=1e-9)


def test_compute_cost_claude_sonnet() -> None:
    bridge = BudgetBridge()
    # 2000 * 3/1M + 1000 * 15/1M = 0.021
    assert bridge.compute_cost("claude-3-sonnet", 2000, 1000) == pytest.approx(0.021, abs=1e-9)


def test_compute_cost_unknown_model() -> None:
    bridge = BudgetBridge()
    # fallback: input 3.0, output 15.0
    assert bridge.compute_cost("unknown-x", 1000, 1000) == pytest.approx(0.018, abs=1e-9)


def test_compute_cost_zero_tokens() -> None:
    bridge = BudgetBridge()
    assert bridge.compute_cost("gpt-4o", 0, 0) == 0.0


def test_record_usage() -> None:
    bridge = BudgetBridge()
    record = bridge.record_usage(
        agent_id="a1",
        model="gpt-4o-mini",
        input_tokens=1000,
        output_tokens=500,
        reported_cost_usd=0.0,
        request_id="req-1",
    )
    assert record.agent_id == "a1"
    assert record.model == "gpt-4o-mini"
    assert record.request_id == "req-1"
    assert record.computed_cost_usd > 0.0


def test_record_discrepancy() -> None:
    bridge = BudgetBridge(pricing={"x": {"input": 50.0, "output": 0.0}})
    record = bridge.record_usage("a1", "x", 1000, 0, reported_cost_usd=0.0)
    assert record.computed_cost_usd == pytest.approx(0.05, abs=1e-9)
    assert record.discrepancy == pytest.approx(0.05, abs=1e-9)


def test_multiple_records() -> None:
    bridge = BudgetBridge()
    bridge.record_usage("a1", "gpt-4o-mini", 100, 100)
    bridge.record_usage("a1", "gpt-4o-mini", 200, 200)
    bridge.record_usage("a1", "gpt-4o-mini", 300, 300)
    assert len(bridge._records["a1"]) == 3


def test_check_budget_under() -> None:
    bridge = BudgetBridge()
    bridge.record_usage("a1", "gpt-4o", 1000, 500)
    assert bridge.check_budget("a1", daily_limit=1.0) is True


def test_check_budget_over() -> None:
    bridge = BudgetBridge(pricing={"x": {"input": 1000.0, "output": 0.0}})
    bridge.record_usage("a1", "x", 1000, 0)
    # computed = 1.0
    assert bridge.check_budget("a1", daily_limit=0.5) is False


def test_check_budget_no_limit() -> None:
    bridge = BudgetBridge()
    bridge.record_usage("a1", "gpt-4o", 10_000, 10_000)
    assert bridge.check_budget("a1") is True


def test_daily_cost_only_today() -> None:
    bridge = BudgetBridge(pricing={"x": {"input": 1000.0, "output": 0.0}})
    old = bridge.record_usage("a1", "x", 1000, 0)
    old.timestamp = (datetime.now() - timedelta(days=1)).timestamp()
    bridge.record_usage("a1", "x", 500, 0)
    # only today's record: 0.5
    assert bridge.get_daily_cost("a1") == pytest.approx(0.5, abs=1e-9)


def test_spoof_detected() -> None:
    bridge = BudgetBridge(pricing={"x": {"input": 5000.0, "output": 0.0}}, spoof_threshold=0.5)
    bridge.record_usage("a1", "x", 1000, 0, reported_cost_usd=0.0)  # computed=5.0
    detection = bridge.detect_cost_spoofing("a1")
    assert detection["spoofing_suspected"] is True


def test_no_spoof() -> None:
    bridge = BudgetBridge()
    computed = bridge.compute_cost("gpt-4o-mini", 1000, 1000)
    bridge.record_usage("a1", "gpt-4o-mini", 1000, 1000, reported_cost_usd=computed)
    detection = bridge.detect_cost_spoofing("a1")
    assert detection["spoofing_suspected"] is False


def test_spoof_threshold() -> None:
    bridge = BudgetBridge(spoof_threshold=0.5)
    computed = bridge.compute_cost("gpt-4o", 1000, 500)
    bridge.record_usage("a1", "gpt-4o", 1000, 500, reported_cost_usd=computed * 0.8)
    detection = bridge.detect_cost_spoofing("a1")
    assert detection["spoofing_suspected"] is False


def test_fleet_summary() -> None:
    bridge = BudgetBridge()
    bridge.record_usage("a1", "gpt-4o-mini", 1000, 1000)
    bridge.record_usage("a2", "gpt-4o-mini", 1000, 1000)
    bridge.record_usage("a3", "gpt-4o-mini", 1000, 1000)
    summary = bridge.get_fleet_summary()
    assert summary["agent_count"] == 3
    assert set(summary["agents"]) == {"a1", "a2", "a3"}


def test_get_status() -> None:
    bridge = BudgetBridge(daily_limit_default=1.0)
    bridge.record_usage("a1", "gpt-4o-mini", 1000, 1000, reported_cost_usd=0.0)
    bridge.record_usage("a1", "gpt-4o-mini", 2000, 2000, reported_cost_usd=0.0)
    status = bridge.get_status("a1")
    assert status.agent_id == "a1"
    assert status.request_count == 2
    assert status.total_tokens == 6000
    assert status.total_cost_usd > 0.0
    assert status.cost_discrepancy_total > 0.0
