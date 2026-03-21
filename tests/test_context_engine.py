"""Tests for Context Engine — intelligent context window management."""

from __future__ import annotations

import os
import threading
from typing import Any

import pytest

from orchesis.context_engine import (
    ContextConfig,
    ContextEngine,
    ContextResult,
)

CI_MULTIPLIER = 5.0 if os.getenv("CI") else 1.0


# --- Dedup Strategy (8 tests) ---


def test_dedup_consecutive_identical() -> None:
    """Two same messages → one."""
    cfg = ContextConfig(enabled=True, strategies=["dedup"])
    engine = ContextEngine(cfg)
    msgs = [
        {"role": "user", "content": "hello"},
        {"role": "user", "content": "hello"},
    ]
    result = engine.optimize(msgs)
    assert len(result.messages) == 1
    assert result.messages[0]["content"] == "hello"
    assert "dedup" in result.strategies_applied


def test_dedup_non_consecutive_no_removal() -> None:
    """Same message far apart (beyond dedup_window) → both kept."""
    cfg = ContextConfig(enabled=True, strategies=["dedup"], dedup_window=2)
    engine = ContextEngine(cfg)
    msgs = [
        {"role": "user", "content": "hello"},
        {"role": "assistant", "content": "m1"},
        {"role": "user", "content": "m2"},
        {"role": "assistant", "content": "m3"},
        {"role": "user", "content": "hello"},
    ]
    result = engine.optimize(msgs)
    assert len(result.messages) == 5


def test_dedup_preserves_system() -> None:
    """System messages never deduped."""
    cfg = ContextConfig(enabled=True, strategies=["dedup"])
    engine = ContextEngine(cfg)
    msgs = [
        {"role": "system", "content": "You are helpful"},
        {"role": "system", "content": "You are helpful"},
    ]
    result = engine.optimize(msgs)
    assert len(result.messages) == 2
    assert result.messages[0]["role"] == "system"
    assert result.messages[1]["role"] == "system"


def test_dedup_different_roles_kept() -> None:
    """Same content, different role → both kept."""
    cfg = ContextConfig(enabled=True, strategies=["dedup"])
    engine = ContextEngine(cfg)
    msgs = [
        {"role": "user", "content": "hello"},
        {"role": "assistant", "content": "hello"},
    ]
    result = engine.optimize(msgs)
    assert len(result.messages) == 2
    assert result.messages[0]["role"] == "user"
    assert result.messages[1]["role"] == "assistant"


def test_dedup_content_list_format() -> None:
    """Anthropic content blocks deduped correctly."""
    cfg = ContextConfig(enabled=True, strategies=["dedup"])
    engine = ContextEngine(cfg)
    block = [{"type": "text", "text": "same"}]
    msgs = [
        {"role": "user", "content": block},
        {"role": "user", "content": block},
    ]
    result = engine.optimize(msgs)
    assert len(result.messages) == 1


def test_dedup_empty_messages() -> None:
    """Empty list → empty list."""
    cfg = ContextConfig(enabled=True, strategies=["dedup"])
    engine = ContextEngine(cfg)
    result = engine.optimize([])
    assert result.messages == []
    assert result.original_count == 0
    assert result.final_count == 0


def test_dedup_window_limit() -> None:
    """Beyond dedup_window → no dedup for far-apart duplicates."""
    cfg = ContextConfig(enabled=True, strategies=["dedup"], dedup_window=2)
    engine = ContextEngine(cfg)
    msgs = [
        {"role": "user", "content": "a"},
        {"role": "user", "content": "b"},
        {"role": "user", "content": "c"},
        {"role": "user", "content": "a"},
    ]
    result = engine.optimize(msgs)
    assert len(result.messages) >= 3


def test_dedup_single_message() -> None:
    """One message → unchanged."""
    cfg = ContextConfig(enabled=True, strategies=["dedup"])
    engine = ContextEngine(cfg)
    msgs = [{"role": "user", "content": "hello"}]
    result = engine.optimize(msgs)
    assert len(result.messages) == 1
    assert result.messages[0]["content"] == "hello"


def test_dedup_large_window_performance() -> None:
    """Dedup should handle large batches without quadratic slowdowns."""
    import time

    engine = ContextEngine(ContextConfig(enabled=True, strategies=["dedup"], dedup_window=50))
    messages = [{"role": "user", "content": f"msg {i}"} for i in range(1000)]
    for i in range(0, 1000, 7):
        messages[i] = {"role": "user", "content": f"msg {i % 50}"}
    start = time.monotonic()
    result = engine.optimize(messages)
    elapsed = time.monotonic() - start
    assert elapsed < 1.0 * CI_MULTIPLIER
    assert len(result.messages) < len(messages)


def test_dedup_window_boundary() -> None:
    """Message outside window should not be considered duplicate."""
    engine = ContextEngine(ContextConfig(enabled=True, strategies=["dedup"], dedup_window=3))
    messages = [
        {"role": "user", "content": "hello"},
        {"role": "user", "content": "world"},
        {"role": "user", "content": "foo"},
        {"role": "user", "content": "bar"},
        {"role": "user", "content": "hello"},
    ]
    result = engine.optimize(messages)
    assert len(result.messages) == 5


def test_dedup_within_window() -> None:
    """Message within window should be deduped."""
    engine = ContextEngine(ContextConfig(enabled=True, strategies=["dedup"], dedup_window=5))
    messages = [
        {"role": "user", "content": "hello"},
        {"role": "user", "content": "world"},
        {"role": "user", "content": "hello"},
    ]
    result = engine.optimize(messages)
    assert len(result.messages) == 2


# --- System Dups Strategy (5 tests) ---


def test_trim_system_dups_identical() -> None:
    """Two identical system → first kept."""
    cfg = ContextConfig(enabled=True, strategies=["trim_system_dups"])
    engine = ContextEngine(cfg)
    msgs = [
        {"role": "system", "content": "Be helpful"},
        {"role": "system", "content": "Be helpful"},
    ]
    result = engine.optimize(msgs)
    assert len(result.messages) == 1
    assert result.messages[0]["content"] == "Be helpful"
    assert "trim_system_dups" in result.strategies_applied


def test_trim_system_dups_different() -> None:
    """Different system messages → both kept."""
    cfg = ContextConfig(enabled=True, strategies=["trim_system_dups"])
    engine = ContextEngine(cfg)
    msgs = [
        {"role": "system", "content": "Be helpful"},
        {"role": "system", "content": "Be concise"},
    ]
    result = engine.optimize(msgs)
    assert len(result.messages) == 2


def test_trim_system_dups_multiple() -> None:
    """3 identical → first kept only."""
    cfg = ContextConfig(enabled=True, strategies=["trim_system_dups"])
    engine = ContextEngine(cfg)
    msgs = [
        {"role": "system", "content": "X"},
        {"role": "system", "content": "X"},
        {"role": "system", "content": "X"},
    ]
    result = engine.optimize(msgs)
    assert len(result.messages) == 1


def test_trim_system_dups_mixed() -> None:
    """System among user/assistant → correct removal."""
    cfg = ContextConfig(enabled=True, strategies=["trim_system_dups"])
    engine = ContextEngine(cfg)
    msgs = [
        {"role": "system", "content": "S1"},
        {"role": "user", "content": "u1"},
        {"role": "system", "content": "S1"},
        {"role": "assistant", "content": "a1"},
    ]
    result = engine.optimize(msgs)
    assert len(result.messages) == 3
    system_contents = [m["content"] for m in result.messages if m["role"] == "system"]
    assert system_contents == ["S1"]


def test_trim_system_dups_none() -> None:
    """No system messages → unchanged."""
    cfg = ContextConfig(enabled=True, strategies=["trim_system_dups"])
    engine = ContextEngine(cfg)
    msgs = [
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": "hello"},
    ]
    result = engine.optimize(msgs)
    assert len(result.messages) == 2


# --- Tool Result Trimming (10 tests) ---


def test_trim_tool_result_short() -> None:
    """Below threshold → unchanged."""
    cfg = ContextConfig(enabled=True, strategies=["trim_tool_results"], max_tool_result_tokens=2000)
    engine = ContextEngine(cfg)
    short = "x" * 100
    msgs = [{"role": "tool", "content": short}]
    result = engine.optimize(msgs)
    assert result.messages[0]["content"] == short
    assert "trim_tool_results" not in result.strategies_applied


def test_trim_tool_result_long() -> None:
    """Above threshold → truncated with marker."""
    cfg = ContextConfig(enabled=True, strategies=["trim_tool_results"], max_tool_result_tokens=100)
    engine = ContextEngine(cfg)
    long_content = "x" * 10000
    msgs = [{"role": "tool", "content": long_content}]
    result = engine.optimize(msgs)
    content = result.messages[0]["content"]
    assert len(content) < len(long_content)
    assert "truncated by Orchesis" in content
    assert "trim_tool_results" in result.strategies_applied


def test_trim_tool_result_marker_contains_saved_count() -> None:
    """Marker shows tokens saved."""
    cfg = ContextConfig(enabled=True, strategies=["trim_tool_results"], max_tool_result_tokens=50)
    engine = ContextEngine(cfg)
    long_content = "x" * 5000
    msgs = [{"role": "tool", "content": long_content}]
    result = engine.optimize(msgs)
    content = result.messages[0]["content"]
    assert "tokens saved" in content


def test_trim_tool_result_anthropic_format() -> None:
    """Content blocks with tool_result type."""
    cfg = ContextConfig(enabled=True, strategies=["trim_tool_results"], max_tool_result_tokens=50)
    engine = ContextEngine(cfg)
    long_text = "y" * 5000
    msgs = [
        {
            "role": "user",
            "content": [{"type": "tool_result", "content": long_text}],
        }
    ]
    result = engine.optimize(msgs)
    blocks = result.messages[0]["content"]
    assert isinstance(blocks, list)
    text = blocks[0].get("content", blocks[0].get("text", ""))
    assert "truncated" in text or len(text) < len(long_text)


def test_trim_tool_result_openai_format() -> None:
    """role=='tool' messages."""
    cfg = ContextConfig(enabled=True, strategies=["trim_tool_results"], max_tool_result_tokens=50)
    engine = ContextEngine(cfg)
    long_content = "z" * 5000
    msgs = [{"role": "tool", "content": long_content}]
    result = engine.optimize(msgs)
    assert "truncated" in result.messages[0]["content"]


def test_trim_multiple_tools() -> None:
    """Several tools, only long ones trimmed."""
    cfg = ContextConfig(enabled=True, strategies=["trim_tool_results"], max_tool_result_tokens=100)
    engine = ContextEngine(cfg)
    short = "a" * 100
    long_content = "b" * 5000
    msgs = [
        {"role": "tool", "content": short},
        {"role": "tool", "content": long_content},
    ]
    result = engine.optimize(msgs)
    assert result.messages[0]["content"] == short
    assert "truncated" in result.messages[1]["content"]


def test_trim_preserves_non_tool() -> None:
    """User/assistant messages untouched."""
    cfg = ContextConfig(enabled=True, strategies=["trim_tool_results"], max_tool_result_tokens=50)
    engine = ContextEngine(cfg)
    long_user = "x" * 10000
    msgs = [{"role": "user", "content": long_user}]
    result = engine.optimize(msgs)
    assert result.messages[0]["content"] == long_user


def test_trim_exact_threshold() -> None:
    """At exactly max_tool_result_tokens → no trim."""
    cfg = ContextConfig(enabled=True, strategies=["trim_tool_results"], max_tool_result_tokens=100)
    engine = ContextEngine(cfg)
    exact = "x" * 400
    msgs = [{"role": "tool", "content": exact}]
    result = engine.optimize(msgs)
    assert result.messages[0]["content"] == exact


def test_compress_very_long_output() -> None:
    """4x threshold → head+tail preserved."""
    cfg = ContextConfig(
        enabled=True,
        strategies=["compress_tool_outputs"],
        max_tool_result_tokens=500,
    )
    engine = ContextEngine(cfg)
    head = "HEAD" * 100
    tail = "TAIL" * 100
    mid = "M" * 10000
    long_content = head + mid + tail
    msgs = [{"role": "tool", "content": long_content}]
    result = engine.optimize(msgs)
    content = result.messages[0]["content"]
    assert "HEAD" in content or "middle section removed" in content
    assert "compress_tool_outputs" in result.strategies_applied


def test_compress_preserves_boundaries() -> None:
    """First 500 + last 500 tokens intact."""
    cfg = ContextConfig(
        enabled=True,
        strategies=["compress_tool_outputs"],
        max_tool_result_tokens=500,
    )
    engine = ContextEngine(cfg)
    head = "START_" * 200
    tail = "_END" * 200
    mid = "X" * 15000
    long_content = head + mid + tail
    msgs = [{"role": "tool", "content": long_content}]
    result = engine.optimize(msgs)
    content = result.messages[0]["content"]
    assert "START_" in content
    assert "_END" in content or "middle section" in content


# --- Sliding Window (7 tests) ---


def test_sliding_window_basic() -> None:
    """20 messages, window=10 → 10 kept."""
    cfg = ContextConfig(
        enabled=True,
        strategies=["sliding_window"],
        sliding_window_size=10,
    )
    engine = ContextEngine(cfg)
    msgs = [{"role": "user", "content": f"msg{i}"} for i in range(20)]
    result = engine.optimize(msgs)
    assert len(result.messages) == 10
    assert result.messages[0]["content"] == "msg10"
    assert result.messages[-1]["content"] == "msg19"


def test_sliding_window_preserves_system() -> None:
    """System messages always kept."""
    cfg = ContextConfig(
        enabled=True,
        strategies=["sliding_window"],
        sliding_window_size=3,
        preserve_system=True,
    )
    engine = ContextEngine(cfg)
    msgs = [
        {"role": "system", "content": "S"},
        {"role": "user", "content": "u1"},
        {"role": "user", "content": "u2"},
        {"role": "user", "content": "u3"},
        {"role": "user", "content": "u4"},
    ]
    result = engine.optimize(msgs)
    assert any(m["role"] == "system" for m in result.messages)
    system_msgs = [m for m in result.messages if m["role"] == "system"]
    assert len(system_msgs) == 1
    assert system_msgs[0]["content"] == "S"


def test_sliding_window_disabled() -> None:
    """window=0 → no change."""
    cfg = ContextConfig(
        enabled=True,
        strategies=["sliding_window"],
        sliding_window_size=0,
    )
    engine = ContextEngine(cfg)
    msgs = [{"role": "user", "content": f"m{i}"} for i in range(10)]
    result = engine.optimize(msgs)
    assert len(result.messages) == 10


def test_sliding_window_smaller_than_messages() -> None:
    """Fewer messages than window → all kept."""
    cfg = ContextConfig(
        enabled=True,
        strategies=["sliding_window"],
        sliding_window_size=100,
    )
    engine = ContextEngine(cfg)
    msgs = [{"role": "user", "content": f"m{i}"} for i in range(5)]
    result = engine.optimize(msgs)
    assert len(result.messages) == 5


def test_sliding_window_order_preserved() -> None:
    """Output in correct chronological order."""
    cfg = ContextConfig(
        enabled=True,
        strategies=["sliding_window"],
        sliding_window_size=3,
    )
    engine = ContextEngine(cfg)
    msgs = [
        {"role": "user", "content": "a"},
        {"role": "assistant", "content": "b"},
        {"role": "user", "content": "c"},
        {"role": "assistant", "content": "d"},
    ]
    result = engine.optimize(msgs)
    assert [m["content"] for m in result.messages] == ["b", "c", "d"]


def test_sliding_window_system_plus_recent() -> None:
    """System + last N-system_count non-system."""
    cfg = ContextConfig(
        enabled=True,
        strategies=["sliding_window"],
        sliding_window_size=4,
        preserve_system=True,
    )
    engine = ContextEngine(cfg)
    msgs = [
        {"role": "system", "content": "S"},
        {"role": "user", "content": "u1"},
        {"role": "user", "content": "u2"},
        {"role": "user", "content": "u3"},
        {"role": "user", "content": "u4"},
    ]
    result = engine.optimize(msgs)
    assert len(result.messages) == 4
    assert result.messages[0]["role"] == "system"
    contents = [m["content"] for m in result.messages]
    assert "u2" in contents and "u3" in contents and "u4" in contents


def test_sliding_window_all_system() -> None:
    """All system messages → all kept."""
    cfg = ContextConfig(
        enabled=True,
        strategies=["sliding_window"],
        sliding_window_size=2,
        preserve_system=True,
    )
    engine = ContextEngine(cfg)
    msgs = [
        {"role": "system", "content": "S1"},
        {"role": "system", "content": "S2"},
    ]
    result = engine.optimize(msgs)
    assert len(result.messages) == 2


# --- Token Budget (8 tests) ---


def test_budget_within_limit() -> None:
    """Already fits → unchanged."""
    cfg = ContextConfig(
        enabled=True,
        strategies=["token_budget"],
        max_context_tokens=100000,
        token_budget_reserve=0,
    )
    engine = ContextEngine(cfg)
    msgs = [{"role": "user", "content": "short"}]
    result = engine.optimize(msgs, max_tokens=100000)
    assert len(result.messages) == 1


def test_budget_removes_oldest_first() -> None:
    """Oldest non-system removed first."""
    cfg = ContextConfig(
        enabled=True,
        strategies=["token_budget"],
        max_context_tokens=1000,
        token_budget_reserve=0,
    )
    engine = ContextEngine(cfg)
    msgs = [
        {"role": "user", "content": "x" * 200},
        {"role": "assistant", "content": "y" * 200},
        {"role": "user", "content": "z" * 200},
    ]
    result = engine.optimize(msgs, max_tokens=100)
    assert len(result.messages) < 3 or result.final_tokens <= 100


def test_budget_preserves_system() -> None:
    """System messages never removed."""
    cfg = ContextConfig(
        enabled=True,
        strategies=["token_budget"],
        max_context_tokens=50,
        token_budget_reserve=0,
    )
    engine = ContextEngine(cfg)
    msgs = [
        {"role": "system", "content": "S" * 100},
        {"role": "user", "content": "u" * 100},
    ]
    result = engine.optimize(msgs, max_tokens=100)
    assert any(m["role"] == "system" for m in result.messages)


def test_budget_preserves_last_user() -> None:
    """Last user message never removed."""
    cfg = ContextConfig(
        enabled=True,
        strategies=["token_budget"],
        max_context_tokens=30,
        token_budget_reserve=0,
    )
    engine = ContextEngine(cfg)
    msgs = [
        {"role": "user", "content": "first"},
        {"role": "assistant", "content": "mid"},
        {"role": "user", "content": "last"},
    ]
    result = engine.optimize(msgs, max_tokens=50)
    user_contents = [m["content"] for m in result.messages if m["role"] == "user"]
    assert "last" in user_contents


def test_budget_with_reserve() -> None:
    """Budget accounts for response reserve."""
    cfg = ContextConfig(
        enabled=True,
        strategies=["token_budget"],
        max_context_tokens=1000,
        token_budget_reserve=500,
    )
    engine = ContextEngine(cfg)
    msgs = [
        {"role": "user", "content": "x" * 2000},
        {"role": "assistant", "content": "y" * 2000},
        {"role": "user", "content": "z"},
    ]
    result = engine.optimize(msgs, max_tokens=1000)
    assert result.final_tokens <= 500


def test_budget_zero_disabled() -> None:
    """budget=0 → no trimming."""
    cfg = ContextConfig(
        enabled=True,
        strategies=["token_budget"],
        max_context_tokens=0,
    )
    engine = ContextEngine(cfg)
    msgs = [{"role": "user", "content": "x" * 10000}]
    result = engine.optimize(msgs, max_tokens=0)
    assert len(result.messages) == 1


def test_budget_extreme_over() -> None:
    """Way over budget → trims to minimum (preserving last user)."""
    cfg = ContextConfig(
        enabled=True,
        strategies=["token_budget"],
        max_context_tokens=20,
        token_budget_reserve=0,
    )
    engine = ContextEngine(cfg)
    msgs = [
        {"role": "user", "content": "x" * 500},
        {"role": "assistant", "content": "y" * 500},
        {"role": "user", "content": "z" * 500},
    ]
    result = engine.optimize(msgs, max_tokens=50)
    assert len(result.messages) == 1
    assert "token_budget" in result.strategies_applied
    assert result.final_tokens < result.original_tokens


def test_budget_single_message() -> None:
    """One message over budget → kept (can't remove)."""
    cfg = ContextConfig(
        enabled=True,
        strategies=["token_budget"],
        max_context_tokens=10,
        token_budget_reserve=0,
    )
    engine = ContextEngine(cfg)
    msgs = [{"role": "user", "content": "x" * 1000}]
    result = engine.optimize(msgs, max_tokens=50)
    assert len(result.messages) == 1


# --- Token Estimation (5 tests) ---


def test_estimate_tokens_string() -> None:
    """'hello world' → ~3 tokens."""
    est = ContextEngine._estimate_tokens([{"role": "user", "content": "hello world"}])
    assert 2 <= est <= 6


def test_estimate_tokens_content_blocks() -> None:
    """List content → correct sum."""
    msgs = [
        {
            "role": "user",
            "content": [{"type": "text", "text": "a" * 40}, {"type": "text", "text": "b" * 40}],
        }
    ]
    est = ContextEngine._estimate_tokens(msgs)
    assert est >= 20


def test_estimate_tokens_empty() -> None:
    """Empty messages → 0."""
    assert ContextEngine._estimate_tokens([]) == 0


def test_estimate_tokens_overhead() -> None:
    """Includes per-message overhead."""
    est_one = ContextEngine._estimate_tokens([{"role": "user", "content": ""}])
    est_three = ContextEngine._estimate_tokens(
        [{"role": "user", "content": ""}, {"role": "assistant", "content": ""}, {"role": "user", "content": ""}]
    )
    assert est_three > est_one


def test_hash_message_deterministic() -> None:
    """Same message → same hash."""
    msg = {"role": "user", "content": "hello"}
    h1 = ContextEngine._hash_message(msg)
    h2 = ContextEngine._hash_message(msg)
    assert h1 == h2
    assert len(h1) == 64


# --- Integration (7 tests) ---


def test_optimize_multiple_strategies() -> None:
    """Dedup + trim applied together."""
    cfg = ContextConfig(
        enabled=True,
        strategies=["dedup", "trim_tool_results"],
        max_tool_result_tokens=100,
    )
    engine = ContextEngine(cfg)
    msgs = [
        {"role": "user", "content": "hi"},
        {"role": "user", "content": "hi"},
        {"role": "tool", "content": "x" * 5000},
    ]
    result = engine.optimize(msgs)
    assert len(result.messages) <= 3
    assert len(result.strategies_applied) >= 1


def test_optimize_disabled() -> None:
    """Engine disabled → passthrough."""
    cfg = ContextConfig(enabled=False, strategies=["dedup"])
    engine = ContextEngine(cfg)
    msgs = [
        {"role": "user", "content": "a"},
        {"role": "user", "content": "a"},
    ]
    result = engine.optimize(msgs)
    assert len(result.messages) == 2
    assert result.strategies_applied == []


def test_optimize_empty_messages() -> None:
    """Empty list → no crash."""
    cfg = ContextConfig(enabled=True, strategies=["dedup"])
    engine = ContextEngine(cfg)
    result = engine.optimize([])
    assert result.messages == []
    assert result.original_count == 0
    assert result.final_count == 0


def test_result_metrics_correct() -> None:
    """tokens_saved, counts correct."""
    cfg = ContextConfig(enabled=True, strategies=["trim_tool_results"], max_tool_result_tokens=50)
    engine = ContextEngine(cfg)
    long_content = "x" * 5000
    msgs = [{"role": "tool", "content": long_content}]
    result = engine.optimize(msgs)
    assert result.original_count == 1
    assert result.final_count == 1
    assert result.tokens_saved > 0
    assert result.original_tokens > result.final_tokens


def test_get_stats_accumulation() -> None:
    """Stats increment across calls."""
    cfg = ContextConfig(enabled=True, strategies=["dedup"], track_savings=True)
    engine = ContextEngine(cfg)
    msgs = [{"role": "user", "content": "x"}, {"role": "user", "content": "x"}]
    engine.optimize(msgs)
    engine.optimize(msgs)
    stats = engine.get_stats()
    assert stats["total_optimizations"] >= 2
    assert stats.get("strategy_hits", {}).get("dedup", 0) >= 2


def test_thread_safe_optimize() -> None:
    """10 concurrent threads."""
    cfg = ContextConfig(enabled=True, strategies=["dedup"], track_savings=True)
    engine = ContextEngine(cfg)
    msgs = [{"role": "user", "content": "a"}, {"role": "user", "content": "a"}]
    results: list[ContextResult] = []

    def run() -> None:
        r = engine.optimize(msgs)
        results.append(r)

    threads = [threading.Thread(target=run) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 10
    for r in results:
        assert len(r.messages) == 1


def test_context_result_strategies_applied() -> None:
    """Tracks which strategies fired."""
    cfg = ContextConfig(enabled=True, strategies=["dedup", "trim_system_dups"])
    engine = ContextEngine(cfg)
    msgs = [
        {"role": "system", "content": "S"},
        {"role": "system", "content": "S"},
        {"role": "user", "content": "u"},
        {"role": "user", "content": "u"},
    ]
    result = engine.optimize(msgs)
    assert "dedup" in result.strategies_applied or "trim_system_dups" in result.strategies_applied


# --- Proxy Integration (5 tests) ---


def test_proxy_phase_context() -> None:
    """Messages modified before upstream."""
    from orchesis.config import load_policy
    from orchesis.proxy import LLMHTTPProxy
    from pathlib import Path

    base = Path(__file__).parent.parent
    policy_path = base / "examples" / "orchesis.yaml"
    if not policy_path.exists():
        policy_path = base / "orchesis.yaml"
    if not policy_path.exists():
        policy_path = base / "examples" / "policy.yaml"
    if not policy_path.exists():
        policy_path = base / "policy.yaml"
    if not policy_path.exists():
        pytest.skip("No policy yaml found")
    try:
        policy = load_policy(policy_path)
    except Exception:
        pytest.skip("Could not load policy")
    policy["context_engine"] = {
        "enabled": True,
        "strategies": ["dedup", "trim_tool_results"],
        "max_tool_result_tokens": 100,
    }
    proxy = LLMHTTPProxy(policy_path=None)
    proxy._policy = policy
    proxy._context_engine = ContextEngine(
        ContextConfig(
            enabled=True,
            strategies=["dedup", "trim_tool_results"],
            max_tool_result_tokens=100,
        )
    )
    from orchesis.proxy import _RequestContext
    from http.server import BaseHTTPRequestHandler

    class FakeHandler:
        pass

    ctx = _RequestContext(handler=FakeHandler(), body={"messages": [{"role": "user", "content": "x"}, {"role": "user", "content": "x"}]})
    ok = proxy._phase_context(ctx)
    assert ok is True
    assert len(ctx.body["messages"]) == 1


def test_proxy_context_headers() -> None:
    """X-Orchesis-Context-Tokens-Saved header set."""
    from orchesis.proxy import LLMHTTPProxy, _RequestContext
    from http.server import BaseHTTPRequestHandler

    class FakeHandler:
        pass

    proxy = LLMHTTPProxy(policy_path=None)
    proxy._context_engine = ContextEngine(
        ContextConfig(enabled=True, strategies=["trim_tool_results"], max_tool_result_tokens=50)
    )
    long_content = "x" * 5000
    ctx = _RequestContext(
        handler=FakeHandler(),
        body={"messages": [{"role": "tool", "content": long_content}], "model": "", "max_tokens": 0},
    )
    proxy._phase_context(ctx)
    assert ctx.context_tokens_saved > 0
    assert "trim_tool_results" in ctx.context_strategies


def test_proxy_context_disabled() -> None:
    """No context engine → passthrough."""
    from orchesis.proxy import LLMHTTPProxy, _RequestContext

    class FakeHandler:
        pass

    proxy = LLMHTTPProxy(policy_path=None)
    proxy._context_engine = None
    msgs = [{"role": "user", "content": "a"}, {"role": "user", "content": "a"}]
    ctx = _RequestContext(handler=FakeHandler(), body={"messages": msgs})
    ok = proxy._phase_context(ctx)
    assert ok is True
    assert ctx.body["messages"] == msgs


def test_proxy_context_stats() -> None:
    """Stats includes context_engine section."""
    from orchesis.proxy import LLMHTTPProxy

    proxy = LLMHTTPProxy(policy_path=None)
    proxy._context_engine = ContextEngine(ContextConfig(enabled=True, strategies=["dedup"]))
    stats = proxy.stats
    assert "context_engine" in stats
    assert "total_tokens_saved" in stats["context_engine"]


def test_config_normalization() -> None:
    """context_engine config validated."""
    from orchesis.config import load_policy
    from pathlib import Path
    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(
            """
context_engine:
  enabled: true
  strategies:
    - dedup
    - trim_tool_results
  max_context_tokens: 0
  token_budget_reserve: 4096
  sliding_window_size: 0
  preserve_system: true
  max_tool_result_tokens: 2000
  dedup_window: 50
  track_savings: true
"""
        )
        path = f.name
    try:
        policy = load_policy(path)
        assert "context_engine" in policy
        ce = policy["context_engine"]
        assert isinstance(ce, dict)
        assert ce.get("enabled") is True
        assert "dedup" in (ce.get("strategies") or [])
    finally:
        import os
        os.unlink(path)
