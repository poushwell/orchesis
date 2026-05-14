from __future__ import annotations

from orchesis.cost_optimizer import CostOptimizer


def test_dedup_removes_duplicate_system_content() -> None:
    opt = CostOptimizer({"strategies": ["dedup_system_prompt"]})
    messages = [
        {"role": "system", "content": "rules"},
        {"role": "system", "content": "rules"},
        {"role": "user", "content": "hello"},
    ]
    out = opt.dedup_system_prompt(messages)
    assert len([m for m in out if m.get("role") == "system"]) == 1


def test_whitespace_trimmed() -> None:
    opt = CostOptimizer({"strategies": ["trim_whitespace"]})
    out = opt.trim_whitespace([{"role": "user", "content": "  a   b \n  c  "}])
    assert out[0]["content"] == "a b c"


def test_tool_results_compressed() -> None:
    opt = CostOptimizer({"tool_result_max_chars": 20, "strategies": ["compress_tool_results"]})
    out = opt.compress_tool_results([{"role": "tool", "content": "x" * 60, "tool_call_id": "t1"}])
    assert len(out[0]["content"]) < 60
    assert "truncated" in out[0]["content"]


def test_old_turns_pruned() -> None:
    opt = CostOptimizer({"max_assistant_turns": 2, "strategies": ["prune_old_assistant"]})
    messages = [{"role": "assistant", "content": str(i)} for i in range(5)]
    out = opt.prune_old_assistant_turns(messages)
    assert len(out) == 2
    assert out[0]["content"] == "3"
    assert out[1]["content"] == "4"


def test_savings_tracked_per_strategy() -> None:
    opt = CostOptimizer({"strategies": ["trim_whitespace"]})
    messages = [{"role": "user", "content": "a    b     c"}]
    _ = opt.optimize(messages)
    report = opt.get_savings_report()
    assert report.get("trim_whitespace", 0) >= 0


def test_optimize_returns_stats() -> None:
    opt = CostOptimizer({})
    out, stats = opt.optimize([{"role": "user", "content": " hello   world "}])
    assert isinstance(out, list)
    assert "original_tokens" in stats
    assert "optimized_tokens" in stats
    assert "savings" in stats
    assert "strategies_applied" in stats


def test_token_estimation_reasonable() -> None:
    opt = CostOptimizer({})
    a = opt.estimate_tokens([{"role": "user", "content": "a " * 20}])
    b = opt.estimate_tokens([{"role": "user", "content": "a " * 200}])
    assert a > 0
    assert b > a


def test_empty_messages_safe() -> None:
    opt = CostOptimizer({})
    out, stats = opt.optimize([])
    assert out == []
    assert stats["original_tokens"] == 0
    assert stats["optimized_tokens"] == 0
