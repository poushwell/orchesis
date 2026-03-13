from __future__ import annotations

import threading

from orchesis.context_optimizer import ContextOptimizer


def _m(role: str, content: str, tool_calls=None):
    item = {"role": role, "content": content}
    if tool_calls is not None:
        item["tool_calls"] = tool_calls
    return item


def _openclaw_messages():
    system = "You are OpenClaw assistant. Follow policy."
    return [
        _m("system", system),
        _m("system", system),
        _m("user", "Please read README.md"),
        _m("assistant", "Sure, I'll do that."),
        _m("assistant", "Sure, I'll do that."),
        _m("assistant", "Calling tool", [{"name": "read_file", "arguments": '{"path":"README.md"}'}]),
        _m("tool", "README contents"),
        _m("assistant", "Done."),
    ]


# System prompt dedup
def test_dedup_single_system_unchanged() -> None:
    c = ContextOptimizer()
    msgs = [_m("system", "a"), _m("user", "b")]
    out, _ = c.optimize(msgs)
    assert len(out) == 2


def test_dedup_duplicate_system_keeps_first() -> None:
    c = ContextOptimizer()
    msgs = [_m("system", "same"), _m("system", "same"), _m("user", "x")]
    out, r = c.optimize(msgs)
    assert len([m for m in out if m["role"] == "system"]) == 1
    assert r.messages_removed >= 1


def test_dedup_different_systems_keeps_both() -> None:
    c = ContextOptimizer()
    msgs = [_m("system", "s1"), _m("system", "s2"), _m("user", "x")]
    out, _ = c.optimize(msgs)
    assert len([m for m in out if m["role"] == "system"]) == 2


def test_dedup_cached_across_calls() -> None:
    c = ContextOptimizer()
    msgs = [_m("system", "same"), _m("user", "x")]
    _, r1 = c.optimize(msgs, agent_id="a")
    _, r2 = c.optimize(msgs, agent_id="a")
    assert r1.system_prompt_cached is False
    assert r2.system_prompt_cached is True


def test_dedup_empty_system() -> None:
    c = ContextOptimizer()
    out, _ = c.optimize([_m("system", ""), _m("user", "x")])
    assert len(out) == 2


# Stale message removal
def test_stale_keeps_last_n() -> None:
    c = ContextOptimizer({"never_remove_last_n": 3, "stale_message_age": 3})
    msgs = [_m("user", "ok")] * 10
    out, _ = c.optimize(msgs)
    assert len(out) >= 3


def test_stale_keeps_system_always() -> None:
    c = ContextOptimizer({"stale_message_age": 1})
    msgs = [_m("system", "rule"), _m("user", "x"), _m("user", "y"), _m("user", "z")]
    out, _ = c.optimize(msgs)
    assert any(m["role"] == "system" for m in out)


def test_stale_removes_old_generic() -> None:
    c = ContextOptimizer({"stale_message_age": 2, "min_message_length": 10})
    msgs = [_m("user", "ok")] * 8 + [_m("assistant", "final")]
    out, r = c.optimize(msgs)
    assert r.messages_removed >= 1
    assert len(out) < len(msgs)


def test_stale_keeps_old_tool_chains() -> None:
    c = ContextOptimizer({"stale_message_age": 1})
    msgs = [
        _m("assistant", "call", [{"name": "read_file", "arguments": "{}"}]),
        _m("tool", "result"),
        _m("assistant", "ok"),
        _m("user", "later"),
    ]
    out, _ = c.optimize(msgs)
    assert any(m["role"] == "tool" for m in out)


def test_stale_keeps_code_blocks() -> None:
    c = ContextOptimizer({"stale_message_age": 1})
    msgs = [_m("user", "```python\nprint(1)\n```"), _m("assistant", "x"), _m("user", "y"), _m("assistant", "z")]
    out, _ = c.optimize(msgs)
    assert any("```" in m.get("content", "") for m in out)


def test_stale_preserves_tool_integrity() -> None:
    c = ContextOptimizer()
    msgs = [
        _m("assistant", "", [{"id": "x", "name": "read_file", "arguments": "{}"}]),
        _m("tool", "res"),
        _m("user", "continue"),
    ]
    out, _ = c.optimize(msgs)
    assert len(out) >= 2


def test_stale_short_conversation_no_removal() -> None:
    c = ContextOptimizer({"stale_message_age": 10})
    msgs = [_m("user", "a"), _m("assistant", "b")]
    out, r = c.optimize(msgs)
    assert len(out) == 2
    assert r.messages_removed == 0


# Tool definition dedup
def test_tools_first_request_unchanged() -> None:
    c = ContextOptimizer()
    tools = [{"name": "read_file", "schema": {"type": "object"}}]
    _, _ = c.optimize([_m("user", "x")], tools=tools, agent_id="a")
    assert c.get_stats()["tool_schema_repeats"] == 0


def test_tools_unchanged_tracked_in_stats() -> None:
    c = ContextOptimizer()
    tools = [{"name": "read_file"}]
    c.optimize([_m("user", "x")], tools=tools, agent_id="a")
    c.optimize([_m("user", "y")], tools=tools, agent_id="a")
    assert c.get_stats()["tool_schema_repeats"] >= 1


def test_tools_changed_tracked() -> None:
    c = ContextOptimizer()
    c.optimize([_m("user", "x")], tools=[{"name": "read_file"}], agent_id="a")
    c.optimize([_m("user", "x")], tools=[{"name": "write_file"}], agent_id="a")
    assert c.get_stats()["tool_schema_repeats"] == 0


# Ack removal
def test_ack_removes_short_filler() -> None:
    c = ContextOptimizer()
    msgs = [_m("user", "a"), _m("assistant", "Sure, I'll do that."), _m("assistant", "final answer with details")]
    out, r = c.optimize(msgs)
    assert r.messages_removed >= 1
    assert len(out) < len(msgs)


def test_ack_keeps_short_with_code() -> None:
    c = ContextOptimizer()
    msgs = [_m("assistant", "```js\n1\n```"), _m("assistant", "final")]
    out, _ = c.optimize(msgs)
    assert any("```" in m.get("content", "") for m in out)


def test_ack_keeps_short_with_numbers() -> None:
    c = ContextOptimizer()
    msgs = [_m("assistant", "Step 1"), _m("assistant", "final long answer goes here")]
    out, _ = c.optimize(msgs)
    assert any("Step 1" in m.get("content", "") for m in out)


def test_ack_keeps_last_assistant() -> None:
    c = ContextOptimizer()
    msgs = [_m("assistant", "Understood.")]
    out, _ = c.optimize(msgs)
    assert len(out) == 1


def test_ack_single_assistant_kept() -> None:
    c = ContextOptimizer()
    out, _ = c.optimize([_m("assistant", "OK, let me help.")])
    assert len(out) == 1


def test_ack_long_message_kept() -> None:
    c = ContextOptimizer()
    long_msg = " ".join(["word"] * 40)
    out, _ = c.optimize([_m("assistant", long_msg), _m("assistant", "final response is substantial too")])
    assert any(m.get("content", "") == long_msg for m in out)


# Consecutive merging
def test_merge_two_user_messages() -> None:
    c = ContextOptimizer()
    out, r = c.optimize([_m("user", "a"), _m("user", "b"), _m("assistant", "c")])
    assert r.messages_merged >= 1
    assert len(out) == 2


def test_merge_two_assistant_messages() -> None:
    c = ContextOptimizer()
    out, _ = c.optimize([_m("assistant", "a"), _m("assistant", "b"), _m("user", "c")])
    assert len(out) == 2


def test_merge_three_consecutive() -> None:
    c = ContextOptimizer()
    out, r = c.optimize([_m("user", "1"), _m("user", "2"), _m("user", "3"), _m("assistant", "x")])
    assert r.messages_merged >= 2
    assert len(out) == 2


def test_merge_different_roles_no_merge() -> None:
    c = ContextOptimizer()
    out, r = c.optimize([_m("user", "1"), _m("assistant", "2"), _m("user", "3")])
    assert r.messages_merged == 0
    assert len(out) == 3


def test_merge_tool_calls_no_merge() -> None:
    c = ContextOptimizer()
    out, r = c.optimize([_m("assistant", "a", [{"name": "x"}]), _m("assistant", "b"), _m("user", "c")])
    assert r.messages_merged == 0
    assert len(out) == 3


def test_merge_preserves_order() -> None:
    c = ContextOptimizer()
    out, _ = c.optimize([_m("user", "first"), _m("user", "second"), _m("assistant", "third")])
    assert "first" in out[0]["content"]
    assert "second" in out[0]["content"]
    assert out[1]["role"] == "assistant"


# Token estimation
def test_estimate_empty() -> None:
    c = ContextOptimizer()
    assert c.estimate_tokens([]) == 0


def test_estimate_short_message() -> None:
    c = ContextOptimizer()
    assert c.estimate_tokens([_m("user", "hello world")]) > 0


def test_estimate_with_tools() -> None:
    c = ContextOptimizer()
    t1 = c.estimate_tokens([_m("user", "hello")], tools=None)
    t2 = c.estimate_tokens([_m("user", "hello")], tools=[{"name": "read_file", "schema": {"a": 1}}])
    assert t2 > t1


def test_estimate_model_specific() -> None:
    c = ContextOptimizer()
    a = c.estimate_tokens([_m("user", "x" * 100)], model="claude-sonnet-4-20250514")
    b = c.estimate_tokens([_m("user", "x" * 100)], model="gpt-4o-mini")
    assert a != b


# Full pipeline
def test_optimize_normal_conversation() -> None:
    c = ContextOptimizer()
    msgs = [_m("system", "policy"), _m("user", "hello"), _m("assistant", "normal response with details")]
    _, r = c.optimize(msgs)
    assert r.savings_percent >= 0.0


def test_optimize_openclaw_pattern() -> None:
    c = ContextOptimizer({"stale_message_age": 2})
    out, r = c.optimize(_openclaw_messages(), agent_id="openclaw")
    assert r.savings_percent >= 20.0
    assert len(out) <= len(_openclaw_messages())


def test_optimize_long_session() -> None:
    c = ContextOptimizer({"stale_message_age": 4})
    msgs = [_m("system", "rules")] + [_m("user" if i % 2 == 0 else "assistant", "ok") for i in range(30)]
    out, _ = c.optimize(msgs)
    assert len(out) >= 3


def test_optimize_preserves_tool_chains() -> None:
    c = ContextOptimizer({"stale_message_age": 1})
    msgs = [
        _m("assistant", "", [{"id": "x1", "type": "function", "function": {"name": "read_file", "arguments": "{}"}}]),
        {"role": "tool", "tool_call_id": "x1", "content": "result"},
        _m("assistant", "final"),
    ]
    out, _ = c.optimize(msgs)
    assert any(m.get("role") == "tool" for m in out)


def test_optimize_never_mutates_input() -> None:
    c = ContextOptimizer()
    msgs = _openclaw_messages()
    snapshot = [dict(m) for m in msgs]
    _ = c.optimize(msgs)
    assert msgs == snapshot


def test_optimize_result_stats_correct() -> None:
    c = ContextOptimizer()
    _, r = c.optimize(_openclaw_messages(), agent_id="a")
    assert r.original_tokens >= r.optimized_tokens
    assert isinstance(r.optimizations_applied, list)


def test_optimize_disabled_strategies_skip() -> None:
    c = ContextOptimizer(
        {
            "dedup_system_prompt": False,
            "remove_stale_messages": False,
            "dedup_tool_definitions": False,
            "remove_ack_messages": False,
            "merge_consecutive": False,
        }
    )
    msgs = _openclaw_messages()
    out, r = c.optimize(msgs)
    assert len(out) == len(msgs)
    assert r.messages_removed == 0


# OpenClaw scenarios
def test_openclaw_repeated_system_50pct_savings() -> None:
    c = ContextOptimizer()
    system = "x" * 6000
    msgs = [_m("system", system), _m("system", system), _m("system", system), _m("user", "run"), _m("assistant", "ok")]
    _, r = c.optimize(msgs)
    assert r.savings_percent >= 40.0


def test_openclaw_cron_accumulation() -> None:
    c = ContextOptimizer({"stale_message_age": 3})
    msgs = [_m("system", "policy")] + [_m("assistant", "ok")] * 15 + [_m("user", "final"), _m("assistant", "final answer")]
    out, r = c.optimize(msgs)
    assert len(out) < len(msgs)
    assert r.messages_removed >= 1


def test_openclaw_multi_turn_with_tools_safe() -> None:
    c = ContextOptimizer({"stale_message_age": 2})
    msgs = [
        _m("system", "policy"),
        _m("assistant", "call", [{"id": "1", "type": "function", "function": {"name": "read_file", "arguments": "{}"}}]),
        {"role": "tool", "tool_call_id": "1", "content": "tool output"},
        _m("assistant", "done"),
        _m("user", "continue"),
    ]
    out, _ = c.optimize(msgs)
    assert any(m.get("role") == "tool" for m in out)


def test_openclaw_preset_compatible() -> None:
    c = ContextOptimizer()
    msgs = [_m("system", "openclaw policy"), _m("user", "status"), _m("assistant", "ok")]
    out, _ = c.optimize(msgs, model="gpt-4o-mini", tools=[{"name": "session_status"}], agent_id="openclaw")
    assert out


# Edge cases
def test_empty_messages() -> None:
    c = ContextOptimizer()
    out, r = c.optimize([])
    assert out == []
    assert r.original_tokens == 0


def test_single_message() -> None:
    c = ContextOptimizer()
    out, _ = c.optimize([_m("user", "hello")])
    assert len(out) == 1


def test_only_system_prompt() -> None:
    c = ContextOptimizer()
    out, _ = c.optimize([_m("system", "policy"), _m("system", "policy")])
    assert len(out) == 1


def test_thread_safety() -> None:
    c = ContextOptimizer()
    errors = []

    def worker():
        try:
            for _ in range(40):
                c.optimize(_openclaw_messages(), agent_id="a")
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


def test_stats_accumulate() -> None:
    c = ContextOptimizer()
    c.optimize(_openclaw_messages(), agent_id="a")
    c.optimize(_openclaw_messages(), agent_id="a")
    stats = c.get_stats()
    assert stats["requests_optimized"] == 2
    assert stats["total_original_tokens"] >= stats["total_optimized_tokens"]


def test_reset_stats() -> None:
    c = ContextOptimizer()
    c.optimize(_openclaw_messages(), agent_id="a")
    c.reset_stats()
    stats = c.get_stats()
    assert stats["requests_optimized"] == 0
