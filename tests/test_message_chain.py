from __future__ import annotations

import threading

from orchesis.message_chain import (
    extract_tool_call_ids,
    extract_tool_result_id,
    find_tool_chain_groups,
    handle_failed_tool_chain,
    truncate_messages_safe,
    validate_tool_chain,
)


def _assistant_with_calls(ids: list[str], content: str = "calling tools") -> dict:
    return {
        "role": "assistant",
        "content": content,
        "tool_calls": [{"id": cid, "type": "function", "function": {"name": "x", "arguments": "{}"}} for cid in ids],
    }


def _tool_result(call_id: str, content: str = "ok") -> dict:
    return {"role": "tool", "tool_call_id": call_id, "content": content}


def test_valid_chain_unchanged() -> None:
    msgs = [{"role": "user", "content": "hi"}, _assistant_with_calls(["a"]), _tool_result("a"), {"role": "assistant", "content": "done"}]
    out = validate_tool_chain(msgs)
    assert out == msgs


def test_empty_messages() -> None:
    assert validate_tool_chain([]) == []


def test_no_tool_calls() -> None:
    msgs = [{"role": "user", "content": "u"}, {"role": "assistant", "content": "a"}]
    assert validate_tool_chain(msgs) == msgs


def test_single_tool_call_with_result() -> None:
    msgs = [_assistant_with_calls(["x"]), _tool_result("x")]
    out = validate_tool_chain(msgs)
    assert extract_tool_call_ids(out[0]) == {"x"}
    assert extract_tool_result_id(out[1]) == "x"


def test_multiple_tool_calls_with_results() -> None:
    msgs = [_assistant_with_calls(["x", "y"]), _tool_result("x"), _tool_result("y")]
    out = validate_tool_chain(msgs)
    assert len(out) == 3
    assert extract_tool_call_ids(out[0]) == {"x", "y"}


def test_assistant_tool_calls_no_results_text_kept() -> None:
    msgs = [_assistant_with_calls(["x"], content="fallback text")]
    out = validate_tool_chain(msgs)
    assert len(out) == 1
    assert "tool_calls" not in out[0]
    assert out[0]["content"] == "fallback text"


def test_assistant_tool_calls_no_results_no_text_removed() -> None:
    msgs = [_assistant_with_calls(["x"], content="   ")]
    out = validate_tool_chain(msgs)
    assert out == []


def test_partial_results_missing() -> None:
    msgs = [_assistant_with_calls(["x", "y"]), _tool_result("x")]
    out = validate_tool_chain(msgs)
    assert len(out) == 2
    assert extract_tool_call_ids(out[0]) == {"x"}
    assert extract_tool_result_id(out[1]) == "x"


def test_orphaned_tool_result_removed() -> None:
    msgs = [{"role": "user", "content": "u"}, _tool_result("orphan")]
    out = validate_tool_chain(msgs)
    assert out == [{"role": "user", "content": "u"}]


def test_tool_result_without_any_assistant_removed() -> None:
    assert validate_tool_chain([_tool_result("x")]) == []


def test_messages_between_call_and_results_reordered() -> None:
    msgs = [_assistant_with_calls(["x"]), {"role": "assistant", "content": "intermediate"}, _tool_result("x")]
    out = validate_tool_chain(msgs)
    assert extract_tool_result_id(out[1]) == "x"
    assert out[2]["content"] == "intermediate"


def test_user_message_between_call_and_results_reordered() -> None:
    msgs = [_assistant_with_calls(["x"]), {"role": "user", "content": "next"}, _tool_result("x")]
    out = validate_tool_chain(msgs)
    assert extract_tool_result_id(out[1]) == "x"
    assert out[2]["role"] == "user"


def test_find_groups_single_chain() -> None:
    msgs = [_assistant_with_calls(["x"]), _tool_result("x")]
    groups = find_tool_chain_groups(msgs)
    assert len(groups) == 1
    assert groups[0]["is_valid"] is True


def test_find_groups_multiple_chains() -> None:
    msgs = [_assistant_with_calls(["a"]), _tool_result("a"), _assistant_with_calls(["b"]), _tool_result("b")]
    groups = find_tool_chain_groups(msgs)
    assert len(groups) == 2


def test_find_groups_nested() -> None:
    msgs = [_assistant_with_calls(["a"]), _assistant_with_calls(["b"]), _tool_result("a"), _tool_result("b")]
    groups = find_tool_chain_groups(msgs)
    assert len(groups) == 2


def test_find_groups_no_chains() -> None:
    assert find_tool_chain_groups([{"role": "user", "content": "x"}]) == []


def test_truncate_preserves_tool_chain_group() -> None:
    msgs = [{"role": "system", "content": "rules"}, _assistant_with_calls(["a"]), _tool_result("a"), {"role": "user", "content": "older"}]
    out = truncate_messages_safe(msgs, max_tokens=3)
    roles = [m["role"] for m in out]
    assert "system" in roles
    assert roles.count("assistant") >= 1
    assert roles.count("tool") >= 1


def test_truncate_removes_complete_old_group() -> None:
    msgs = [
        {"role": "system", "content": "rules"},
        _assistant_with_calls(["a"], "one two"),
        _tool_result("a", "r1"),
        _assistant_with_calls(["b"], "three four"),
        _tool_result("b", "r2"),
    ]
    out = truncate_messages_safe(msgs, max_tokens=8)
    text = " ".join(str(m.get("content", "")) for m in out)
    assert "three four" in text


def test_truncate_never_removes_system_prompt() -> None:
    msgs = [{"role": "system", "content": "important"}] + [{"role": "user", "content": "x y z"} for _ in range(20)]
    out = truncate_messages_safe(msgs, max_tokens=5)
    assert any(m.get("role") == "system" for m in out)


def test_truncate_never_removes_latest_group() -> None:
    msgs = [
        {"role": "user", "content": "old"},
        _assistant_with_calls(["a"], "old-chain"),
        _tool_result("a"),
        _assistant_with_calls(["b"], "latest-chain"),
        _tool_result("b"),
    ]
    out = truncate_messages_safe(msgs, max_tokens=4)
    joined = " ".join(str(m.get("content", "")) for m in out)
    assert "latest-chain" in joined


def test_truncate_prefers_removing_old_chat_over_tool_chains() -> None:
    msgs = [{"role": "user", "content": "old chat " * 20}, _assistant_with_calls(["a"], "short"), _tool_result("a", "r")]
    out = truncate_messages_safe(msgs, max_tokens=6)
    assert any(m.get("role") == "tool" for m in out)


def test_abandoned_chain_stripped() -> None:
    msgs = [_assistant_with_calls(["x"], "text")] + [{"role": "user", "content": f"m{i}"} for i in range(6)]
    out = handle_failed_tool_chain(msgs)
    assert "tool_calls" not in out[0]


def test_recent_chain_kept() -> None:
    msgs = [_assistant_with_calls(["x"], "text"), {"role": "user", "content": "m1"}, _tool_result("x")]
    out = handle_failed_tool_chain(msgs)
    assert "tool_calls" in out[0]


def test_openclaw_read_tool_chain() -> None:
    msgs = [{"role": "user", "content": "read file"}, _assistant_with_calls(["r1"]), _tool_result("r1"), {"role": "assistant", "content": "parsed"}]
    out = validate_tool_chain(msgs)
    assert out == msgs


def test_openclaw_execute_chain() -> None:
    msgs = [{"role": "user", "content": "exec"}, _assistant_with_calls(["e1"]), _tool_result("e1"), {"role": "assistant", "content": "done"}]
    out = validate_tool_chain(msgs)
    assert extract_tool_result_id(out[2]) == "e1"


def test_openclaw_multi_tool_chain() -> None:
    msgs = [_assistant_with_calls(["r", "e", "w"]), _tool_result("r"), _tool_result("e"), _tool_result("w")]
    out = validate_tool_chain(msgs)
    assert len(out) == 4
    assert extract_tool_call_ids(out[0]) == {"r", "e", "w"}


def test_openclaw_session_new_after_failure() -> None:
    msgs = [_assistant_with_calls(["old"], "x")] + [{"role": "user", "content": "new session"} for _ in range(7)]
    out = validate_tool_chain(msgs)
    assert out[0].get("tool_calls") is None


def test_openclaw_context_truncation_preserves_active_chain() -> None:
    msgs = [{"role": "system", "content": "rules"}] + [{"role": "user", "content": "noise"} for _ in range(20)]
    msgs += [_assistant_with_calls(["live"], "active"), _tool_result("live")]
    out = truncate_messages_safe(msgs, max_tokens=15)
    assert any(extract_tool_result_id(m) == "live" for m in out)


def test_cascade_model_switch_preserves_chain() -> None:
    msgs = [_assistant_with_calls(["x"]), {"role": "assistant", "content": "switching"}, _tool_result("x")]
    out = validate_tool_chain(msgs)
    assert extract_tool_result_id(out[1]) == "x"


def test_cascade_retry_validates_chain() -> None:
    msgs = [_assistant_with_calls(["x"], "retry"), {"role": "user", "content": "between"}, _tool_result("x")]
    out = validate_tool_chain(msgs)
    assert out[0]["content"] == "retry"
    assert out[1]["role"] == "tool"


def test_duplicate_tool_call_ids() -> None:
    msgs = [_assistant_with_calls(["dup"]), _tool_result("dup"), _assistant_with_calls(["dup"]), _tool_result("dup")]
    out = validate_tool_chain(msgs)
    assert len([m for m in out if m.get("role") == "tool"]) == 2


def test_empty_tool_calls_array() -> None:
    msgs = [{"role": "assistant", "content": "x", "tool_calls": []}]
    out = validate_tool_chain(msgs)
    assert out == msgs


def test_malformed_tool_call_no_id() -> None:
    msgs = [{"role": "assistant", "content": "x", "tool_calls": [{"function": {"name": "a"}}]}, _tool_result("a")]
    out = validate_tool_chain(msgs)
    assert not out[0].get("tool_calls")


def test_very_long_chain() -> None:
    ids = [f"id{i}" for i in range(20)]
    msgs = [_assistant_with_calls(ids)] + [_tool_result(i) for i in ids]
    out = validate_tool_chain(msgs)
    assert len(out) == 21


def test_validate_idempotent() -> None:
    msgs = [_assistant_with_calls(["x"]), {"role": "user", "content": "mid"}, _tool_result("x")]
    once = validate_tool_chain(msgs)
    twice = validate_tool_chain(once)
    assert once == twice


def test_no_mutation_of_input() -> None:
    msgs = [_assistant_with_calls(["x"]), {"role": "user", "content": "u"}, _tool_result("x")]
    snapshot = json_like_copy(msgs)
    _ = validate_tool_chain(msgs)
    assert msgs == snapshot


def json_like_copy(obj):
    if isinstance(obj, list):
        return [json_like_copy(x) for x in obj]
    if isinstance(obj, dict):
        return {k: json_like_copy(v) for k, v in obj.items()}
    return obj


def test_extract_tool_call_ids_helper() -> None:
    ids = extract_tool_call_ids(_assistant_with_calls(["a", "b"]))
    assert ids == {"a", "b"}


def test_extract_tool_result_id_helper() -> None:
    assert extract_tool_result_id(_tool_result("a")) == "a"


def test_thread_safety() -> None:
    msgs = [_assistant_with_calls(["x"]), {"role": "user", "content": "between"}, _tool_result("x")]
    outputs: list[list[dict]] = []

    def worker() -> None:
        for _ in range(50):
            outputs.append(validate_tool_chain(msgs))

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(outputs) == 300
    assert all(out[1]["role"] == "tool" for out in outputs)

