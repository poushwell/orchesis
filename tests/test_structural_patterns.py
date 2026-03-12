from __future__ import annotations

import threading
from typing import Any

import pytest

from orchesis.structural_patterns import StructuralPatternDetector, StructuralSignature


def _req(
    messages: list[dict[str, Any]],
    model: str = "gpt-4o-mini",
    tools: list[str] | None = None,
    tokens: int | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {"messages": messages, "model": model}
    if tools is not None:
        payload["tools"] = tools
    if tokens is not None:
        payload["tokens"] = tokens
    return payload


def _msg(role: str, content: str, tool_calls: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    item: dict[str, Any] = {"role": role, "content": content}
    if tool_calls is not None:
        item["tool_calls"] = tool_calls
    return item


# Signature extraction
def test_extract_simple_chat() -> None:
    det = StructuralPatternDetector()
    sig = det.extract_signature(
        _req([_msg("user", "hello"), _msg("assistant", "hi there")], model="gpt-4o")
    )
    assert sig.role_sequence == ("user", "assistant")
    assert sig.has_tool_calls is False
    assert sig.has_tool_results is False


def test_extract_with_tool_calls() -> None:
    det = StructuralPatternDetector()
    sig = det.extract_signature(
        _req(
            [
                _msg("user", "read file"),
                _msg(
                    "assistant",
                    "calling tool",
                    tool_calls=[{"name": "read_file"}, {"function": {"name": "write_file"}}],
                ),
                _msg("tool", "result"),
                _msg("assistant", "done"),
            ]
        )
    )
    assert sig.has_tool_calls is True
    assert sig.has_tool_results is True
    assert sig.tool_sequence == ("read_file", "write_file")


def test_extract_with_system_prompt() -> None:
    det = StructuralPatternDetector()
    sig = det.extract_signature(_req([_msg("system", "rules"), _msg("user", "task")]))
    assert sig.has_system_prompt is True


def test_extract_empty_messages() -> None:
    det = StructuralPatternDetector()
    sig = det.extract_signature({"messages": []})
    assert sig.message_count == 0
    assert sig.estimated_tokens == 0


def test_extract_complex_multi_turn() -> None:
    det = StructuralPatternDetector()
    msgs = [_msg("user" if i % 2 == 0 else "assistant", f"m{i}") for i in range(12)]
    sig = det.extract_signature(_req(msgs))
    assert sig.message_count == 12
    assert len(sig.role_sequence) == 12


def test_extract_model_captured() -> None:
    det = StructuralPatternDetector()
    sig = det.extract_signature(_req([_msg("user", "x")], model="gpt-5"))
    assert sig.model == "gpt-5"


def test_extract_token_estimation() -> None:
    det = StructuralPatternDetector()
    sig = det.extract_signature(_req([_msg("user", "one two three four")]))
    assert sig.estimated_tokens >= 4


# Tool chain loop detection
def test_tool_chain_no_pattern() -> None:
    det = StructuralPatternDetector({"min_occurrences": 3})
    history = [
        StructuralSignature(("u",), ("a",), 1, False, True, False, "m", 10),
        StructuralSignature(("u",), ("b",), 1, False, True, False, "m", 10),
        StructuralSignature(("u",), ("c",), 1, False, True, False, "m", 10),
    ]
    assert det.detect_tool_chain_loops(history) == []


def test_tool_chain_simple_loop() -> None:
    det = StructuralPatternDetector({"min_occurrences": 3, "min_pattern_length": 2})
    history = []
    for t in [("read_file",), ("execute",)] * 3:
        history.append(StructuralSignature(("user", "assistant"), t, 2, False, True, False, "m", 20))
    matches = det.detect_tool_chain_loops(history)
    assert any(m.pattern_type == "tool_chain_loop" for m in matches)


def test_tool_chain_triple_loop() -> None:
    det = StructuralPatternDetector({"min_occurrences": 3, "min_pattern_length": 3})
    seq = [("a",), ("b",), ("c",)] * 3
    history = [StructuralSignature(("u",), item, 1, False, True, False, "m", 5) for item in seq]
    matches = det.detect_tool_chain_loops(history)
    assert matches


def test_tool_chain_insufficient_repeats() -> None:
    det = StructuralPatternDetector({"min_occurrences": 3})
    seq = [("a",), ("b",), ("a",), ("b",)]
    history = [StructuralSignature(("u",), item, 1, False, True, False, "m", 5) for item in seq]
    assert det.detect_tool_chain_loops(history) == []


def test_tool_chain_with_noise() -> None:
    det = StructuralPatternDetector({"min_occurrences": 3})
    seq = [("a",), ("b",), ("x",), ("a",), ("b",), ("a",), ("b",)]
    history = [StructuralSignature(("u",), item, 1, False, True, False, "m", 5) for item in seq]
    matches = det.detect_tool_chain_loops(history)
    assert matches


def test_tool_chain_empty_tools() -> None:
    det = StructuralPatternDetector()
    history = [StructuralSignature(("u",), tuple(), 1, False, False, False, "m", 5) for _ in range(10)]
    assert det.detect_tool_chain_loops(history) == []


# Role cycle detection
def test_role_cycle_simple() -> None:
    det = StructuralPatternDetector({"min_occurrences": 3})
    history = [StructuralSignature(("user", "assistant"), tuple(), 2, False, False, False, "m", 10) for _ in range(4)]
    matches = det.detect_role_cycles(history)
    assert matches and matches[0].pattern_type == "role_cycle"


def test_role_cycle_with_tools() -> None:
    det = StructuralPatternDetector({"min_occurrences": 3})
    sig = StructuralSignature(("user", "assistant", "tool"), ("read_file",), 3, False, True, True, "m", 20)
    matches = det.detect_role_cycles([sig, sig, sig, sig])
    assert matches


def test_role_cycle_no_pattern() -> None:
    det = StructuralPatternDetector({"min_occurrences": 3})
    history = [
        StructuralSignature(("u", "a"), tuple(), 2, False, False, False, "m", 5),
        StructuralSignature(("u", "a", "t"), tuple(), 3, False, False, False, "m", 6),
        StructuralSignature(("u",), tuple(), 1, False, False, False, "m", 4),
    ]
    assert det.detect_role_cycles(history) == []


# Request template detection
def test_template_identical_requests() -> None:
    det = StructuralPatternDetector({"min_occurrences": 3})
    sig = StructuralSignature(("user", "assistant"), ("search",), 2, False, True, False, "m", 10)
    matches = det.detect_request_templates([sig, sig, sig, sig, sig])
    assert matches


def test_template_varied_requests() -> None:
    det = StructuralPatternDetector({"min_occurrences": 3})
    history = [
        StructuralSignature(("u",), ("a",), 1, False, True, False, "m", 2),
        StructuralSignature(("u", "a"), ("a",), 2, False, True, False, "m", 3),
        StructuralSignature(("u", "a", "t"), ("a",), 3, False, True, True, "m", 4),
    ]
    assert det.detect_request_templates(history) == []


def test_template_same_structure_different_content() -> None:
    det = StructuralPatternDetector({"min_occurrences": 3})
    for i in range(5):
        det.record(
            "x",
            det.extract_signature(
                _req(
                    [_msg("user", f"question {i}"), _msg("assistant", f"answer {i}")],
                    model="gpt-4o-mini",
                    tools=["search"],
                )
            ),
        )
    matches = det.detect_patterns("x")
    assert any(m.pattern_type == "request_template" for m in matches)


def test_template_different_models() -> None:
    det = StructuralPatternDetector({"min_occurrences": 3})
    history = [
        StructuralSignature(("u", "a"), ("search",), 2, False, True, False, "m1", 10),
        StructuralSignature(("u", "a"), ("search",), 2, False, True, False, "m2", 10),
        StructuralSignature(("u", "a"), ("search",), 2, False, True, False, "m1", 10),
    ]
    assert det.detect_request_templates(history) == []


# Escalation chain detection
def test_escalation_growing_tokens() -> None:
    det = StructuralPatternDetector()
    history = [
        StructuralSignature(("u",), tuple(), 1, False, False, False, "m", v)
        for v in [10, 20, 30, 40, 55]
    ]
    assert det.detect_escalation_chains(history)


def test_escalation_growing_messages() -> None:
    det = StructuralPatternDetector()
    history = [
        StructuralSignature(("u",) * m, tuple(), m, False, False, False, "m", 10)
        for m in [1, 2, 3, 4, 5]
    ]
    assert det.detect_escalation_chains(history)


def test_escalation_flat() -> None:
    det = StructuralPatternDetector()
    history = [StructuralSignature(("u",), tuple(), 2, False, False, False, "m", 10) for _ in range(5)]
    assert det.detect_escalation_chains(history) == []


def test_escalation_with_noise() -> None:
    det = StructuralPatternDetector()
    history = [
        StructuralSignature(("u",), tuple(), 1, False, False, False, "m", v)
        for v in [10, 20, 18, 30, 40]
    ]
    assert det.detect_escalation_chains(history)


# Ping-pong detection
def test_pingpong_two_tools() -> None:
    det = StructuralPatternDetector({"min_occurrences": 3})
    history = [
        StructuralSignature(("u",), (tool,), 1, False, True, False, "m", 5)
        for tool in ["read_file", "write_file", "read_file", "write_file", "read_file", "write_file"]
    ]
    matches = det.detect_ping_pong(history)
    assert matches and matches[0].pattern_type == "ping_pong"


def test_pingpong_three_tools() -> None:
    det = StructuralPatternDetector({"min_occurrences": 3})
    history = [
        StructuralSignature(("u",), (tool,), 1, False, True, False, "m", 5)
        for tool in ["a", "b", "c", "a", "b", "c"]
    ]
    assert det.detect_ping_pong(history) == []


def test_pingpong_no_alternation() -> None:
    det = StructuralPatternDetector({"min_occurrences": 3})
    history = [
        StructuralSignature(("u",), (tool,), 1, False, True, False, "m", 5)
        for tool in ["a", "a", "b", "a", "b", "b"]
    ]
    assert det.detect_ping_pong(history) == []


# Structural similarity
def test_similarity_identical() -> None:
    det = StructuralPatternDetector()
    a = StructuralSignature(("u", "a"), ("x",), 2, False, True, False, "m", 20)
    assert det.structural_similarity(a, a) == 1.0


def test_similarity_completely_different() -> None:
    det = StructuralPatternDetector()
    a = StructuralSignature(("u",), ("x",), 1, False, True, False, "m1", 10)
    b = StructuralSignature(("system", "tool"), ("z", "q"), 9, True, True, True, "m2", 500)
    assert det.structural_similarity(a, b) < 0.3


def test_similarity_same_roles_different_tools() -> None:
    det = StructuralPatternDetector()
    a = StructuralSignature(("u", "a"), ("x",), 2, False, True, False, "m", 20)
    b = StructuralSignature(("u", "a"), ("y",), 2, False, True, False, "m", 20)
    sim = det.structural_similarity(a, b)
    assert 0.4 <= sim <= 0.9


def test_similarity_same_tools_different_model() -> None:
    det = StructuralPatternDetector()
    a = StructuralSignature(("u", "a"), ("x",), 2, False, True, False, "m1", 20)
    b = StructuralSignature(("u", "a"), ("x",), 2, False, True, False, "m2", 20)
    sim = det.structural_similarity(a, b)
    assert 0.7 <= sim < 1.0


# Full pipeline
def test_check_builds_history() -> None:
    det = StructuralPatternDetector()
    for i in range(5):
        det.check("agent", _req([_msg("user", f"hello {i}")]))
    summary = det.get_agent_history("agent")
    assert summary["count"] == 5


def test_check_detects_patterns_over_time() -> None:
    det = StructuralPatternDetector({"min_occurrences": 3})
    for i in range(6):
        det.check(
            "agent",
            _req(
                [_msg("user", f"q{i}"), _msg("assistant", "doing")],
                tools=["read_file" if i % 2 == 0 else "write_file"],
            ),
        )
    has, matches = det.check(
        "agent",
        _req([_msg("user", "q-final"), _msg("assistant", "doing")], tools=["read_file"]),
    )
    assert has
    assert len(matches) >= 1


def test_check_multiple_agents_independent() -> None:
    det = StructuralPatternDetector()
    for i in range(4):
        det.check("a1", _req([_msg("user", f"a{i}")]))
        det.check("a2", _req([_msg("user", f"b{i}")], model="gpt-5"))
    all_agents = det.get_all_agents()
    assert set(all_agents.keys()) == {"a1", "a2"}


def test_check_thread_safety() -> None:
    det = StructuralPatternDetector({"history_size": 300})

    def worker(prefix: str) -> None:
        for i in range(80):
            det.check(prefix, _req([_msg("user", f"{prefix}-{i}")], tools=["search"]))

    threads = [threading.Thread(target=worker, args=(f"agent-{i%3}",)) for i in range(9)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    summaries = det.get_all_agents()
    assert len(summaries) == 3
    total = sum(int(item["count"]) for item in summaries.values())
    assert total == 720


def test_get_agent_history() -> None:
    det = StructuralPatternDetector()
    det.check("a", _req([_msg("user", "x"), _msg("assistant", "y")], tools=["search"]))
    hist = det.get_agent_history("a")
    assert hist["count"] == 1
    assert hist["has_tools"] is True


def test_reset_clears_history() -> None:
    det = StructuralPatternDetector()
    det.check("a", _req([_msg("user", "x")]))
    det.reset("a")
    hist = det.get_agent_history("a")
    assert hist["count"] == 0


# Edge cases
def test_single_request_no_patterns() -> None:
    det = StructuralPatternDetector()
    has, matches = det.check("a", _req([_msg("user", "one")]))
    assert not has
    assert matches == []


def test_history_size_bounded() -> None:
    det = StructuralPatternDetector({"history_size": 5})
    for i in range(20):
        det.check("a", _req([_msg("user", str(i))]))
    hist = det.get_agent_history("a")
    assert hist["count"] == 5


def test_empty_request_data() -> None:
    det = StructuralPatternDetector()
    sig = det.extract_signature({})
    assert sig.message_count == 0
    assert sig.role_sequence == tuple()


def test_unicode_in_tool_names() -> None:
    det = StructuralPatternDetector()
    sig = det.extract_signature(
        _req(
            [_msg("assistant", "run", tool_calls=[{"name": "поиск"}, {"name": "分析"}])],
            tools=["🔧-tool"],
        )
    )
    assert len(sig.tool_sequence) >= 2


def test_very_long_tool_sequence() -> None:
    det = StructuralPatternDetector({"history_size": 200})
    tools = [f"tool_{i}" for i in range(150)]
    sig = det.extract_signature(_req([_msg("assistant", "x")], tools=tools))
    det.record("a", sig)
    hist = det.get_agent_history("a")
    assert hist["count"] == 1
    assert hist["top_tools"][0][0].startswith("tool_")


def test_structural_similarity_threshold_usage() -> None:
    det = StructuralPatternDetector({"similarity_threshold": 0.9})
    a = StructuralSignature(("u", "a"), ("x",), 2, False, True, False, "m", 20)
    b = StructuralSignature(("u", "a"), ("x",), 2, False, True, False, "m", 22)
    assert det.structural_similarity(a, b) >= 0.9


def test_get_all_agents_empty() -> None:
    det = StructuralPatternDetector()
    assert det.get_all_agents() == {}


def test_detect_patterns_empty_agent() -> None:
    det = StructuralPatternDetector()
    assert det.detect_patterns("missing") == []


def test_record_unknown_agent_id() -> None:
    det = StructuralPatternDetector()
    det.record("", StructuralSignature(tuple(), tuple(), 0, False, False, False, "", 0))
    assert det.get_agent_history("unknown")["count"] == 1

