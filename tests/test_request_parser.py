from __future__ import annotations

import json

from orchesis.request_parser import parse_request, parse_response


def test_parse_anthropic_simple_text_message() -> None:
    body = {"model": "claude-sonnet-4", "max_tokens": 256, "messages": [{"role": "user", "content": "hello"}]}
    parsed = parse_request(body, "/v1/messages")
    assert parsed.provider == "anthropic"
    assert parsed.content_text == "hello"


def test_parse_anthropic_with_tool_use_block() -> None:
    body = {
        "model": "claude-sonnet-4",
        "max_tokens": 256,
        "messages": [
            {
                "role": "assistant",
                "content": [{"type": "tool_use", "id": "toolu_1", "name": "read_file", "input": {"path": "/etc/passwd"}}],
            }
        ],
    }
    parsed = parse_request(body, "/v1/messages")
    assert len(parsed.tool_calls) == 1
    assert parsed.tool_calls[0].name == "read_file"


def test_parse_anthropic_with_tool_result_block() -> None:
    body = {
        "model": "claude-sonnet-4",
        "max_tokens": 128,
        "messages": [
            {
                "role": "assistant",
                "content": [{"type": "tool_result", "content": [{"type": "text", "text": "result data"}]}],
            }
        ],
    }
    parsed = parse_request(body, "/v1/messages")
    assert "result data" in parsed.content_text


def test_parse_anthropic_extracts_model_name() -> None:
    parsed = parse_request({"model": "claude-haiku-4", "max_tokens": 12, "messages": []}, "/v1/messages")
    assert parsed.model == "claude-haiku-4"


def test_parse_anthropic_extracts_multiple_tool_calls() -> None:
    body = {
        "model": "claude-sonnet-4",
        "max_tokens": 128,
        "messages": [
            {
                "role": "assistant",
                "content": [
                    {"type": "tool_use", "id": "a", "name": "read_file", "input": {"path": "a"}},
                    {"type": "tool_use", "id": "b", "name": "web_search", "input": {"query": "x"}},
                ],
            }
        ],
    }
    parsed = parse_request(body, "/v1/messages")
    assert len(parsed.tool_calls) == 2


def test_parse_anthropic_handles_empty_messages() -> None:
    parsed = parse_request({"model": "claude", "max_tokens": 1, "messages": []}, "/v1/messages")
    assert parsed.messages == []
    assert parsed.content_text == ""


def test_parse_anthropic_extracts_content_text_from_mixed_blocks() -> None:
    body = {
        "model": "claude",
        "max_tokens": 12,
        "messages": [
            {
                "role": "assistant",
                "content": [
                    {"type": "text", "text": "part1"},
                    {"type": "tool_use", "id": "t", "name": "read_file", "input": {"path": "/tmp/x"}},
                    {"type": "tool_result", "content": "part2"},
                ],
            }
        ],
    }
    parsed = parse_request(body, "/v1/messages")
    assert "part1" in parsed.content_text
    assert "part2" in parsed.content_text


def test_parse_openai_simple_text_message() -> None:
    body = {"model": "gpt-4o", "messages": [{"role": "user", "content": "hello"}]}
    parsed = parse_request(body, "/v1/chat/completions")
    assert parsed.provider == "openai"
    assert parsed.content_text == "hello"


def test_parse_openai_with_tool_calls() -> None:
    body = {
        "model": "gpt-4o",
        "messages": [
            {
                "role": "assistant",
                "tool_calls": [
                    {"id": "call_1", "type": "function", "function": {"name": "read_file", "arguments": '{"path":"/etc/passwd"}'}}
                ],
            }
        ],
    }
    parsed = parse_request(body, "/v1/chat/completions")
    assert len(parsed.tool_calls) == 1
    assert parsed.tool_calls[0].params["path"] == "/etc/passwd"


def test_parse_openai_malformed_function_args_graceful() -> None:
    body = {
        "model": "gpt-4o",
        "messages": [
            {
                "role": "assistant",
                "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "read_file", "arguments": "{bad"}}],
            }
        ],
    }
    parsed = parse_request(body, "/v1/chat/completions")
    assert parsed.tool_calls[0].params == {}


def test_parse_openai_extract_model() -> None:
    parsed = parse_request({"model": "gpt-4.1-mini", "messages": []}, "/v1/chat/completions")
    assert parsed.model == "gpt-4.1-mini"


def test_parse_openai_extract_multiple_tool_calls() -> None:
    body = {
        "model": "gpt-4o",
        "messages": [
            {
                "role": "assistant",
                "tool_calls": [
                    {"id": "1", "type": "function", "function": {"name": "a", "arguments": "{}"}},
                    {"id": "2", "type": "function", "function": {"name": "b", "arguments": "{}"}},
                ],
            }
        ],
    }
    parsed = parse_request(body, "/v1/chat/completions")
    assert len(parsed.tool_calls) == 2


def test_parse_openai_extract_content_text() -> None:
    body = {"model": "gpt-4o", "messages": [{"role": "user", "content": "A"}, {"role": "assistant", "content": "B"}]}
    parsed = parse_request(body, "/v1/chat/completions")
    assert parsed.content_text == "A\nB"


def test_parse_request_auto_detect_by_messages_path() -> None:
    parsed = parse_request({"model": "x", "max_tokens": 1, "messages": []}, "/v1/messages")
    assert parsed.provider == "anthropic"


def test_parse_request_auto_detect_by_chat_path() -> None:
    parsed = parse_request({"model": "x", "messages": []}, "/v1/chat/completions")
    assert parsed.provider == "openai"


def test_parse_request_auto_detect_anthropic_by_max_tokens() -> None:
    parsed = parse_request({"model": "x", "max_tokens": 1, "messages": []}, "/v1/unknown")
    assert parsed.provider == "anthropic"


def test_parse_anthropic_response_with_usage_tokens() -> None:
    body = {"model": "claude", "usage": {"input_tokens": 11, "output_tokens": 22}, "content": []}
    parsed = parse_response(body, "anthropic")
    assert parsed.input_tokens == 11
    assert parsed.output_tokens == 22


def test_parse_anthropic_response_with_tool_use() -> None:
    body = {"model": "claude", "content": [{"type": "tool_use", "id": "x", "name": "read_file", "input": {"path": "/tmp/a"}}]}
    parsed = parse_response(body, "anthropic")
    assert len(parsed.tool_calls) == 1
    assert parsed.tool_calls[0].name == "read_file"


def test_parse_openai_response_with_usage_tokens() -> None:
    body = {"model": "gpt-4o", "usage": {"prompt_tokens": 9, "completion_tokens": 5}, "choices": []}
    parsed = parse_response(body, "openai")
    assert parsed.input_tokens == 9
    assert parsed.output_tokens == 5


def test_parse_openai_response_with_tool_calls() -> None:
    body = {
        "model": "gpt-4o",
        "choices": [
            {
                "finish_reason": "tool_calls",
                "message": {
                    "tool_calls": [
                        {"id": "call_1", "type": "function", "function": {"name": "web_search", "arguments": '{"query":"x"}'}}
                    ]
                },
            }
        ],
    }
    parsed = parse_response(body, "openai")
    assert len(parsed.tool_calls) == 1
    assert parsed.stop_reason == "tool_calls"


def test_parse_response_extract_stop_reason_from_openai() -> None:
    body = {"model": "gpt", "choices": [{"finish_reason": "stop", "message": {"content": "ok"}}]}
    parsed = parse_response(body, "openai")
    assert parsed.stop_reason == "stop"

