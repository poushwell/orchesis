"""Parse LLM API requests/responses to extract tool calls and usage."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from typing import Any


@dataclass
class ToolCall:
    """Represents an extracted tool call."""

    name: str
    params: dict[str, Any] = field(default_factory=dict)
    call_id: str = ""


@dataclass
class ParsedRequest:
    """Parsed incoming LLM API request."""

    provider: str
    model: str = ""
    messages: list[dict[str, Any]] = field(default_factory=list)
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_definitions: list[dict[str, Any]] = field(default_factory=list)
    raw_body: dict[str, Any] = field(default_factory=dict)
    content_text: str = ""


@dataclass
class ParsedResponse:
    """Parsed LLM API response payload."""

    provider: str
    model: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    content_text: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    raw_body: dict[str, Any] = field(default_factory=dict)
    stop_reason: str = ""


def parse_request(body: dict[str, Any], path: str) -> ParsedRequest:
    """Parse incoming request body from Anthropic/OpenAI-compatible APIs."""
    safe_path = path.lower()
    if "/messages" in safe_path:
        return _parse_anthropic_request(body)
    if "/chat/completions" in safe_path:
        return _parse_openai_request(body)
    if "max_tokens" in body and "messages" in body:
        return _parse_anthropic_request(body)
    return _parse_openai_request(body)


def parse_response(body: dict[str, Any], provider: str) -> ParsedResponse:
    """Parse response body from Anthropic/OpenAI-compatible APIs."""
    safe_provider = provider.lower().strip()
    if safe_provider == "anthropic":
        return _parse_anthropic_response(body)
    return _parse_openai_response(body)


def _parse_anthropic_request(body: dict[str, Any]) -> ParsedRequest:
    result = ParsedRequest(provider="anthropic", raw_body=body)
    result.model = str(body.get("model", ""))
    messages = body.get("messages", [])
    result.messages = messages if isinstance(messages, list) else []
    tools = body.get("tools", [])
    result.tool_definitions = tools if isinstance(tools, list) else []

    text_parts: list[str] = []
    for msg in result.messages:
        if not isinstance(msg, dict):
            continue
        content = msg.get("content", "")
        if isinstance(content, str):
            if content:
                text_parts.append(content)
            continue
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict):
                continue
            block_type = str(block.get("type", ""))
            if block_type == "tool_use":
                name = block.get("name", "")
                call_input = block.get("input", {})
                result.tool_calls.append(
                    ToolCall(
                        name=str(name) if isinstance(name, str) else "",
                        params=call_input if isinstance(call_input, dict) else {},
                        call_id=str(block.get("id", "")),
                    )
                )
            elif block_type == "text":
                text = block.get("text", "")
                if isinstance(text, str) and text:
                    text_parts.append(text)
            elif block_type == "tool_result":
                content_val = block.get("content", "")
                if isinstance(content_val, str) and content_val:
                    text_parts.append(content_val)
                elif isinstance(content_val, list):
                    for sub in content_val:
                        if isinstance(sub, dict) and sub.get("type") == "text":
                            text = sub.get("text", "")
                            if isinstance(text, str) and text:
                                text_parts.append(text)

    result.content_text = "\n".join(text_parts)
    return result


def _parse_openai_request(body: dict[str, Any]) -> ParsedRequest:
    result = ParsedRequest(provider="openai", raw_body=body)
    result.model = str(body.get("model", ""))
    messages = body.get("messages", [])
    result.messages = messages if isinstance(messages, list) else []
    tools = body.get("tools", [])
    result.tool_definitions = tools if isinstance(tools, list) else []

    text_parts: list[str] = []
    for msg in result.messages:
        if not isinstance(msg, dict):
            continue
        content = msg.get("content", "")
        if isinstance(content, str) and content:
            text_parts.append(content)
        tool_calls = msg.get("tool_calls", [])
        if not isinstance(tool_calls, list):
            continue
        for tc in tool_calls:
            if not isinstance(tc, dict):
                continue
            func = tc.get("function", {})
            if not isinstance(func, dict):
                continue
            name = func.get("name", "")
            arguments = func.get("arguments", "{}")
            params: dict[str, Any]
            try:
                parsed = json.loads(arguments) if isinstance(arguments, str) else arguments
            except (json.JSONDecodeError, TypeError):
                parsed = {}
            params = parsed if isinstance(parsed, dict) else {}
            result.tool_calls.append(
                ToolCall(
                    name=str(name) if isinstance(name, str) else "",
                    params=params,
                    call_id=str(tc.get("id", "")),
                )
            )

    result.content_text = "\n".join(text_parts)
    return result


def _parse_anthropic_response(body: dict[str, Any]) -> ParsedResponse:
    result = ParsedResponse(provider="anthropic", raw_body=body)
    result.model = str(body.get("model", ""))
    result.stop_reason = str(body.get("stop_reason", ""))
    usage = body.get("usage", {})
    if isinstance(usage, dict):
        result.input_tokens = int(usage.get("input_tokens", 0) or 0)
        result.output_tokens = int(usage.get("output_tokens", 0) or 0)

    content = body.get("content", [])
    text_parts: list[str] = []
    if isinstance(content, list):
        for block in content:
            if not isinstance(block, dict):
                continue
            block_type = str(block.get("type", ""))
            if block_type == "text":
                text = block.get("text", "")
                if isinstance(text, str) and text:
                    text_parts.append(text)
            elif block_type == "tool_use":
                name = block.get("name", "")
                call_input = block.get("input", {})
                result.tool_calls.append(
                    ToolCall(
                        name=str(name) if isinstance(name, str) else "",
                        params=call_input if isinstance(call_input, dict) else {},
                        call_id=str(block.get("id", "")),
                    )
                )

    result.content_text = "\n".join(text_parts)
    return result


def _parse_openai_response(body: dict[str, Any]) -> ParsedResponse:
    result = ParsedResponse(provider="openai", raw_body=body)
    result.model = str(body.get("model", ""))
    usage = body.get("usage", {})
    if isinstance(usage, dict):
        result.input_tokens = int(usage.get("prompt_tokens", 0) or 0)
        result.output_tokens = int(usage.get("completion_tokens", 0) or 0)

    text_parts: list[str] = []
    choices = body.get("choices", [])
    if isinstance(choices, list):
        for choice in choices:
            if not isinstance(choice, dict):
                continue
            finish_reason = choice.get("finish_reason")
            if isinstance(finish_reason, str):
                result.stop_reason = finish_reason
            msg = choice.get("message", {})
            if not isinstance(msg, dict):
                continue
            content = msg.get("content", "")
            if isinstance(content, str) and content:
                text_parts.append(content)
            tool_calls = msg.get("tool_calls", [])
            if not isinstance(tool_calls, list):
                continue
            for tc in tool_calls:
                if not isinstance(tc, dict):
                    continue
                func = tc.get("function", {})
                if not isinstance(func, dict):
                    continue
                name = func.get("name", "")
                arguments = func.get("arguments", "{}")
                try:
                    parsed = json.loads(arguments) if isinstance(arguments, str) else arguments
                except (json.JSONDecodeError, TypeError):
                    parsed = {}
                params = parsed if isinstance(parsed, dict) else {}
                result.tool_calls.append(
                    ToolCall(
                        name=str(name) if isinstance(name, str) else "",
                        params=params,
                        call_id=str(tc.get("id", "")),
                    )
                )

    result.content_text = "\n".join(text_parts)
    return result

