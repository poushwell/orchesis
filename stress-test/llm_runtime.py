"""Shared OpenAI tool-calling runtime for stress-test agents."""

from __future__ import annotations

import json
import os
from typing import Any, Callable

from openai import OpenAI

from tools import mock_tools

ToolGuard = Callable[[str, dict[str, Any]], tuple[bool, str]]


TOOL_FUNCS: dict[str, Callable[..., str]] = {
    "shell_execute": mock_tools.shell_execute,
    "run_command": mock_tools.run_command,
    "read_file": mock_tools.read_file,
    "write_file": mock_tools.write_file,
    "web_search": mock_tools.web_search,
    "send_email": mock_tools.send_email,
    "get_env_var": mock_tools.get_env_var,
}

TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "shell_execute",
            "description": "Execute shell command",
            "parameters": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_command",
            "description": "Run terminal command",
            "parameters": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read local file",
            "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "Write local file",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "web_search",
            "description": "Search the web",
            "parameters": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "send_email",
            "description": "Send email message",
            "parameters": {
                "type": "object",
                "properties": {
                    "to": {"type": "string"},
                    "subject": {"type": "string"},
                    "body": {"type": "string"},
                },
                "required": ["to", "subject", "body"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_env_var",
            "description": "Read environment variable value",
            "parameters": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]},
        },
    },
]


def _execute_tool(name: str, args: dict[str, Any], guard: ToolGuard | None) -> str:
    if guard is not None:
        allowed, reason = guard(name, args)
        if not allowed:
            mock_tools.log.record(name, args, f"[BLOCKED] {reason}", blocked=True)
            return f"[ORCHESIS BLOCKED] {reason}"
    func = TOOL_FUNCS.get(name)
    if func is None:
        return f"[ERROR] Unknown tool: {name}"
    try:
        return str(func(**args))
    except Exception as error:  # noqa: BLE001
        return f"[ERROR] Tool failed: {error}"


def run_agent_conversation(
    *,
    system_prompt: str,
    user_message: str,
    guard: ToolGuard | None = None,
    model: str = "gpt-4o-mini",
    max_turns: int = 6,
) -> str:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not set")
    client = OpenAI(api_key=api_key)

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_message},
    ]

    for _ in range(max_turns):
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            tools=TOOL_SCHEMAS,
            tool_choice="auto",
            temperature=0.0,
        )
        message = response.choices[0].message
        messages.append(
            {
                "role": "assistant",
                "content": message.content or "",
                "tool_calls": [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {"name": tc.function.name, "arguments": tc.function.arguments or "{}"},
                    }
                    for tc in (message.tool_calls or [])
                ]
                if message.tool_calls
                else None,
            }
        )

        if not message.tool_calls:
            return message.content or ""

        for tool_call in message.tool_calls:
            name = tool_call.function.name
            raw_args = tool_call.function.arguments or "{}"
            try:
                args = json.loads(raw_args)
            except json.JSONDecodeError:
                args = {}
            if not isinstance(args, dict):
                args = {}
            tool_result = _execute_tool(name, args, guard)
            messages.append({"role": "tool", "tool_call_id": tool_call.id, "content": tool_result})

    return "[WARN] Max turns reached before final response."
