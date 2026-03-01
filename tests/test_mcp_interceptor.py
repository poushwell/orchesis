from __future__ import annotations

from orchesis.interceptors.mcp import McpInterceptor
from orchesis.models import Decision


class _Engine:
    def __init__(self, deny_tools: set[str] | None = None):
        self.deny_tools = deny_tools or set()

    def evaluate(self, payload: dict, session_type: str = "cli"):
        _ = session_type
        if payload.get("tool") in self.deny_tools:
            return Decision(allowed=False, reasons=["file_access: blocked"], rules_checked=["file_access"])
        return Decision(allowed=True, reasons=[], rules_checked=["file_access"])


def test_intercept_tool_call_allow() -> None:
    interceptor = McpInterceptor(_Engine())
    message = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "/tmp/a"}},
    }
    assert interceptor.intercept_request(message) is None


def test_intercept_tool_call_deny() -> None:
    interceptor = McpInterceptor(_Engine(deny_tools={"write_file"}))
    message = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "write_file", "arguments": {"path": "/etc/passwd"}},
    }
    deny = interceptor.intercept_request(message)
    assert isinstance(deny, dict)
    assert deny["error"]["code"] == -32001


def test_intercept_non_tool_message_passthrough() -> None:
    interceptor = McpInterceptor(_Engine())
    message = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    assert interceptor.intercept_request(message) is None


def test_intercept_notification_passthrough() -> None:
    interceptor = McpInterceptor(_Engine())
    message = {"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}
    assert interceptor.intercept_request(message) is None


def test_intercept_tool_list_filter_allowlist() -> None:
    interceptor = McpInterceptor(_Engine(), policy={"tool_access": {"mode": "allowlist", "allowed": ["read_file"]}})
    message = {
        "jsonrpc": "2.0",
        "id": 2,
        "result": {
            "tools": [
                {"name": "read_file", "description": "Read files"},
                {"name": "write_file", "description": "Write files"},
            ]
        },
    }
    out = interceptor.intercept_tool_list(message)
    assert len(out["result"]["tools"]) == 1
    assert out["result"]["tools"][0]["name"] == "read_file"


def test_intercept_tool_description_ioc_scan() -> None:
    interceptor = McpInterceptor(_Engine())
    message = {
        "jsonrpc": "2.0",
        "id": 2,
        "result": {"tools": [{"name": "a", "description": "download from http://45.33.32.156/payload"}]},
    }
    out = interceptor.intercept_tool_list(message)
    assert "orchesis_ioc_findings" in out


def test_extract_tool_info() -> None:
    message = {"method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "/tmp/a"}}}
    assert McpInterceptor.extract_tool_info(message) == ("read_file", {"path": "/tmp/a"})


def test_is_tool_call() -> None:
    assert McpInterceptor.is_tool_call({"id": 1, "method": "tools/call"}) is True
    assert McpInterceptor.is_tool_call({"method": "tools/call"}) is False


def test_deny_response_jsonrpc_format() -> None:
    interceptor = McpInterceptor(_Engine(deny_tools={"shell"}))
    message = {"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": "shell", "arguments": {}}}
    out = interceptor.intercept_request(message)
    assert out is not None
    assert out["jsonrpc"] == "2.0"
    assert out["id"] == 9
    assert "Blocked by policy" in out["error"]["message"]


def test_intercept_response_secret_scan() -> None:
    interceptor = McpInterceptor(_Engine())
    message = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"content": [{"type": "text", "text": "token=sk-abcdefghijklmnopqrstuvwxyz123"}]},
    }
    out = interceptor.intercept_response(message)
    assert out["result"]["content"][0]["text"] != message["result"]["content"][0]["text"]
