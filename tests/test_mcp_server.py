from __future__ import annotations

import io
import json
from concurrent.futures import ThreadPoolExecutor

from orchesis.mcp_server import MCPServer, MCP_VERSION


def _server_with_tools() -> MCPServer:
    return MCPServer(
        {
            "orchesis_echo": {
                "description": "Echo payload",
                "inputSchema": {
                    "type": "object",
                    "properties": {"text": {"type": "string"}},
                    "required": ["text"],
                },
                "handler": lambda params: f"echo:{params['text']}",
            },
            "orchesis_json": {
                "description": "JSON payload",
                "inputSchema": {"type": "object", "properties": {}},
                "handler": lambda _params: {"ok": True},
            },
            "orchesis_list": {
                "description": "List payload",
                "inputSchema": {"type": "object", "properties": {}},
                "handler": lambda _params: [{"type": "text", "text": "x"}],
            },
            "orchesis_fail": {
                "description": "Fail payload",
                "inputSchema": {"type": "object", "properties": {}},
                "handler": lambda _params: (_ for _ in ()).throw(RuntimeError("boom")),
            },
        }
    )


def test_initialize_handshake_returns_protocol_and_server_info() -> None:
    server = _server_with_tools()
    response = server._handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert isinstance(response, dict)
    assert response["result"]["protocolVersion"] == MCP_VERSION
    assert response["result"]["serverInfo"]["name"] == "orchesis"


def test_initialize_returns_tools_capability() -> None:
    server = _server_with_tools()
    response = server._handle_request({"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {}})
    assert response is not None
    assert response["result"]["capabilities"]["tools"]["listChanged"] is False


def test_tools_list_returns_all_tools() -> None:
    server = _server_with_tools()
    response = server._handle_request({"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}})
    assert response is not None
    names = {item["name"] for item in response["result"]["tools"]}
    assert {"orchesis_echo", "orchesis_json", "orchesis_list", "orchesis_fail"} == names


def test_tools_call_string_result_wrapped_as_text_content() -> None:
    server = _server_with_tools()
    response = server._handle_request(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "orchesis_echo", "arguments": {"text": "hello"}},
        }
    )
    assert response is not None
    payload = response["result"]
    assert payload["isError"] is False
    assert payload["content"][0]["text"] == "echo:hello"


def test_tools_call_dict_result_serialized_as_json_text() -> None:
    server = _server_with_tools()
    response = server._handle_request(
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "orchesis_json", "arguments": {}}}
    )
    assert response is not None
    assert '"ok": true' in response["result"]["content"][0]["text"].lower()


def test_tools_call_list_result_returned_as_is() -> None:
    server = _server_with_tools()
    response = server._handle_request(
        {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "orchesis_list", "arguments": {}}}
    )
    assert response is not None
    assert response["result"]["content"] == [{"type": "text", "text": "x"}]


def test_unknown_tool_returns_invalid_params_error() -> None:
    server = _server_with_tools()
    response = server._handle_request(
        {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "missing", "arguments": {}}}
    )
    assert response is not None
    assert response["error"]["code"] == -32602


def test_invalid_json_payload_returns_parse_error() -> None:
    server = _server_with_tools()
    responses = server.handle_json_message("{not-json}")
    assert responses[0]["error"]["code"] == -32700


def test_unknown_method_returns_method_not_found() -> None:
    server = _server_with_tools()
    response = server._handle_request({"jsonrpc": "2.0", "id": 8, "method": "unknown", "params": {}})
    assert response is not None
    assert response["error"]["code"] == -32601


def test_ping_returns_empty_result_object() -> None:
    server = _server_with_tools()
    response = server._handle_request({"jsonrpc": "2.0", "id": 9, "method": "ping", "params": {}})
    assert response is not None
    assert response["result"] == {}


def test_initialized_notification_returns_no_response() -> None:
    server = _server_with_tools()
    response = server._handle_request({"jsonrpc": "2.0", "method": "initialized", "params": {}})
    assert response is None


def test_missing_required_params_returns_error() -> None:
    server = _server_with_tools()
    response = server._handle_request(
        {"jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": {"name": "orchesis_echo", "arguments": {}}}
    )
    assert response is not None
    assert response["error"]["code"] == -32602
    assert "Missing required parameter: text" in response["error"]["message"]


def test_tool_exception_returns_is_error_true() -> None:
    server = _server_with_tools()
    response = server._handle_request(
        {"jsonrpc": "2.0", "id": 11, "method": "tools/call", "params": {"name": "orchesis_fail", "arguments": {}}}
    )
    assert response is not None
    assert response["result"]["isError"] is True
    assert "Error: boom" in response["result"]["content"][0]["text"]


def test_batch_request_returns_only_non_notification_responses() -> None:
    server = _server_with_tools()
    payload = json.dumps(
        [
            {"jsonrpc": "2.0", "id": 12, "method": "ping", "params": {}},
            {"jsonrpc": "2.0", "method": "initialized", "params": {}},
            {"jsonrpc": "2.0", "id": 13, "method": "tools/list", "params": {}},
        ]
    )
    responses = server.handle_json_message(payload)
    ids = sorted(item["id"] for item in responses)
    assert ids == [12, 13]


def test_run_writes_stdout_lines_for_each_response(monkeypatch) -> None:
    server = _server_with_tools()
    stdin = io.StringIO('{"jsonrpc":"2.0","id":14,"method":"ping","params":{}}\n')
    stdout = io.StringIO()
    monkeypatch.setattr("sys.stdin", stdin)
    monkeypatch.setattr("sys.stdout", stdout)
    server.run()
    output = stdout.getvalue().strip()
    assert output
    payload = json.loads(output)
    assert payload["id"] == 14


def test_concurrent_request_handling_returns_correct_ids() -> None:
    server = _server_with_tools()

    def call(i: int) -> int:
        response = server._handle_request({"jsonrpc": "2.0", "id": i, "method": "ping", "params": {}})
        assert response is not None
        return int(response["id"])

    with ThreadPoolExecutor(max_workers=8) as pool:
        ids = sorted(pool.map(call, range(100, 120)))
    assert ids == list(range(100, 120))

