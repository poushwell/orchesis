"""Orchesis MCP Server - expose Orchesis capabilities as MCP tools."""

from __future__ import annotations

import json
import logging
import sys
import threading
from typing import Any

logger = logging.getLogger("orchesis.mcp")

MCP_VERSION = "2024-11-05"


class MCPServer:
    """Minimal MCP server using stdio transport (JSON-RPC 2.0)."""

    def __init__(self, tool_registry: dict[str, dict[str, Any]]):
        self._tools = tool_registry
        self._initialized = False
        self._send_lock = threading.Lock()

    def run(self) -> None:
        """Read JSON-RPC messages from stdin and write responses to stdout."""
        logger.info("Orchesis MCP server starting on stdio")
        for line in sys.stdin:
            payload = line.strip()
            if not payload:
                continue
            responses = self.handle_json_message(payload)
            for response in responses:
                self._send(response)

    def handle_json_message(self, payload: str) -> list[dict[str, Any]]:
        """Handle one raw JSON-RPC message string and return responses."""
        try:
            data = json.loads(payload)
        except json.JSONDecodeError as error:
            return [self._error(None, -32700, f"Parse error: {error}")]

        if isinstance(data, list):
            if len(data) == 0:
                return [self._error(None, -32600, "Invalid Request")]
            responses: list[dict[str, Any]] = []
            for item in data:
                response = self._handle_request(item)
                if response is not None:
                    responses.append(response)
            return responses

        response = self._handle_request(data)
        return [] if response is None else [response]

    def _handle_request(self, request: Any) -> dict[str, Any] | None:
        if not isinstance(request, dict):
            return self._error(None, -32600, "Invalid Request")

        jsonrpc = request.get("jsonrpc")
        if jsonrpc is not None and jsonrpc != "2.0":
            return self._error(request.get("id"), -32600, "Invalid Request: jsonrpc must be '2.0'")

        method = request.get("method")
        req_id = request.get("id")
        params = request.get("params", {})
        if not isinstance(method, str) or not method:
            return self._error(req_id, -32600, "Invalid Request: method is required")
        if not isinstance(params, dict):
            return self._error(req_id, -32602, "Invalid params")

        if method == "initialize":
            return self._handle_initialize(req_id, params)
        if method == "initialized":
            self._initialized = True
            return None
        if method == "tools/list":
            return self._handle_tools_list(req_id)
        if method == "tools/call":
            return self._handle_tools_call(req_id, params)
        if method == "ping":
            return self._result(req_id, {})
        return self._error(req_id, -32601, f"Method not found: {method}")

    def _handle_initialize(self, req_id: Any, _params: dict[str, Any]) -> dict[str, Any]:
        return self._result(
            req_id,
            {
                "protocolVersion": MCP_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "orchesis", "version": "0.7.0"},
            },
        )

    def _handle_tools_list(self, req_id: Any) -> dict[str, Any]:
        tools: list[dict[str, Any]] = []
        for name, tool in self._tools.items():
            tools.append(
                {
                    "name": name,
                    "description": str(tool.get("description", "")),
                    "inputSchema": tool.get("inputSchema", {"type": "object", "properties": {}}),
                }
            )
        return self._result(req_id, {"tools": tools})

    def _handle_tools_call(self, req_id: Any, params: dict[str, Any]) -> dict[str, Any]:
        tool_name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(tool_name, str) or not tool_name:
            return self._error(req_id, -32602, "Invalid params: 'name' is required")
        if not isinstance(arguments, dict):
            return self._error(req_id, -32602, "Invalid params: 'arguments' must be object")
        if tool_name not in self._tools:
            return self._error(req_id, -32602, f"Unknown tool: {tool_name}")

        tool = self._tools[tool_name]
        schema = tool.get("inputSchema")
        if isinstance(schema, dict):
            required = schema.get("required", [])
            if isinstance(required, list):
                for field in required:
                    if isinstance(field, str) and field not in arguments:
                        return self._error(req_id, -32602, f"Missing required parameter: {field}")

        try:
            handler = tool["handler"]
            result = handler(arguments)
            content = self._wrap_content(result)
            return self._result(req_id, {"content": content, "isError": False})
        except Exception as error:  # noqa: BLE001
            logger.exception("MCP tool '%s' failed", tool_name)
            return self._result(
                req_id,
                {
                    "content": [{"type": "text", "text": f"Error: {error}"}],
                    "isError": True,
                },
            )

    @staticmethod
    def _wrap_content(result: Any) -> list[dict[str, Any]]:
        if isinstance(result, list):
            return result
        if isinstance(result, str):
            return [{"type": "text", "text": result}]
        if isinstance(result, dict):
            return [{"type": "text", "text": json.dumps(result, ensure_ascii=False, indent=2, default=str)}]
        return [{"type": "text", "text": str(result)}]

    @staticmethod
    def _result(req_id: Any, result: Any) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    @staticmethod
    def _error(req_id: Any, code: int, message: str) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": code, "message": message},
        }

    def _send(self, response: dict[str, Any]) -> None:
        with self._send_lock:
            sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
            sys.stdout.flush()

