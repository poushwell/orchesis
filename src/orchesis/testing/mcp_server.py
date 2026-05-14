"""Embedded permissive MCP server for end-to-end integration tests."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

import mcp.server.stdio
import mcp.types as types
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.models import InitializationOptions


class TestMCPServer:
    """Minimal MCP server with dangerous and safe tools."""

    def __init__(self, call_log_path: str | None = None):
        self.server = Server("orchesis-test-mcp-server")
        self.call_log_path = Path(call_log_path) if call_log_path else None
        self._register_handlers()

    def _register_handlers(self) -> None:
        @self.server.list_tools()
        async def _list_tools() -> list[types.Tool]:
            return [
                types.Tool(
                    name="read_file",
                    description="Read any file path",
                    inputSchema={"type": "object", "properties": {"path": {"type": "string"}}},
                ),
                types.Tool(
                    name="write_file",
                    description="Write content to path",
                    inputSchema={
                        "type": "object",
                        "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
                    },
                ),
                types.Tool(
                    name="delete_file",
                    description="Delete path",
                    inputSchema={"type": "object", "properties": {"path": {"type": "string"}}},
                ),
                types.Tool(
                    name="run_sql",
                    description="Execute sql query",
                    inputSchema={"type": "object", "properties": {"query": {"type": "string"}}},
                ),
                types.Tool(
                    name="api_call",
                    description="Call external API",
                    inputSchema={
                        "type": "object",
                        "properties": {"url": {"type": "string"}, "method": {"type": "string"}},
                    },
                ),
                types.Tool(
                    name="expensive_operation",
                    description="Expensive operation simulation",
                    inputSchema={"type": "object", "properties": {"cost": {"type": "number"}}},
                ),
            ]

        @self.server.call_tool()
        async def _call_tool(name: str, arguments: dict[str, Any]) -> list[types.TextContent]:
            self._log_call(name, arguments)
            if name == "read_file":
                path = str(arguments.get("path", ""))
                if path.startswith("/etc/"):
                    return [types.TextContent(type="text", text=f"SENSITIVE: {path}")]
                return [types.TextContent(type="text", text=f"content of {path}")]
            if name == "write_file":
                path = str(arguments.get("path", ""))
                content = str(arguments.get("content", ""))
                return [
                    types.TextContent(type="text", text=f"wrote {len(content)} bytes to {path}")
                ]
            if name == "delete_file":
                path = str(arguments.get("path", ""))
                return [types.TextContent(type="text", text=f"deleted {path}")]
            if name == "run_sql":
                query = str(arguments.get("query", ""))
                return [types.TextContent(type="text", text=f"executed: {query}")]
            if name == "api_call":
                url = str(arguments.get("url", ""))
                method = str(arguments.get("method", "GET"))
                return [types.TextContent(type="text", text=f"called {method} {url}")]
            if name == "expensive_operation":
                cost = arguments.get("cost", 0.0)
                return [types.TextContent(type="text", text=f"completed operation costing {cost}")]
            raise ValueError(f"Unknown tool: {name}")

    def _log_call(self, name: str, arguments: dict[str, Any]) -> None:
        if self.call_log_path is None:
            return
        self.call_log_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"tool": name, "arguments": arguments}
        with self.call_log_path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(payload, ensure_ascii=False) + "\n")

    async def run(self) -> None:
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="orchesis-test-mcp-server",
                    server_version="0.1.0",
                    capabilities=self.server.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    ),
                ),
            )


def main() -> None:
    call_log_path = os.getenv("TEST_MCP_CALL_LOG")
    server = TestMCPServer(call_log_path=call_log_path)
    asyncio.run(server.run())


if __name__ == "__main__":
    main()
