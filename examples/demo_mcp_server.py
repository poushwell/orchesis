"""Minimal MCP demo server for Orchesis proxy e2e checks."""

from __future__ import annotations

import asyncio
from typing import Any

import mcp.server.stdio
import mcp.types as types
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.models import InitializationOptions

server = Server("demo-mcp-server")


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="read_file",
            description="Read file content (stubbed)",
            inputSchema={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        ),
        types.Tool(
            name="delete_file",
            description="Delete file (stubbed)",
            inputSchema={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        ),
        types.Tool(
            name="run_sql",
            description="Run SQL query (stubbed)",
            inputSchema={
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[types.TextContent]:
    if name == "read_file":
        path = str(arguments.get("path", ""))
        return [types.TextContent(type="text", text=f"fake content from {path}")]

    if name == "delete_file":
        return [types.TextContent(type="text", text="deleted")]

    if name == "run_sql":
        return [types.TextContent(type="text", text="executed")]

    raise ValueError(f"Unknown tool: {name}")


async def run() -> None:
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="demo-mcp-server",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
