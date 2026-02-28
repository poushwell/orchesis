"""MCP stdio-to-stdio interceptor that applies Orchesis policy checks."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Protocol

import mcp.server.stdio
import mcp.types as types
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.models import InitializationOptions

from orchesis.config import load_policy
from orchesis.engine import evaluate
from orchesis.mcp_config import McpProxySettings


class DownstreamSession(Protocol):
    async def list_tools(self) -> types.ListToolsResult: ...

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
    ) -> types.CallToolResult: ...


@dataclass
class McpToolInterceptor:
    """Interception layer that checks tool calls before forwarding."""

    policy: dict[str, Any]
    downstream_session: DownstreamSession
    default_tool_cost: float = 0.0
    downstream_timeout_seconds: float | None = None

    def _build_evaluate_request(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        raw_cost = arguments.get("cost", self.default_tool_cost)
        cost = float(raw_cost) if isinstance(raw_cost, int | float) else self.default_tool_cost
        return {
            "tool": tool_name,
            "params": arguments,
            "cost": cost,
            "context": {"adapter": "mcp_stdio_proxy"},
        }

    async def list_tools(self) -> list[types.Tool]:
        result = await self.downstream_session.list_tools()
        return result.tools

    async def call_tool(self, name: str, arguments: dict[str, Any] | None) -> types.CallToolResult:
        tool_args = arguments or {}
        decision = evaluate(self._build_evaluate_request(name, tool_args), self.policy)
        if not decision.allowed:
            reason = "; ".join(decision.reasons) if decision.reasons else "Denied by policy"
            raise ValueError(reason)
        try:
            if self.downstream_timeout_seconds is None:
                return await self.downstream_session.call_tool(name=name, arguments=tool_args)

            timeout = timedelta(seconds=self.downstream_timeout_seconds)
            return await self.downstream_session.call_tool(
                name=name,
                arguments=tool_args,
                read_timeout_seconds=timeout,
            )
        except TypeError:
            # Backward compatibility for mocked sessions that don't support timeout kwargs.
            return await self.downstream_session.call_tool(name=name, arguments=tool_args)
        except Exception as error:
            if "timed out" in str(error).lower() or "timeout" in str(error).lower():
                raise TimeoutError("Downstream tool call timeout") from error
            raise


def create_interceptor_from_policy(
    policy_path: str,
    downstream_session: DownstreamSession,
    *,
    default_tool_cost: float = 0.0,
    downstream_timeout_seconds: float | None = None,
) -> McpToolInterceptor:
    """Build interceptor using policy loaded from disk."""
    policy = load_policy(policy_path)
    return McpToolInterceptor(
        policy=policy,
        downstream_session=downstream_session,
        default_tool_cost=default_tool_cost,
        downstream_timeout_seconds=downstream_timeout_seconds,
    )


@asynccontextmanager
async def open_downstream_session(
    *,
    downstream_command: str,
    downstream_args: list[str],
    stdio_client_factory: Any = stdio_client,
    downstream_env: dict[str, str] | None = None,
) -> AsyncIterator[ClientSession]:
    """Open initialized ClientSession to downstream MCP server over stdio."""
    server_params = StdioServerParameters(
        command=downstream_command,
        args=downstream_args,
        env=downstream_env,
    )
    async with stdio_client_factory(server=server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            yield session


def build_proxy_server(interceptor: McpToolInterceptor) -> Server:
    """Build low-level MCP server handlers for tool passthrough/interception."""
    server = Server("orchesis-mcp-proxy")

    @server.list_tools()
    async def handle_list_tools() -> list[types.Tool]:
        return await interceptor.list_tools()

    @server.call_tool()
    async def handle_call_tool(name: str, arguments: dict[str, Any]) -> types.CallToolResult:
        return await interceptor.call_tool(name, arguments)

    return server


async def run_stdio_proxy(settings: McpProxySettings | None = None) -> None:
    """Run Orchesis MCP proxy over stdio."""
    cfg = settings or McpProxySettings.from_env()

    async with open_downstream_session(
        downstream_command=cfg.downstream_command,
        downstream_args=cfg.downstream_args,
    ) as downstream_session:
        interceptor = create_interceptor_from_policy(
            cfg.policy_path,
            downstream_session,
            default_tool_cost=cfg.default_tool_cost,
            downstream_timeout_seconds=cfg.downstream_timeout_seconds,
        )
        server = build_proxy_server(interceptor)
        init_options = InitializationOptions(
            server_name="orchesis-mcp-proxy",
            server_version="0.1.0",
            capabilities=server.get_capabilities(
                notification_options=NotificationOptions(),
                experimental_capabilities={},
            ),
        )
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, init_options)


def main() -> None:
    """CLI entry point to run MCP stdio interceptor."""
    asyncio.run(run_stdio_proxy())


if __name__ == "__main__":
    main()
