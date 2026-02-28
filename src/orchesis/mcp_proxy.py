"""MCP stdio-to-stdio interceptor that applies Orchesis policy checks."""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any, Protocol

import mcp.server.stdio
import mcp.types as types
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.models import InitializationOptions

from orchesis.config import load_agent_registry, load_policy
from orchesis.engine import evaluate
from orchesis.identity import AgentRegistry
from orchesis.mcp_config import McpProxySettings
from orchesis.state import RateLimitTracker
from orchesis.telemetry import EventEmitter, JsonlEmitter


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
    registry: AgentRegistry | None = None
    state: RateLimitTracker | None = None
    emitter: EventEmitter | None = None
    policy_path: str | None = None
    _policy_hash: str | None = None

    def _build_evaluate_request(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any], bool]:
        tool_args = dict(arguments)
        raw_cost = tool_args.pop("cost", self.default_tool_cost)
        cost = float(raw_cost) if isinstance(raw_cost, int | float) else self.default_tool_cost
        context: dict[str, Any] = {"adapter": "mcp_stdio_proxy"}
        agent_id = tool_args.pop("agent_id", None)
        session_id = tool_args.pop("session_id", None)
        debug_flag = bool(tool_args.pop("debug", False))
        if isinstance(agent_id, str) and agent_id.strip():
            context["agent"] = agent_id.strip()
        if isinstance(session_id, str) and session_id.strip():
            context["session"] = session_id.strip()
        return (
            {
                "tool": tool_name,
                "params": tool_args,
                "cost": cost,
                "context": context,
            },
            tool_args,
            debug_flag,
        )

    def _maybe_reload_policy(self) -> None:
        if not self.policy_path:
            return
        policy_file = Path(self.policy_path)
        if not policy_file.exists():
            return
        current_hash = str(policy_file.stat().st_mtime_ns)
        if current_hash == self._policy_hash:
            return
        self.policy = load_policy(str(policy_file))
        has_identity = "agents" in self.policy or "default_trust_tier" in self.policy
        self.registry = load_agent_registry(self.policy) if has_identity else None
        self._policy_hash = current_hash

    def _append_debug(
        self, result: types.CallToolResult, debug_trace: dict[str, Any] | None
    ) -> types.CallToolResult:
        if not isinstance(debug_trace, dict):
            return result
        content = list(result.content)
        content.append(
            types.TextContent(
                type="text",
                text=json.dumps({"debug_trace": debug_trace}, ensure_ascii=False),
            )
        )
        return types.CallToolResult(content=content, isError=result.isError)

    async def list_tools(self) -> list[types.Tool]:
        result = await self.downstream_session.list_tools()
        return result.tools

    async def call_tool(self, name: str, arguments: dict[str, Any] | None) -> types.CallToolResult:
        self._maybe_reload_policy()
        tool_args = arguments or {}
        eval_request, cleaned_args, debug = self._build_evaluate_request(name, tool_args)
        tracker = self.state or RateLimitTracker(persist_path=None)
        decision = evaluate(
            eval_request,
            self.policy,
            state=tracker,
            emitter=self.emitter,
            registry=self.registry,
            debug=debug,
        )
        if not decision.allowed:
            reason = "; ".join(decision.reasons) if decision.reasons else "Denied by policy"
            if debug and isinstance(decision.debug_trace, dict):
                reason = (
                    f"{reason}\ndebug_trace={json.dumps(decision.debug_trace, ensure_ascii=False)}"
                )
            raise ValueError(reason)
        try:
            if self.downstream_timeout_seconds is None:
                result = await self.downstream_session.call_tool(name=name, arguments=cleaned_args)
            else:
                timeout = timedelta(seconds=self.downstream_timeout_seconds)
                result = await self.downstream_session.call_tool(
                    name=name,
                    arguments=cleaned_args,
                    read_timeout_seconds=timeout,
                )
        except TypeError:
            # Backward compatibility for mocked sessions that don't support timeout kwargs.
            result = await self.downstream_session.call_tool(name=name, arguments=cleaned_args)
        except Exception as error:
            if "timed out" in str(error).lower() or "timeout" in str(error).lower():
                raise TimeoutError("Downstream tool call timeout") from error
            raise
        return self._append_debug(result, decision.debug_trace if debug else None)


def create_interceptor_from_policy(
    policy_path: str,
    downstream_session: DownstreamSession,
    *,
    default_tool_cost: float = 0.0,
    downstream_timeout_seconds: float | None = None,
) -> McpToolInterceptor:
    """Build interceptor using policy loaded from disk."""
    policy = load_policy(policy_path)
    has_identity = "agents" in policy or "default_trust_tier" in policy
    registry = load_agent_registry(policy) if has_identity else None
    return McpToolInterceptor(
        policy=policy,
        downstream_session=downstream_session,
        default_tool_cost=default_tool_cost,
        downstream_timeout_seconds=downstream_timeout_seconds,
        registry=registry,
        state=RateLimitTracker(persist_path=None),
        policy_path=policy_path,
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
        decisions_log_path = os.getenv("DECISIONS_LOG_PATH")
        state_path = os.getenv("STATE_PATH")
        if isinstance(decisions_log_path, str) and decisions_log_path.strip():
            interceptor.emitter = JsonlEmitter(decisions_log_path.strip())
        if isinstance(state_path, str) and state_path.strip():
            interceptor.state = RateLimitTracker(persist_path=state_path.strip())
        interceptor._policy_hash = str(Path(cfg.policy_path).stat().st_mtime_ns)
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
