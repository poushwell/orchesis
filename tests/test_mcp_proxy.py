from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import pytest
import mcp.types as types

from orchesis.mcp_proxy import (
    McpToolInterceptor,
    create_interceptor_from_policy,
    open_downstream_session,
)


class FakeDownstreamSession:
    def __init__(self) -> None:
        self.list_tools_result = types.ListToolsResult(
            tools=[
                types.Tool(
                    name="get_data",
                    description="Get data",
                    inputSchema={"type": "object", "properties": {}},
                )
            ]
        )
        self.call_tool_result = types.CallToolResult(
            content=[types.TextContent(type="text", text="ok")],
            isError=False,
        )
        self.call_count = 0
        self.last_call: tuple[str, dict[str, object]] | None = None
        self.raise_on_call: Exception | None = None

    async def list_tools(self) -> types.ListToolsResult:
        return self.list_tools_result

    async def call_tool(self, name: str, arguments: dict[str, object]) -> types.CallToolResult:
        self.call_count += 1
        self.last_call = (name, arguments)
        if self.raise_on_call is not None:
            raise self.raise_on_call
        return self.call_tool_result


@pytest.mark.asyncio
async def test_tools_passthrough_returns_downstream_tools() -> None:
    downstream = FakeDownstreamSession()
    interceptor = McpToolInterceptor(policy={"rules": []}, downstream_session=downstream)

    tools = await interceptor.list_tools()

    assert len(tools) == 1
    assert tools[0].name == "get_data"


@pytest.mark.asyncio
async def test_allow_forward_calls_downstream_and_returns_result() -> None:
    policy = {"rules": [{"name": "sql_restriction", "denied_operations": ["DROP"]}]}
    downstream = FakeDownstreamSession()
    interceptor = McpToolInterceptor(policy=policy, downstream_session=downstream)

    result = await interceptor.call_tool("get_data", {"query": "SELECT 1"})

    assert downstream.call_count == 1
    assert downstream.last_call == ("get_data", {"query": "SELECT 1"})
    assert result.isError is False


@pytest.mark.asyncio
async def test_deny_block_does_not_call_downstream() -> None:
    policy = {"rules": [{"name": "sql_restriction", "denied_operations": ["DROP"]}]}
    downstream = FakeDownstreamSession()
    interceptor = McpToolInterceptor(policy=policy, downstream_session=downstream)

    with pytest.raises(ValueError, match="sql_restriction: DROP is denied"):
        await interceptor.call_tool("sql_query", {"query": "DROP TABLE users"})

    assert downstream.call_count == 0


@pytest.mark.asyncio
async def test_unknown_tool_error_passthrough_from_downstream() -> None:
    downstream = FakeDownstreamSession()
    downstream.raise_on_call = ValueError("Unknown tool: missing_tool")
    interceptor = McpToolInterceptor(policy={"rules": []}, downstream_session=downstream)

    with pytest.raises(ValueError, match="Unknown tool: missing_tool"):
        await interceptor.call_tool("missing_tool", {})

    assert downstream.call_count == 1


@pytest.mark.asyncio
async def test_open_downstream_session_initializes_and_closes(monkeypatch) -> None:
    events: list[str] = []

    class FakeClientSession:
        def __init__(self, _read: object, _write: object) -> None:
            events.append("session:init")

        async def __aenter__(self) -> FakeClientSession:
            events.append("session:enter")
            return self

        async def __aexit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
            _ = (exc_type, exc, tb)
            events.append("session:exit")

        async def initialize(self) -> None:
            events.append("session:initialize")

    @asynccontextmanager
    async def fake_stdio_client(*, server) -> AsyncIterator[tuple[object, object]]:  # type: ignore[no-untyped-def]
        _ = server
        events.append("stdio:enter")
        yield object(), object()
        events.append("stdio:exit")

    monkeypatch.setattr("orchesis.mcp_proxy.ClientSession", FakeClientSession)

    async with open_downstream_session(
        downstream_command="python",
        downstream_args=["server.py"],
        stdio_client_factory=fake_stdio_client,
    ) as _session:
        assert _session is not None
        events.append("inside")

    assert events == [
        "stdio:enter",
        "session:init",
        "session:enter",
        "session:initialize",
        "inside",
        "session:exit",
        "stdio:exit",
    ]


def test_create_interceptor_from_policy_loads_policy(tmp_path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
rules:
  - name: budget_limit
    max_cost_per_call: 0.5
""".strip(),
        encoding="utf-8",
    )
    downstream = FakeDownstreamSession()

    interceptor = create_interceptor_from_policy(str(policy_path), downstream)

    assert interceptor.policy["rules"][0]["name"] == "budget_limit"
