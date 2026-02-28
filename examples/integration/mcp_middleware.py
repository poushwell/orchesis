"""Example: MCP-style middleware with Orchesis pre-checks."""

from __future__ import annotations

from typing import Any

from orchesis.client import OrchesisClient, OrchesisDenied


class MCPServer:
    """Minimal MCP-like server skeleton for demonstration only."""

    def handle_tool_call(self, tool: str, params: dict[str, Any]) -> dict[str, Any]:
        return {"ok": True, "tool": tool, "params": params}


class OrchesisMCPMiddleware:
    def __init__(self, server: MCPServer, client: OrchesisClient, agent_id: str):
        self._server = server
        self._client = client
        self._agent_id = agent_id

    def handle_tool_call(self, tool: str, params: dict[str, Any]) -> dict[str, Any]:
        result = self._client.evaluate(tool=tool, params=params, agent_id=self._agent_id)
        if not result:
            raise OrchesisDenied(result.reasons, tool)
        return self._server.handle_tool_call(tool, params)


def main() -> None:
    client = OrchesisClient("http://localhost:8080", api_token="orch_sk_example")
    server = MCPServer()
    guarded = OrchesisMCPMiddleware(server, client, agent_id="mcp_agent")
    print(guarded.handle_tool_call("read_file", {"path": "/data/readme.txt"}))


if __name__ == "__main__":
    main()
