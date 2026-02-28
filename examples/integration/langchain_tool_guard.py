"""Example LangChain-like tool wrapper with Orchesis guard."""

from __future__ import annotations


from orchesis.client import OrchesisClient


class BaseTool:
    name = "tool"

    def _run(self, query: str) -> str:
        raise NotImplementedError


class EchoSqlTool(BaseTool):
    name = "run_sql"

    def _run(self, query: str) -> str:
        return f"executed: {query}"


class OrchesisGuardedTool(BaseTool):
    def __init__(self, wrapped_tool: BaseTool, client: OrchesisClient, agent_id: str):
        self.wrapped_tool = wrapped_tool
        self.orchesis = client
        self.agent_id = agent_id
        self.name = wrapped_tool.name

    def _run(self, query: str) -> str:
        if not self.orchesis.is_allowed(
            self.name, params={"query": query}, agent_id=self.agent_id
        ):
            return "Tool call denied by policy"
        return self.wrapped_tool._run(query)


def main() -> None:
    client = OrchesisClient("http://localhost:8080", api_token="orch_sk_example")
    tool = OrchesisGuardedTool(EchoSqlTool(), client, agent_id="langchain_agent")
    print(tool._run("SELECT * FROM users"))
    print(tool._run("DROP TABLE users"))


if __name__ == "__main__":
    main()
