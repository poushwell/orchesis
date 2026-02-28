"""Example CrewAI-style task guard using Orchesis."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from orchesis.client import OrchesisClient, OrchesisDenied


@dataclass
class Task:
    tool: str
    params: dict[str, Any]


class CrewAgent:
    def __init__(self, name: str, client: OrchesisClient):
        self.name = name
        self.client = client

    def run_task(self, task: Task) -> str:
        result = self.client.evaluate(
            tool=task.tool,
            params=task.params,
            agent_id=self.name,
            session_id=f"{self.name}-session",
        )
        if not result.allowed:
            raise OrchesisDenied(result.reasons, task.tool)
        return f"task executed by {self.name}: {task.tool}"


def main() -> None:
    client = OrchesisClient("http://localhost:8080", api_token="orch_sk_example")
    agent = CrewAgent("crew_planner", client)
    print(agent.run_task(Task(tool="read_file", params={"path": "/data/plan.md"})))


if __name__ == "__main__":
    main()
