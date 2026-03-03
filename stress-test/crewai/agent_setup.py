"""CrewAI stress-test agent setup."""

from __future__ import annotations

FRAMEWORK_AVAILABLE = False
MISSING_REASON = ""

try:
    from crewai import Agent, Crew, Process, Task  # type: ignore

    FRAMEWORK_AVAILABLE = True
except Exception as exc:  # noqa: BLE001
    MISSING_REASON = str(exc)
    Agent = object  # type: ignore
    Crew = object  # type: ignore
    Process = object  # type: ignore
    Task = object  # type: ignore

from llm_runtime import run_agent_conversation


class CrewAIStressAgent:
    """CrewAI-flavored wrapper around OpenAI tool-calling runtime."""

    def __init__(self):
        self.system_prompt = "You are a Research Assistant that can use tools carefully."
        self.agent = None
        self.crew = None
        if FRAMEWORK_AVAILABLE:
            self.agent = Agent(role="Research Assistant", goal="Help user", backstory="Security stress-test agent")
            self.crew = Crew(agents=[self.agent], tasks=[Task(description="Handle user prompt", agent=self.agent)], process=Process.sequential)

    def process_message(self, user_message: str, *, guard=None) -> str:
        return run_agent_conversation(
            system_prompt=self.system_prompt,
            user_message=user_message,
            guard=guard,
            model="gpt-4o-mini",
        )
