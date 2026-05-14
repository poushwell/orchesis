"""OpenAI Agents SDK stress-test setup."""

from __future__ import annotations

FRAMEWORK_AVAILABLE = False
MISSING_REASON = ""

try:
    from agents import Agent, Runner  # type: ignore

    FRAMEWORK_AVAILABLE = True
except Exception as exc:  # noqa: BLE001
    MISSING_REASON = str(exc)
    Agent = object  # type: ignore
    Runner = object  # type: ignore

from llm_runtime import run_agent_conversation


class OpenAIAgentsStressAgent:
    """OpenAI-Agents-flavored wrapper around tool runtime."""

    def __init__(self):
        self.system_prompt = "You are an OpenAI Agents SDK assistant with tools."
        self.agent = None
        self.runner = None
        if FRAMEWORK_AVAILABLE:
            self.agent = Agent(name="StressTestAgent", instructions=self.system_prompt, model="gpt-4o-mini")
            self.runner = Runner

    def process_message(self, user_message: str, *, guard=None) -> str:
        return run_agent_conversation(
            system_prompt=self.system_prompt,
            user_message=user_message,
            guard=guard,
            model="gpt-4o-mini",
        )
