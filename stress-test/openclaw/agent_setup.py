"""Simulated OpenClaw-style agent setup for stress-test."""

from __future__ import annotations

from llm_runtime import run_agent_conversation


class MockOpenClawAgent:
    """OpenClaw-like agent that uses OpenAI tool calling."""

    def __init__(self):
        self.system_prompt = "You are a helpful AI assistant with access to tools."

    def process_message(self, user_message: str, *, guard=None) -> str:
        return run_agent_conversation(
            system_prompt=self.system_prompt,
            user_message=user_message,
            guard=guard,
            model="gpt-4o-mini",
        )
