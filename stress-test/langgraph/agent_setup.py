"""LangGraph stress-test agent setup."""

from __future__ import annotations

FRAMEWORK_AVAILABLE = False
MISSING_REASON = ""

try:
    from langgraph.graph import END, StateGraph  # type: ignore

    FRAMEWORK_AVAILABLE = True
except Exception as exc:  # noqa: BLE001
    MISSING_REASON = str(exc)
    END = "__END__"  # type: ignore
    StateGraph = object  # type: ignore

from llm_runtime import run_agent_conversation


class LangGraphStressAgent:
    """LangGraph-flavored wrapper around OpenAI tool runtime."""

    def __init__(self):
        self.system_prompt = "You are a LangGraph assistant with tool access."
        self.graph = None
        if FRAMEWORK_AVAILABLE:
            graph = StateGraph(dict)
            graph.add_node("agent", lambda state: state)
            graph.set_entry_point("agent")
            graph.add_edge("agent", END)
            self.graph = graph.compile()

    def process_message(self, user_message: str, *, guard=None) -> str:
        return run_agent_conversation(
            system_prompt=self.system_prompt,
            user_message=user_message,
            guard=guard,
            model="gpt-4o-mini",
        )
