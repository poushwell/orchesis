"""Simple deterministic agent loop integrated with Orchesis decisions."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from orchesis.agent.planner import load_task_catalog, resolve_task_steps
from orchesis.config import load_agent_registry, load_policy
from orchesis.engine import evaluate
from orchesis.logger import append_decision
from orchesis.models import Decision
from orchesis.state import RateLimitTracker


@dataclass
class AgentState:
    task: str
    steps: list[dict[str, Any]] = field(default_factory=list)
    current_step: int = 0
    max_steps: int = 10
    status: str = "running"  # running | completed | blocked | failed


class SimpleAgent:
    def __init__(
        self,
        policy_path: str,
        tools: list[dict[str, Any]],
        *,
        tasks_path: str | Path = "examples/agent_tasks.yaml",
        log_path: str | Path = "decisions.jsonl",
    ):
        self.policy = load_policy(policy_path)
        has_identity_config = "agents" in self.policy or "default_trust_tier" in self.policy
        self.registry = load_agent_registry(self.policy) if has_identity_config else None
        self.tools = tools
        self.tasks_path = Path(tasks_path)
        self.log_path = Path(log_path)
        self.catalog = load_task_catalog(self.tasks_path)

    def run(self, task: str, *, max_steps: int = 10) -> AgentState:
        """Main loop: plan -> verify -> execute -> repeat."""
        state = AgentState(task=task, max_steps=max_steps)
        tracker = RateLimitTracker(persist_path=None)

        while state.current_step < state.max_steps:
            action = self.plan_next_action(state)
            if action is None:
                state.status = "completed"
                break

            decision = self.verify_action(action, tracker=tracker)
            effective_agent = (
                action.get("context", {}).get("agent")
                if isinstance(action.get("context"), dict)
                and isinstance(action.get("context", {}).get("agent"), str)
                else "cursor"
            )
            identity = self.registry.get(effective_agent) if self.registry is not None else None
            step_record: dict[str, Any] = {
                "step": state.current_step + 1,
                "tool": action["tool"],
                "params": action.get("params", {}),
                "agent": effective_agent,
                "trust_tier": identity.trust_tier.name.lower() if identity is not None else "n/a",
                "cost": action.get("cost", 0.0),
                "decision": "ALLOW" if decision.allowed else "DENY",
                "reasons": decision.reasons,
            }

            request = {
                "tool": action["tool"],
                "params": action.get("params", {}),
                "cost": action.get("cost", 0.0),
                "context": {
                    "task": state.task,
                    "agent": "cursor",
                    **(action.get("context") if isinstance(action.get("context"), dict) else {}),
                },
            }
            append_decision(decision, request, self.log_path)

            if decision.allowed:
                execution = self.execute_action(action)
                step_record["result"] = execution
            else:
                self.handle_block(state, decision)

            state.steps.append(step_record)
            state.current_step += 1

        if state.status == "running":
            # Max steps reached before completing planned sequence.
            state.status = "failed"

        return state

    def plan_next_action(self, state: AgentState) -> dict[str, Any] | None:
        """Deterministic mapping: task + history -> next action."""
        task_steps = resolve_task_steps(state.task, self.catalog)
        if state.current_step >= len(task_steps):
            return None
        action = task_steps[state.current_step]
        if not isinstance(action, dict) or "tool" not in action:
            raise ValueError(f"Invalid task step at index {state.current_step}")
        return action

    def verify_action(self, action: dict[str, Any], *, tracker: RateLimitTracker) -> Decision:
        """Pass action through Orchesis evaluate()."""
        request = {
            "tool": action["tool"],
            "params": action.get("params", {}),
            "cost": action.get("cost", 0.0),
            "context": {
                "agent": "cursor",
                **(action.get("context") if isinstance(action.get("context"), dict) else {}),
            },
        }
        return evaluate(request, self.policy, state=tracker, registry=self.registry)

    def execute_action(self, action: dict[str, Any]) -> dict[str, Any]:
        """Execute allowed tool call via deterministic stubs."""
        tool = action["tool"]
        params = action.get("params", {})

        if tool == "read_file":
            path = params.get("path", "")
            return {"status": "ok", "content": f"stub content from {path}"}
        if tool == "delete_file":
            return {"status": "ok", "message": "deleted"}
        if tool == "run_sql":
            query = str(params.get("query", ""))
            if query.strip().upper().startswith("SELECT SUM"):
                return {"status": "ok", "result": "1000"}
            return {"status": "ok", "result": "executed"}
        if tool == "write_file":
            return {"status": "ok", "message": "written"}
        if tool == "api_call":
            endpoint = params.get("endpoint", "unknown")
            return {"status": "ok", "message": f"called {endpoint}"}

        return {"status": "ok", "message": f"tool {tool} executed"}

    def handle_block(self, state: AgentState, decision: Decision) -> None:
        """Handle blocked action. Current strategy: record and continue."""
        _ = decision
        state.status = "running"
