"""Run deterministic agent harness demo over sample tasks."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from orchesis.agent.harness import SimpleAgent
from orchesis.cli import main as orchesis_cli
from orchesis.policy_store import PolicyStore


def _print_task_result(task_name: str, state) -> None:  # type: ignore[no-untyped-def]
    print(f"\nTask: {task_name}")
    for step in state.steps:
        tool = step["tool"]
        params = step["params"]
        agent = step.get("agent", "cursor")
        trust_tier = step.get("trust_tier", "intern")
        decision = step["decision"]
        reasons = step["reasons"]
        print(
            f"- step {step['step']}: agent={agent} tier={trust_tier} "
            f"tool={tool} params={params} decision={decision}"
        )
        if decision == "DENY":
            print(f"  reason={'; '.join(reasons)}")
    executed = sum(1 for s in state.steps if s["decision"] == "ALLOW")
    blocked = sum(1 for s in state.steps if s["decision"] == "DENY")
    print(f"Final: status={state.status} executed={executed} blocked={blocked}")


def main() -> None:
    project_root = Path(__file__).resolve().parent
    policy_path = project_root / "examples" / "policy.yaml"
    log_path = project_root / "decisions.jsonl"
    if log_path.exists():
        log_path.unlink()

    store = PolicyStore()
    version = store.load(str(policy_path))
    print(f"Policy version: {version.version_id[:12]} loaded_at={version.loaded_at}")
    print("Registered agents:")
    for agent_id in sorted(version.registry.agents):
        identity = version.registry.agents[agent_id]
        print(f"- {agent_id}: tier={identity.trust_tier.name.lower()}")

    agent = SimpleAgent(
        policy_path=str(policy_path),
        tools=[],
        tasks_path=str(project_root / "examples" / "agent_tasks.yaml"),
        log_path=log_path,
    )

    task_plan = [
        ("analyze_sales_data", 10),
        ("untrusted_agent_attempt", 10),
        ("unknown_agent_attempt", 10),
        ("admin_agent_attempt", 10),
        ("blocked_agent_attempt", 10),
    ]
    for task, max_steps in task_plan:
        state = agent.run(task, max_steps=max_steps)
        _print_task_result(task, state)

    print("\nAudit summary:")
    runner = CliRunner()
    result = runner.invoke(orchesis_cli, ["audit", "--limit", "20"])
    print(result.output.strip())

    print("\nForensic (cursor):")
    forensic = runner.invoke(orchesis_cli, ["forensic", "--agent", "cursor", "--log", str(log_path)])
    print(forensic.output.strip())


if __name__ == "__main__":
    main()
