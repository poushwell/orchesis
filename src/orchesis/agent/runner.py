"""CLI runner for deterministic agent harness."""

from __future__ import annotations

import click

from orchesis.agent.harness import SimpleAgent


@click.group()
def main() -> None:
    """Orchesis agent harness CLI."""


@main.command("run")
@click.argument("task")
@click.option("--policy", "policy_path", type=click.Path(exists=True), required=True)
@click.option("--tasks", "tasks_path", type=click.Path(exists=True), default="examples/agent_tasks.yaml")
@click.option("--max-steps", type=int, default=10)
@click.option("--log-path", type=click.Path(), default="decisions.jsonl")
def run_task(task: str, policy_path: str, tasks_path: str, max_steps: int, log_path: str) -> None:
    """Run deterministic agent loop for a given task name."""
    agent = SimpleAgent(
        policy_path=policy_path,
        tools=[],
        tasks_path=tasks_path,
        log_path=log_path,
    )
    state = agent.run(task, max_steps=max_steps)

    click.echo(f"Task: {task}")
    for step in state.steps:
        click.echo(
            f"step={step['step']} tool={step['tool']} decision={step['decision']} "
            f"reasons={step['reasons']}"
        )
    executed = sum(1 for s in state.steps if s["decision"] == "ALLOW")
    blocked = sum(1 for s in state.steps if s["decision"] == "DENY")
    click.echo(f"status={state.status} executed={executed} blocked={blocked}")


if __name__ == "__main__":
    main()
