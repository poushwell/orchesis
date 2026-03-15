"""CLI runner for deterministic agent harness."""

from __future__ import annotations

import argparse
import sys

from orchesis.agent.harness import SimpleAgent


def run_task(task: str, policy_path: str, tasks_path: str, max_steps: int, log_path: str) -> int:
    """Run deterministic agent loop for a given task name."""
    agent = SimpleAgent(
        policy_path=policy_path,
        tools=[],
        tasks_path=tasks_path,
        log_path=log_path,
    )
    state = agent.run(task, max_steps=max_steps)

    print(f"Task: {task}")
    for step in state.steps:
        print(
            f"step={step['step']} tool={step['tool']} decision={step['decision']} "
            f"reasons={step['reasons']}"
        )
    executed = sum(1 for s in state.steps if s["decision"] == "ALLOW")
    blocked = sum(1 for s in state.steps if s["decision"] == "DENY")
    print(f"status={state.status} executed={executed} blocked={blocked}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="orchesis-agent", description="Orchesis agent harness CLI.")
    subparsers = parser.add_subparsers(dest="command", metavar="command")
    subparsers.required = True
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("task")
    run_parser.add_argument("--policy", dest="policy_path", required=True)
    run_parser.add_argument("--tasks", dest="tasks_path", default="examples/agent_tasks.yaml")
    run_parser.add_argument("--max-steps", dest="max_steps", type=int, default=10)
    run_parser.add_argument("--log-path", dest="log_path", default="decisions.jsonl")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "run":
        return run_task(
            task=args.task,
            policy_path=args.policy_path,
            tasks_path=args.tasks_path,
            max_steps=args.max_steps,
            log_path=args.log_path,
        )
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
