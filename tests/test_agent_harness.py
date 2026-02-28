from __future__ import annotations

import json
from pathlib import Path

from orchesis.agent.harness import SimpleAgent


def _write_policy(path: Path) -> None:
    path.write_text(
        """
rules:
  - name: budget_limit
    max_cost_per_call: 0.5
  - name: file_access
    allowed_paths:
      - "/data"
      - "/tmp"
    denied_paths:
      - "/etc"
      - "/root"
  - name: sql_restriction
    denied_operations:
      - "DROP"
      - "DELETE"
  - name: rate_limit
    max_requests_per_minute: 100
""".strip(),
        encoding="utf-8",
    )


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def _new_agent(tmp_path: Path) -> SimpleAgent:
    policy_path = tmp_path / "policy.yaml"
    _write_policy(policy_path)
    return SimpleAgent(
        policy_path=str(policy_path),
        tools=[],
        tasks_path=Path(__file__).resolve().parents[1] / "examples" / "agent_tasks.yaml",
        log_path=tmp_path / "decisions.jsonl",
    )


def test_safe_task_completes_all_steps(tmp_path: Path) -> None:
    agent = _new_agent(tmp_path)
    state = agent.run("analyze_sales_data")

    assert state.status == "completed"
    assert len(state.steps) == 3
    assert all(step["decision"] == "ALLOW" for step in state.steps)


def test_dangerous_task_blocks_correctly(tmp_path: Path) -> None:
    agent = _new_agent(tmp_path)
    state = agent.run("dangerous_cleanup")

    assert state.status == "completed"
    assert len(state.steps) == 3
    assert state.steps[0]["decision"] == "DENY"
    assert state.steps[1]["decision"] == "DENY"
    assert state.steps[2]["decision"] == "ALLOW"
    assert any("file_access" in reason for reason in state.steps[0]["reasons"])
    assert any("sql_restriction" in reason for reason in state.steps[1]["reasons"])


def test_budget_task_blocks_expensive_calls(tmp_path: Path) -> None:
    agent = _new_agent(tmp_path)
    state = agent.run("budget_burn")

    assert state.status == "completed"
    assert len(state.steps) == 3
    assert state.steps[0]["decision"] == "DENY"
    assert state.steps[1]["decision"] == "DENY"
    assert state.steps[2]["decision"] == "ALLOW"
    assert any("budget_limit" in reason for reason in state.steps[0]["reasons"])


def test_agent_respects_max_steps(tmp_path: Path) -> None:
    agent = _new_agent(tmp_path)
    state = agent.run("analyze_sales_data", max_steps=2)

    assert state.status == "failed"
    assert len(state.steps) == 2
    assert state.current_step == 2


def test_agent_state_history_is_complete(tmp_path: Path) -> None:
    agent = _new_agent(tmp_path)
    state = agent.run("dangerous_cleanup")

    for idx, step in enumerate(state.steps, start=1):
        assert step["step"] == idx
        assert "tool" in step
        assert "params" in step
        assert "decision" in step
        assert "reasons" in step


def test_all_decisions_logged_to_jsonl(tmp_path: Path) -> None:
    agent = _new_agent(tmp_path)
    state = agent.run("dangerous_cleanup")
    log_path = tmp_path / "decisions.jsonl"
    entries = _read_jsonl(log_path)

    assert len(entries) == len(state.steps)
    assert [e["decision"] for e in entries] == [s["decision"] for s in state.steps]
