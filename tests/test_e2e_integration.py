from __future__ import annotations

import os
import shlex
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from orchesis.replay import read_events_from_jsonl


def _write_policy(path: Path, *, max_requests: int = 10, daily_budget: float = 5.0) -> None:
    path.write_text(
        f"""
default_trust_tier: intern
agents:
  - id: cursor
    name: Cursor
    trust_tier: operator
  - id: untrusted_bot
    name: Untrusted Bot
    trust_tier: intern
  - id: blocked_agent
    name: Blocked
    trust_tier: blocked
rules:
  - name: budget_limit
    max_cost_per_call: 10.0
    daily_budget: {daily_budget}
  - name: file_access
    allowed_paths: ["/data", "/tmp"]
    denied_paths: ["/etc", "/root"]
  - name: sql_restriction
    denied_operations: ["DROP", "DELETE", "TRUNCATE", "ALTER", "GRANT"]
  - name: rate_limit
    max_requests_per_minute: {max_requests}
  - name: command_pattern_guard
    type: regex_match
    field: params.command
    deny_patterns:
      - '(?i)rm\\s+-rf\\s+'
  - name: context_limits
    type: context_rules
    rules:
      - agent: "*"
        max_cost_per_call: 10.0
  - name: write_guard
    type: composite
    operator: AND
    conditions:
      - rule: file_access
      - rule: budget_limit
""".strip(),
        encoding="utf-8",
    )


def _count_jsonl(path: Path) -> int:
    return (
        sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
        if path.exists()
        else 0
    )


def _first_text(result) -> str:  # noqa: ANN001
    return str(getattr(result.content[0], "text", "")) if result.content else ""


@asynccontextmanager
async def _proxy_session(tmp_path: Path, policy_path: Path):
    calls_log = tmp_path / "mcp_server_calls.jsonl"
    decisions_log = tmp_path / "decisions.jsonl"
    state_log = tmp_path / "state.jsonl"
    env = os.environ.copy()
    env["POLICY_PATH"] = str(policy_path)
    env["DECISIONS_LOG_PATH"] = str(decisions_log)
    env["STATE_PATH"] = str(state_log)
    env["DOWNSTREAM_COMMAND"] = sys.executable
    env["DOWNSTREAM_ARGS"] = " ".join(
        [
            shlex.quote("-m"),
            shlex.quote("orchesis.testing.mcp_server"),
        ]
    )
    env["TEST_MCP_CALL_LOG"] = str(calls_log)

    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "orchesis.mcp_proxy"],
        env=env,
        cwd=Path(__file__).resolve().parents[1],
    )
    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            yield session, calls_log, decisions_log


async def _call(session: ClientSession, tool: str, **kwargs):
    return await session.call_tool(tool, kwargs)


async def _expect_blocked(session: ClientSession, calls: Path, tool: str, reason: str, **kwargs) -> None:
    before = _count_jsonl(calls)
    result = await _call(session, tool, **kwargs)
    after = _count_jsonl(calls)
    assert result.isError is True
    assert reason.lower() in _first_text(result).lower()
    assert after == before


@pytest.mark.asyncio
async def test_e2e_safe_read_allowed(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    _write_policy(policy)
    async with _proxy_session(tmp_path, policy) as (session, _calls, decisions):
        result = await _call(session, "read_file", path="/data/report.csv", agent_id="cursor", cost=0.1)
    assert result.isError is False
    assert "content of /data/report.csv" in _first_text(result)
    events = read_events_from_jsonl(decisions)
    assert events and events[-1].decision == "ALLOW"


@pytest.mark.asyncio
async def test_e2e_dangerous_read_blocked(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    _write_policy(policy)
    async with _proxy_session(tmp_path, policy) as (session, calls, decisions):
        await _expect_blocked(
            session, calls, "read_file", "file_access", path="/etc/passwd", agent_id="cursor", cost=0.1
        )
    assert read_events_from_jsonl(decisions)[-1].decision == "DENY"


@pytest.mark.asyncio
async def test_e2e_sql_injection_blocked(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    _write_policy(policy)
    async with _proxy_session(tmp_path, policy) as (session, calls, _decisions):
        await _expect_blocked(
            session, calls, "run_sql", "drop is denied", query="DROP TABLE users", agent_id="cursor", cost=0.1
        )


@pytest.mark.asyncio
async def test_e2e_blocked_agent_denied(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    _write_policy(policy)
    async with _proxy_session(tmp_path, policy) as (session, calls, _decisions):
        await _expect_blocked(
            session, calls, "read_file", "blocked", path="/data/safe.txt", agent_id="blocked_agent", cost=0.1
        )


@pytest.mark.asyncio
async def test_e2e_intern_write_denied(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    _write_policy(policy)
    async with _proxy_session(tmp_path, policy) as (session, calls, _decisions):
        await _expect_blocked(
            session,
            calls,
            "write_file",
            "intern",
            path="/data/hack.txt",
            content="x",
            agent_id="untrusted_bot",
            cost=0.1,
        )


@pytest.mark.asyncio
async def test_e2e_rate_limit_enforcement(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    _write_policy(policy, max_requests=10)
    async with _proxy_session(tmp_path, policy) as (session, _calls, _decisions):
        results = [
            await _call(
                session,
                "read_file",
                path=f"/data/file-{i}.txt",
                agent_id="cursor",
                session_id="s-rate",
                cost=0.0,
            )
            for i in range(15)
        ]
    allow = sum(1 for item in results if not item.isError)
    deny = sum(1 for item in results if item.isError)
    assert allow == 10
    assert deny == 5


@pytest.mark.asyncio
async def test_e2e_budget_enforcement(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    _write_policy(policy, daily_budget=5.0)
    async with _proxy_session(tmp_path, policy) as (session, _calls, _decisions):
        first = await _call(session, "expensive_operation", cost=2.0, agent_id="cursor", session_id="s-budget")
        second = await _call(session, "expensive_operation", cost=2.0, agent_id="cursor", session_id="s-budget")
        third = await _call(session, "expensive_operation", cost=2.0, agent_id="cursor", session_id="s-budget")
    assert first.isError is False
    assert second.isError is False
    assert third.isError is True


@pytest.mark.asyncio
async def test_e2e_full_audit_trail(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    _write_policy(policy)
    async with _proxy_session(tmp_path, policy) as (session, _calls, decisions):
        for i in range(5):
            await _call(session, "read_file", path=f"/data/safe-{i}.txt", agent_id="cursor", cost=0.1)
        for _ in range(5):
            await _call(session, "read_file", path="/etc/passwd", agent_id="cursor", cost=0.1)
    events = read_events_from_jsonl(decisions)
    assert len(events) == 10
    assert all(item.agent_id == "cursor" for item in events)
    assert all(item.tool == "read_file" for item in events)
    assert len({item.policy_version for item in events}) == 1


@pytest.mark.asyncio
async def test_e2e_debug_mode(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    _write_policy(policy)
    async with _proxy_session(tmp_path, policy) as (session, _calls, _decisions):
        result = await _call(session, "read_file", path="/etc/passwd", agent_id="cursor", cost=0.1, debug=True)
    assert result.isError is True
    text = "\n".join(str(getattr(item, "text", "")) for item in result.content)
    assert "debug_trace" in text


@pytest.mark.asyncio
async def test_e2e_policy_hot_reload(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    _write_policy(policy, daily_budget=10.0)
    async with _proxy_session(tmp_path, policy) as (session, _calls, _decisions):
        first = await _call(session, "expensive_operation", cost=8.0, agent_id="cursor", session_id="hot-reload")
        _write_policy(policy, daily_budget=5.0)
        time.sleep(0.02)
        second = await _call(session, "expensive_operation", cost=8.0, agent_id="cursor", session_id="hot-reload-2")
    assert first.isError is False
    assert second.isError is True
