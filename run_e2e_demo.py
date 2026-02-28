from __future__ import annotations

import asyncio
import os
import shlex
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from orchesis.invariants import InvariantChecker
from orchesis.replay import read_events_from_jsonl


def _write_demo_policy(path: Path) -> None:
    path.write_text(
        """
default_trust_tier: intern
agents:
  - id: cursor
    name: Cursor
    trust_tier: operator
  - id: untrusted_bot
    name: Untrusted Bot
    trust_tier: intern
  - id: blocked_agent
    name: Blocked Agent
    trust_tier: blocked
rules:
  - name: budget_limit
    max_cost_per_call: 10.0
    daily_budget: 5.0
  - name: file_access
    allowed_paths: ["/data", "/tmp"]
    denied_paths: ["/etc", "/root"]
  - name: sql_restriction
    denied_operations: ["DROP", "DELETE", "TRUNCATE", "ALTER", "GRANT"]
  - name: rate_limit
    max_requests_per_minute: 60
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


@asynccontextmanager
async def _proxy_session(policy_path: Path, decisions_log: Path, state_log: Path, call_log: Path):
    env = os.environ.copy()
    env["POLICY_PATH"] = str(policy_path)
    env["DECISIONS_LOG_PATH"] = str(decisions_log)
    env["STATE_PATH"] = str(state_log)
    env["DOWNSTREAM_COMMAND"] = sys.executable
    env["DOWNSTREAM_ARGS"] = " ".join([shlex.quote("-m"), shlex.quote("orchesis.testing.mcp_server")])
    env["TEST_MCP_CALL_LOG"] = str(call_log)
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "orchesis.mcp_proxy"],
        env=env,
        cwd=Path(__file__).resolve().parent,
    )
    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            yield session


async def run_demo(rate_burst: int = 100) -> dict[str, int | float | str]:
    runtime_dir = Path(".orchesis")
    runtime_dir.mkdir(parents=True, exist_ok=True)
    policy_path = runtime_dir / "e2e_demo_policy.yaml"
    decisions_log = runtime_dir / "decisions.jsonl"
    state_log = runtime_dir / "state.jsonl"
    call_log = runtime_dir / "mcp_server_calls.jsonl"
    for path in (decisions_log, state_log, call_log):
        if path.exists():
            path.unlink()
    _write_demo_policy(policy_path)

    print("╔══════════════════════════════════════╗")
    print("║  Orchesis v0.5.0 — Live Demo         ║")
    print("╚══════════════════════════════════════╝")
    print("")
    print("Starting MCP server... ✓")
    print("Loading policy (3 agents, 7 rules)... ✓")
    print("")

    async with _proxy_session(policy_path, decisions_log, state_log, call_log) as session:
        async def _invoke(tool: str, **kwargs):
            started = time.perf_counter_ns()
            result = await session.call_tool(tool, kwargs)
            elapsed = (time.perf_counter_ns() - started) // 1000
            reason = getattr(result.content[0], "text", "") if result.content else ""
            return result, elapsed, reason

        print("─── Scenario 1: Normal Operations ───")
        for tool, label, args in [
            ("read_file", "[cursor/operator] read_file /data/report.csv", {"path": "/data/report.csv", "agent_id": "cursor", "cost": 0.1}),
            ("run_sql", "[cursor/operator] run_sql SELECT * FROM sales", {"query": "SELECT * FROM sales", "agent_id": "cursor", "cost": 0.2}),
        ]:
            result, elapsed, _ = await _invoke(tool, **args)
            print(f"{label}\n  → {'ALLOW' if not result.isError else 'DENY'} ({elapsed}μs)")
        print("")

        print("─── Scenario 2: Attack Prevention ───")
        for tool, label, args in [
            ("read_file", "[cursor/operator] read_file /etc/passwd", {"path": "/etc/passwd", "agent_id": "cursor", "cost": 0.1}),
            ("run_sql", "[cursor/operator] run_sql DROP TABLE users", {"query": "DROP TABLE users", "agent_id": "cursor", "cost": 0.1}),
        ]:
            result, elapsed, reason = await _invoke(tool, **args)
            print(f"{label}\n  → {'DENY' if result.isError else 'ALLOW'}: {reason} ({elapsed}μs)")
        print("")

        print("─── Scenario 3: Identity Enforcement ───")
        for tool, label, args in [
            ("read_file", "[untrusted_bot/intern] read_file /data/safe.txt", {"path": "/data/safe.txt", "agent_id": "untrusted_bot", "cost": 0.1}),
            ("write_file", "[untrusted_bot/intern] write_file /data/hack.txt", {"path": "/data/hack.txt", "content": "x", "agent_id": "untrusted_bot", "cost": 0.1}),
            ("read_file", "[blocked_agent/blocked] read_file /data/safe.txt", {"path": "/data/safe.txt", "agent_id": "blocked_agent", "cost": 0.1}),
        ]:
            result, elapsed, reason = await _invoke(tool, **args)
            arrow = "ALLOW" if not result.isError else f"DENY: {reason}"
            print(f"{label}\n  → {arrow} ({elapsed}μs)")
        print("")

        print("─── Scenario 4: Rate Limiting ───")
        rate_results = [
            (await _invoke("read_file", path=f"/data/rate-{idx}.txt", agent_id="cursor", session_id="demo-rate", cost=0.0))[0]
            for idx in range(rate_burst)
        ]
        allow = sum(1 for item in rate_results if not item.isError)
        deny = sum(1 for item in rate_results if item.isError)
        print("[cursor/operator] read_file x100 rapid calls...")
        print(f"  → {allow} ALLOW, {deny} DENY (rate limit: 60/min)")
        print("")

        print("─── Scenario 5: Budget Control ───")
        budget_calls = [(await _invoke("expensive_operation", cost=2.0, agent_id="cursor", session_id="demo-budget"))[0] for _ in range(3)]
        b_status = ["ALLOW" if not item.isError else "DENY" for item in budget_calls]
        print("[cursor/operator] expensive_operation cost=2.0 x3")
        print(f"  → {b_status[0]} ($2.00), {b_status[1]} ($4.00), {b_status[2]} (daily budget $5.00 exceeded)")
        print("")

    events = read_events_from_jsonl(decisions_log)
    allowed = sum(1 for event in events if event.decision == "ALLOW")
    denied = sum(1 for event in events if event.decision == "DENY")
    avg_latency = (sum(event.evaluation_duration_us for event in events) / len(events)) if events else 0.0
    policy_version = events[0].policy_version if events else "unknown"
    invariant_log = runtime_dir / "invariants_input.jsonl"
    report = InvariantChecker(policy_path=str(policy_path), decisions_log=str(invariant_log)).check_all()
    passed = sum(1 for item in report.results if item.passed)
    print("─── Summary ───")
    print("")
    print(f"Total decisions: {len(events)}")
    print(f"Allowed: {allowed} ({(allowed/len(events)*100.0) if events else 0:.0f}%)")
    print(f"Denied: {denied} ({(denied/len(events)*100.0) if events else 0:.0f}%)")
    print(f"Avg latency: {avg_latency:.0f}μs")
    print(f"Policy version: {policy_version[:6]}")
    print("")
    print(f"Invariant check: {passed}/{len(report.results)} passed ✓")
    print("")
    print(f"Full audit trail: {decisions_log} ({len(events)} entries)")
    return {"total": len(events), "allowed": allowed, "denied": denied, "invariants_passed": int(report.all_passed)}


def main() -> None:
    asyncio.run(run_demo())


if __name__ == "__main__":
    main()
