from __future__ import annotations

import os
import time
import tracemalloc
from concurrent.futures import ThreadPoolExecutor
from random import Random

from orchesis.engine import evaluate
from orchesis.identity import AgentIdentity, AgentRegistry, TrustTier
from orchesis.state import RateLimitTracker
from orchesis.telemetry import InMemoryEmitter

CI_MULTIPLIER = 5.0 if os.getenv("CI") else 1.0


def _policy(*, rate_limit: int = 10, daily_budget: float = 1000.0, max_cost: float = 10.0) -> dict:
    return {
        "rules": [
            {"name": "budget_limit", "max_cost_per_call": max_cost, "daily_budget": daily_budget},
            {"name": "rate_limit", "max_requests_per_minute": rate_limit},
            {"name": "file_access", "allowed_paths": ["/data"], "denied_paths": ["/etc", "/root"]},
            {"name": "sql_restriction", "denied_operations": ["DROP", "DELETE"]},
        ]
    }


def test_1000_agents_concurrent() -> None:
    policy = _policy(rate_limit=10)
    tracker = RateLimitTracker(persist_path=None)

    def _call(i: int) -> bool:
        agent_id = f"agent-{i // 10}"
        request = {
            "tool": "read_file",
            "params": {"path": "/data/safe.txt"},
            "cost": 0.1,
            "context": {"agent": agent_id},
        }
        decision = evaluate(request, policy, state=tracker)
        return decision.allowed

    with ThreadPoolExecutor(max_workers=100) as pool:
        results = list(pool.map(_call, range(10_000)))
    assert all(isinstance(item, bool) for item in results)

    # Every agent sends exactly 10 requests against rate_limit=10 => all should pass.
    for agent_idx in range(1000):
        allowed = sum(results[agent_idx * 10 : (agent_idx + 1) * 10])
        assert allowed == 10


def test_5000_concurrent_evaluations() -> None:
    policy = _policy(rate_limit=500)
    tracker = RateLimitTracker(persist_path=None)
    rng = Random(42)
    requests: list[tuple[dict, bool]] = []
    for i in range(5000):
        roll = rng.random()
        base = {"context": {"agent": f"agent-{i % 50}"}, "cost": 0.1}
        if roll < 0.60:
            req = {"tool": "read_file", "params": {"path": "/data/report.txt"}, **base}
            requests.append((req, True))
        elif roll < 0.80:
            req = {"tool": "read_file", "params": {"path": "/etc/passwd"}, **base}
            requests.append((req, False))
        else:
            req = {"tool": "run_sql", "params": {"query": "DROP TABLE users"}, **base}
            requests.append((req, False))

    started = time.perf_counter()

    def _call(item: tuple[dict, bool]) -> tuple[bool, bool]:
        req, expected_allow = item
        decision = evaluate(req, policy, state=tracker)
        return decision.allowed, expected_allow

    with ThreadPoolExecutor(max_workers=200) as pool:
        results = list(pool.map(_call, requests))
    elapsed = time.perf_counter() - started

    for allowed, expected_allow in results:
        assert allowed == expected_allow
    assert elapsed < 60.0 * CI_MULTIPLIER, (
        f"5000 concurrent evaluations took {elapsed:.1f}s (limit {60.0 * CI_MULTIPLIER:.1f}s)"
    )


def test_rate_limit_exact_under_concurrency() -> None:
    policy = _policy(rate_limit=10)
    tracker = RateLimitTracker(persist_path=None)

    def _call(i: int) -> tuple[str, bool]:
        agent_id = f"agent-{i % 20}"
        decision = evaluate(
            {
                "tool": "read_file",
                "params": {"path": "/data/safe.txt"},
                "cost": 0.1,
                "context": {"agent": agent_id},
            },
            policy,
            state=tracker,
        )
        return agent_id, decision.allowed

    with ThreadPoolExecutor(max_workers=200) as pool:
        results = list(pool.map(_call, range(400)))

    by_agent: dict[str, list[bool]] = {}
    for agent_id, allowed in results:
        by_agent.setdefault(agent_id, []).append(allowed)

    for values in by_agent.values():
        assert sum(values) == 10
        assert len(values) - sum(values) == 10


def test_budget_exact_under_concurrency() -> None:
    policy = _policy(rate_limit=1000, daily_budget=5.0, max_cost=10.0)
    tracker = RateLimitTracker(persist_path=None)

    def _call(i: int) -> tuple[str, bool]:
        agent_id = f"agent-{i % 10}"
        decision = evaluate(
            {
                "tool": "read_file",
                "params": {"path": "/data/safe.txt"},
                "cost": 1.0,
                "context": {"agent": agent_id},
            },
            policy,
            state=tracker,
        )
        return agent_id, decision.allowed

    with ThreadPoolExecutor(max_workers=100) as pool:
        results = list(pool.map(_call, range(100)))

    by_agent: dict[str, list[bool]] = {}
    for agent_id, allowed in results:
        by_agent.setdefault(agent_id, []).append(allowed)

    for agent_id, values in by_agent.items():
        assert sum(values) == 5
        assert len(values) - sum(values) == 5
        assert tracker.get_agent_budget_spent(agent_id, window_seconds=86400) == 5.0


def test_session_isolation_under_load() -> None:
    policy = _policy(rate_limit=10)
    tracker = RateLimitTracker(persist_path=None)

    def _call(i: int) -> tuple[str, str, bool]:
        agent = f"agent-{(i // 200) % 5}"
        session = f"session-{(i // 20) % 10}"
        decision = evaluate(
            {
                "tool": "read_file",
                "params": {"path": "/data/safe.txt"},
                "cost": 0.1,
                "context": {"agent": agent, "session": session},
            },
            policy,
            state=tracker,
        )
        return agent, session, decision.allowed

    with ThreadPoolExecutor(max_workers=100) as pool:
        results = list(pool.map(_call, range(1000)))

    by_key: dict[tuple[str, str], list[bool]] = {}
    for agent, session, allowed in results:
        by_key.setdefault((agent, session), []).append(allowed)

    for values in by_key.values():
        assert sum(values) == 10
        assert len(values) - sum(values) == 10


def test_mixed_identity_tiers_concurrent() -> None:
    policy = _policy(rate_limit=1000)
    registry = AgentRegistry(
        agents={
            "blocked": AgentIdentity("blocked", "blocked", trust_tier=TrustTier.BLOCKED),
            "intern": AgentIdentity("intern", "intern", trust_tier=TrustTier.INTERN),
            "operator": AgentIdentity("operator", "operator", trust_tier=TrustTier.OPERATOR),
            "principal": AgentIdentity("principal", "principal", trust_tier=TrustTier.PRINCIPAL),
        }
    )
    tracker = RateLimitTracker(persist_path=None)

    calls: list[tuple[dict, bool]] = []
    for _ in range(100):
        calls.append(
            (
                {
                    "tool": "read_file",
                    "params": {"path": "/data/a.txt"},
                    "cost": 0.1,
                    "context": {"agent": "blocked"},
                },
                False,
            )
        )
        calls.append(
            (
                {
                    "tool": "read_file",
                    "params": {"path": "/data/a.txt"},
                    "cost": 0.1,
                    "context": {"agent": "intern"},
                },
                True,
            )
        )
        calls.append(
            (
                {
                    "tool": "write_file",
                    "params": {"path": "/data/a.txt"},
                    "cost": 0.1,
                    "context": {"agent": "intern"},
                },
                False,
            )
        )
        calls.append(
            (
                {
                    "tool": "write_file",
                    "params": {"path": "/data/a.txt"},
                    "cost": 0.1,
                    "context": {"agent": "operator"},
                },
                True,
            )
        )
        calls.append(
            (
                {
                    "tool": "delete_file",
                    "params": {"path": "/data/a.txt"},
                    "cost": 0.1,
                    "context": {"agent": "principal"},
                },
                True,
            )
        )

    def _call(item: tuple[dict, bool]) -> bool:
        req, expected = item
        decision = evaluate(req, policy, state=tracker, registry=registry)
        return decision.allowed == expected

    with ThreadPoolExecutor(max_workers=100) as pool:
        results = list(pool.map(_call, calls))
    assert all(results)


def test_policy_reload_during_traffic() -> None:
    policy_a = _policy(rate_limit=1000, max_cost=1.0, daily_budget=100.0)
    policy_b = _policy(rate_limit=1000, max_cost=0.5, daily_budget=100.0)
    current = [policy_a]
    tracker = RateLimitTracker(persist_path=None)

    def _call(i: int) -> bool:
        decision = evaluate(
            {
                "tool": "read_file",
                "params": {"path": "/data/safe.txt"},
                "cost": 0.75,
                "context": {"agent": f"agent-{i % 20}"},
            },
            current[0],
            state=tracker,
        )
        return decision.allowed

    with ThreadPoolExecutor(max_workers=100) as pool:
        first_half = list(pool.map(_call, range(500)))
        current[0] = policy_b
        second_half = list(pool.map(_call, range(500, 1000)))

    assert all(first_half)
    assert not any(second_half)


def test_state_persistence_under_crash(tmp_path) -> None:  # noqa: ANN001
    state_file = tmp_path / "state.jsonl"
    policy = _policy(rate_limit=2000, daily_budget=2000.0)

    tracker1 = RateLimitTracker(persist_path=state_file)
    for i in range(500):
        decision = evaluate(
            {
                "tool": "read_file",
                "params": {"path": "/data/a.txt"},
                "cost": 1.0,
                "context": {"agent": "persist-agent"},
            },
            policy,
            state=tracker1,
        )
        assert decision.allowed
    tracker1.flush()

    tracker2 = RateLimitTracker(persist_path=state_file)
    assert tracker2.get_count("read_file", 86400, agent_id="persist-agent") >= 500
    assert tracker2.get_agent_budget_spent("persist-agent", 86400) >= 500.0

    for _ in range(500):
        decision = evaluate(
            {
                "tool": "read_file",
                "params": {"path": "/data/a.txt"},
                "cost": 1.0,
                "context": {"agent": "persist-agent"},
            },
            policy,
            state=tracker2,
        )
        assert decision.allowed
    assert tracker2.get_count("read_file", 86400, agent_id="persist-agent") >= 1000
    assert tracker2.get_agent_budget_spent("persist-agent", 86400) >= 1000.0


def test_sustained_throughput_60_seconds() -> None:
    policy = _policy(rate_limit=10_000_000, daily_budget=100000.0)
    tracker = RateLimitTracker(persist_path=None)
    latencies_us: list[int] = []

    tracemalloc.start()
    start_mem, _ = tracemalloc.get_traced_memory()
    started = time.perf_counter()
    total = 0
    while time.perf_counter() - started < 60:
        before = time.perf_counter_ns()
        decision = evaluate(
            {
                "tool": "read_file",
                "params": {"path": "/data/load.txt"},
                "cost": 0.1,
                "context": {"agent": "sustain"},
            },
            policy,
            state=tracker,
        )
        latencies_us.append(max(0, (time.perf_counter_ns() - before) // 1000))
        total += 1
        assert decision.allowed

    end_mem, _ = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    elapsed = max(0.001, time.perf_counter() - started)
    throughput = total / elapsed
    sorted_lat = sorted(latencies_us)
    p99_idx = max(0, int(0.99 * (len(sorted_lat) - 1)))
    p99 = sorted_lat[p99_idx]
    memory_growth_mb = max(0.0, (end_mem - start_mem) / (1024.0 * 1024.0))
    assert throughput >= 100.0
    assert p99 < 20_000 * CI_MULTIPLIER
    assert memory_growth_mb <= 100.0


def test_telemetry_doesnt_slow_evaluation() -> None:
    policy = {
        "rules": [
            {"name": "budget_limit", "max_cost_per_call": 10.0},
            {
                "name": "regex_guard",
                "type": "regex_match",
                "field": "params.query",
                "deny_patterns": [f"NEVER_MATCH_{idx}$" for idx in range(1200)],
            },
        ]
    }
    request = {
        "tool": "read_file",
        "params": {
            "path": "/data/telemetry.txt",
            "query": "SELECT * FROM telemetry_table WHERE x=1",
        },
        "cost": 0.0,
        "context": {"agent": "telemetry-agent"},
    }

    tracker_without = RateLimitTracker(persist_path=None)
    started_without = time.perf_counter()
    for _ in range(200):
        evaluate(request, policy, state=tracker_without)
    elapsed_without = max(1e-9, time.perf_counter() - started_without)

    tracker_with = RateLimitTracker(persist_path=None)
    emitter = InMemoryEmitter()
    started_with = time.perf_counter()
    for _ in range(200):
        evaluate(request, policy, state=tracker_with, emitter=emitter)
    elapsed_with = time.perf_counter() - started_with

    overhead = (elapsed_with - elapsed_without) / elapsed_without
    # Perf noise on shared CI/VMs can be spiky; keep a strict but stable threshold.
    assert overhead < 0.80
