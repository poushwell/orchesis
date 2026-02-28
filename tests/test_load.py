from __future__ import annotations

import threading
import tracemalloc
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from time import perf_counter, perf_counter_ns

from orchesis.engine import evaluate
from orchesis.models import Decision
from orchesis.state import RateLimitTracker


def _full_policy() -> dict[str, object]:
    return {
        "rules": [
            {"name": "budget_limit", "max_cost_per_call": 2.0, "daily_budget": 100.0},
            {"name": "rate_limit", "max_requests_per_minute": 10000},
            {"name": "file_access", "allowed_paths": ["/data"], "denied_paths": ["/etc"]},
            {"name": "sql_restriction", "denied_operations": ["DROP", "DELETE"]},
            {
                "name": "rx",
                "type": "regex_match",
                "field": "params.query",
                "deny_patterns": [r"(?i)drop\s+table"],
            },
            {
                "name": "ctx",
                "type": "context_rules",
                "rules": [{"agent": "*", "max_cost_per_call": 2.0}],
            },
            {
                "name": "combo",
                "type": "composite",
                "operator": "AND",
                "conditions": [{"rule": "budget_limit"}, {"rule": "file_access"}],
            },
        ]
    }


def _request(agent_id: str = "load_agent") -> dict[str, object]:
    return {
        "tool": "run_sql",
        "params": {"path": "/data/sales.csv", "query": "SELECT 1"},
        "cost": 0.1,
        "context": {"agent": agent_id},
    }


def _percentile(values_ms: list[float], q: float) -> float:
    sorted_values = sorted(values_ms)
    idx = int(q * (len(sorted_values) - 1))
    return sorted_values[idx]


def test_1000_sequential_evaluations_under_1_second() -> None:
    tracker = RateLimitTracker(persist_path=None)
    policy = _full_policy()
    request = _request()

    start = perf_counter()
    samples_ms: list[float] = []
    for _ in range(1000):
        step_start_ns = perf_counter_ns()
        _ = evaluate(request, policy, state=tracker)
        samples_ms.append((perf_counter_ns() - step_start_ns) / 1_000_000)
    elapsed = perf_counter() - start

    avg = sum(samples_ms) / len(samples_ms)
    p50 = _percentile(samples_ms, 0.50)
    p95 = _percentile(samples_ms, 0.95)
    p99 = _percentile(samples_ms, 0.99)
    print(
        f"load_seq total_s={elapsed:.6f} avg_ms={avg:.6f} p50_ms={p50:.6f} p95_ms={p95:.6f} p99_ms={p99:.6f}"
    )
    assert elapsed < 1.0


def test_500_concurrent_evaluations_no_race_conditions() -> None:
    policy = {"rules": [{"name": "budget_limit", "max_cost_per_call": 1.0}]}
    request = _request()
    expected = evaluate(request, policy)

    start = perf_counter()
    with ThreadPoolExecutor(max_workers=50) as pool:
        results = list(pool.map(lambda _: evaluate(request, policy), range(500)))
    elapsed = perf_counter() - start
    throughput = len(results) / elapsed if elapsed > 0 else float("inf")
    print(f"load_concurrent elapsed_s={elapsed:.6f} throughput={throughput:.2f} decisions_per_sec")

    assert all(isinstance(item, Decision) for item in results)
    assert all(item.allowed == expected.allowed for item in results)
    assert all(item.reasons == expected.reasons for item in results)
    assert all(item.rules_checked == expected.rules_checked for item in results)


def test_rate_limit_under_concurrent_load() -> None:
    policy = {"rules": [{"name": "rate_limit", "max_requests_per_minute": 15}]}
    tracker = RateLimitTracker(persist_path=None)
    results_by_agent: dict[str, list[bool]] = defaultdict(list)
    lock = threading.Lock()

    calls: list[str] = []
    for i in range(10):
        calls.extend([f"agent_{i}"] * 20)

    def run_call(agent_id: str) -> None:
        decision = evaluate(_request(agent_id), policy, state=tracker)
        with lock:
            results_by_agent[agent_id].append(decision.allowed)

    with ThreadPoolExecutor(max_workers=100) as pool:
        list(pool.map(run_call, calls))

    for agent_id in sorted(results_by_agent.keys()):
        allowed = sum(1 for x in results_by_agent[agent_id] if x)
        denied = sum(1 for x in results_by_agent[agent_id] if not x)
        assert allowed == 15
        assert denied == 5


def test_evaluation_latency_with_large_policy() -> None:
    mixed_rules: list[dict[str, object]] = []
    for idx in range(20):
        mixed_rules.append(
            {"name": f"budget_limit_{idx}", "type": "budget_limit", "max_cost_per_call": 1.0}
        )
        mixed_rules.append(
            {
                "name": f"file_access_{idx}",
                "type": "file_access",
                "allowed_paths": ["/data"],
                "denied_paths": ["/etc"],
            }
        )
        mixed_rules.append(
            {
                "name": f"sql_restriction_{idx}",
                "type": "sql_restriction",
                "denied_operations": ["DROP"],
            }
        )
        mixed_rules.append(
            {
                "name": f"regex_{idx}",
                "type": "regex_match",
                "field": "params.query",
                "deny_patterns": [r"(?i)drop\s+table"],
            }
        )
        mixed_rules.append(
            {"name": f"rate_limit_{idx}", "type": "rate_limit", "max_requests_per_minute": 100000}
        )

    policy = {"rules": mixed_rules}
    request = _request()
    tracker = RateLimitTracker(persist_path=None)
    samples_ms: list[float] = []

    for _ in range(100):
        start_ns = perf_counter_ns()
        decision = evaluate(request, policy, state=tracker)
        samples_ms.append((perf_counter_ns() - start_ns) / 1_000_000)
        assert isinstance(decision, Decision)

    p99 = _percentile(samples_ms, 0.99)
    avg = sum(samples_ms) / len(samples_ms)
    counts_by_prefix: dict[str, int] = defaultdict(int)
    for rule in mixed_rules:
        name = str(rule["name"])
        prefix = name.split("_", 1)[0]
        counts_by_prefix[prefix] += 1
    print(f"large_policy avg_ms={avg:.6f} p99_ms={p99:.6f} rule_mix={dict(counts_by_prefix)}")
    assert p99 < 5.0


def test_sustained_throughput_10_seconds() -> None:
    policy = {"rules": [{"name": "budget_limit", "max_cost_per_call": 1.0}]}
    request = _request()
    end_at = perf_counter() + 10.0

    tracemalloc.start()
    start_mem, _ = tracemalloc.get_traced_memory()

    total = 0
    while perf_counter() < end_at:
        _ = evaluate(request, policy)
        total += 1

    end_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    throughput = total / 10.0
    print(
        f"sustained_10s total={total} throughput={throughput:.2f}/s start_mem={start_mem} end_mem={end_mem} peak={peak_mem}"
    )
    assert end_mem < start_mem + 10 * 1024 * 1024


def test_state_persistence_under_load(tmp_path) -> None:
    state_path = tmp_path / "state.jsonl"
    tracker = RateLimitTracker(persist_path=state_path)
    policy = {"rules": [{"name": "rate_limit", "max_requests_per_minute": 100000}]}
    request = _request("persist_agent")

    for _ in range(1000):
        _ = evaluate(request, policy, state=tracker)

    reloaded = RateLimitTracker(persist_path=state_path)
    count = reloaded.get_count("run_sql", window_seconds=3600, agent_id="persist_agent")
    assert count == 1000
