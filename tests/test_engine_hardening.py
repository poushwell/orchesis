from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from time import perf_counter_ns

from orchesis.engine import evaluate
from orchesis.models import Decision


def _policy() -> dict[str, object]:
    return {
        "rules": [
            {"name": "budget_limit", "max_cost_per_call": 0.5},
            {"name": "file_access", "allowed_paths": ["/data", "/tmp"], "denied_paths": ["/etc"]},
            {"name": "sql_restriction", "denied_operations": ["DROP", "DELETE"]},
            {"name": "rate_limit", "max_requests_per_minute": 100},
        ]
    }


def test_empty_policy_defaults_to_allow() -> None:
    request = {"tool": "noop", "params": {}, "cost": 0.0}
    decision = evaluate(request, {"rules": []})

    assert isinstance(decision, Decision)
    assert decision.allowed is True
    assert decision.reasons == []
    assert decision.rules_checked == []


def test_request_missing_all_fields_is_handled_gracefully() -> None:
    decision = evaluate({}, _policy())

    assert isinstance(decision, Decision)
    assert isinstance(decision.allowed, bool)
    assert isinstance(decision.reasons, list)
    assert isinstance(decision.rules_checked, list)


def test_long_unicode_and_nested_request_does_not_crash() -> None:
    long_text = "данные" * 5000 + "🚀" * 2000
    request = {
        "tool": "sql_query",
        "cost": 0.1,
        "params": {
            "path": "/data/" + long_text,
            "query": "SELECT 1",
            "nested": {
                "level1": {
                    "level2": {
                        "payload": long_text,
                    }
                }
            },
        },
        "context": {"agent": "cursor", "session": long_text[:200]},
    }

    decision = evaluate(request, _policy())
    assert isinstance(decision, Decision)


def test_concurrent_evaluate_calls_are_thread_safe_and_deterministic() -> None:
    request = {"tool": "sql_query", "params": {"query": "SELECT 1", "path": "/data/x"}, "cost": 0.1}
    policy = _policy()
    expected = evaluate(request, policy)

    def run_once() -> tuple[bool, list[str], list[str]]:
        result = evaluate(request, policy)
        return result.allowed, result.reasons, result.rules_checked

    with ThreadPoolExecutor(max_workers=16) as executor:
        results = list(executor.map(lambda _: run_once(), range(200)))

    assert all(allowed == expected.allowed for allowed, _, _ in results)
    assert all(reasons == expected.reasons for _, reasons, _ in results)
    assert all(rules_checked == expected.rules_checked for _, _, rules_checked in results)


def test_benchmark_1000_evaluate_calls_reports_latency() -> None:
    request = {
        "tool": "sql_query",
        "params": {"query": "SELECT * FROM demo", "path": "/data/report.csv"},
        "cost": 0.2,
    }
    policy = _policy()

    samples_ms: list[float] = []
    for _ in range(1000):
        started_ns = perf_counter_ns()
        _ = evaluate(request, policy)
        elapsed_ns = perf_counter_ns() - started_ns
        samples_ms.append(elapsed_ns / 1_000_000)

    sorted_samples = sorted(samples_ms)
    avg_ms = sum(samples_ms) / len(samples_ms)
    p95_ms = sorted_samples[int(0.95 * (len(sorted_samples) - 1))]
    p99_ms = sorted_samples[int(0.99 * (len(sorted_samples) - 1))]

    print(f"benchmark_evaluate_1000 avg_ms={avg_ms:.6f} p95_ms={p95_ms:.6f} p99_ms={p99_ms:.6f}")
    assert avg_ms >= 0.0
    assert p95_ms >= 0.0
    assert p99_ms >= 0.0
