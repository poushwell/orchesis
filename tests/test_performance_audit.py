from __future__ import annotations

import json
import os
import statistics
import sys
import tempfile
import threading
import time
from collections import deque
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable

import pytest

from ci_multiplier import get_ci_multiplier

from orchesis.ars import AgentReliabilityScore
from orchesis.entropy_detector import EntropyDetector
from orchesis.message_chain import validate_tool_chain
from orchesis.ngram_profiler import NgramProfiler, cosine_similarity
from orchesis.openclaw_auditor import OpenClawAuditor
from orchesis.context_router import ContextStrategyRouter
from orchesis.cost_optimizer import CostOptimizer
from orchesis.context_compression_v2 import ContextCompressionV2
from orchesis.request_sampler import RequestSampler
from orchesis.request_prioritizer import RequestPrioritizer
from orchesis.context_window_optimizer import ContextWindowOptimizer
from orchesis.session_risk import RiskSignal, SessionRiskAccumulator
from orchesis.structural_patterns import StructuralPatternDetector
from orchesis.telemetry_export import TelemetryRecord

ITERATIONS = 1000

_CI = os.environ.get("CI")
# Historically 3.0× slack on CI; scale with ORCHESIS_CI_MULTIPLIER (default 10 vs old 5).
CI_FACTOR = 1.0 if not _CI else max(3.0, get_ci_multiplier() * 0.6)

pytestmark = [pytest.mark.performance, pytest.mark.slow]


def _th(value: float) -> float:
    return value * CI_FACTOR


def benchmark(func: Callable[[], Any], iterations: int = ITERATIONS) -> dict[str, float]:
    """Run function N times and return timing stats in microseconds."""

    samples: list[float] = []
    for _ in range(iterations):
        start = time.perf_counter_ns()
        func()
        samples.append((time.perf_counter_ns() - start) / 1000.0)
    ordered = sorted(samples)
    return {
        "mean_us": statistics.fmean(samples),
        "median_us": statistics.median(samples),
        "p99_us": ordered[min(len(ordered) - 1, int(len(ordered) * 0.99))],
        "max_us": max(samples),
        "min_us": min(samples),
        "iterations": float(iterations),
    }


def _run_benchmark(func: Callable[[], Any], n: int = ITERATIONS) -> dict[str, float]:
    """Compatibility wrapper used by newer perf tests."""
    return benchmark(func, iterations=n)


def get_memory_bytes(obj: Any) -> int:
    """Recursive memory estimate for nested containers."""

    seen: set[int] = set()

    def walk(item: Any) -> int:
        oid = id(item)
        if oid in seen:
            return 0
        seen.add(oid)
        size = sys.getsizeof(item)
        if isinstance(item, dict):
            return size + sum(walk(k) + walk(v) for k, v in item.items())
        if isinstance(item, (list, tuple, set, frozenset, deque)):
            return size + sum(walk(v) for v in item)
        return size

    return walk(obj)


def _words(n: int) -> str:
    vocab = [
        "a",
        "b",
        "c",
        "d",
        "e",
        "f",
        "g",
        "h",
        "i",
        "j",
    ]
    return " ".join(vocab[i % len(vocab)] for i in range(n))


def _request_10_messages() -> dict[str, Any]:
    messages = []
    for i in range(10):
        role = "user" if i % 2 == 0 else "assistant"
        messages.append({"role": role, "content": f"msg {i} content with moderate length"})
    messages[5]["tool_calls"] = [
        {"id": "tc1", "type": "function", "function": {"name": "read", "arguments": "{}"}},
        {"id": "tc2", "type": "function", "function": {"name": "write", "arguments": "{}"}},
        {"id": "tc3", "type": "function", "function": {"name": "search", "arguments": "{}"}},
    ]
    return {"messages": messages, "model": "gpt-4o-mini", "tools": ["read", "write", "search"]}


def _tool_chain_messages(size: int) -> list[dict[str, Any]]:
    msgs: list[dict[str, Any]] = [{"role": "system", "content": "rules"}]
    group_count = max(1, size // 10)
    for i in range(group_count):
        call_id = f"c{i}"
        msgs.extend(
            [
                {"role": "user", "content": f"task {i}"},
                {
                    "role": "assistant",
                    "content": f"using tool {i}",
                    "tool_calls": [{"id": call_id, "type": "function", "function": {"name": "read", "arguments": "{}"}}],
                },
                {"role": "tool", "tool_call_id": call_id, "content": f"result {i}"},
            ]
        )
    while len(msgs) < size:
        msgs.append({"role": "assistant", "content": "extra"})
    return msgs[:size]


@lru_cache(maxsize=1)
def _module_results() -> dict[str, dict[str, float]]:
    text_500 = _words(500)
    request_10 = _request_10_messages()
    chain_20 = _tool_chain_messages(20)
    chain_100 = _tool_chain_messages(100)

    entropy = EntropyDetector({"min_observations": 10, "window_size": 50})
    for i in range(20):
        entropy.check("agent-a", {"messages": [{"role": "assistant", "content": f"{_words(90)} {i}"}], "timestamp": float(i)})

    structural = StructuralPatternDetector({"history_size": 120, "max_pattern_length": 5, "min_occurrences": 3})
    for i in range(50):
        structural.check(
            "agent-a",
            {"messages": request_10["messages"], "model": "gpt-4o-mini", "tools": ["read" if i % 2 == 0 else "write", "search"]},
        )

    ngram = NgramProfiler({"baseline_messages": 20, "window_size": 10, "min_tokens": 50, "top_k": 200})
    for i in range(25):
        ngram.check("agent-a", f"{_words(80)} warm{i}")

    risk = SessionRiskAccumulator()
    for i in range(20):
        risk.record_signal(
            "session-1",
            RiskSignal(
                category="prompt_injection",
                confidence=0.45,
                severity="medium",
                source="threat_intel",
                description=f"signal{i}",
            ),
        )

    ars = AgentReliabilityScore()
    for i in range(180):
        ars.update(
            "agent-a",
            is_session_end=(i % 3 == 0),
            session_success=(i % 9 != 0),
            loop_flagged=(i % 25 == 0),
            cost_usd=0.001,
            latency_ms=150.0 + (i % 5),
            token_count=220 + (i % 11),
            clean_termination=(i % 13 != 0),
            has_threat=(i % 31 == 0),
        )

    vec_a = {f"k{i}": 1 / 200.0 for i in range(200)}
    vec_b = {f"k{i}": (1 / 200.0 if i % 5 else 2 / 200.0) for i in range(200)}

    cfg_path = Path(tempfile.gettempdir()) / "orchesis_perf_openclaw.json"
    cfg_path.write_text(
        json.dumps(
            {
                "mode": "production",
                "workspace": "/opt/openclaw/workspace",
                "env": {"NODE_ENV": "production"},
                "tools": {"exec": {"mode": "sandboxed", "allowedCommands": ["python"], "blockedPaths": ["/etc"], "maxFileSizeMb": 10}},
                "skills": [{"name": "safe", "version": "1.0.0"}],
                "skillAllowlist": ["safe"],
            }
        ),
        encoding="utf-8",
    )
    auditor = OpenClawAuditor()

    def full_pipeline_warm() -> None:
        entropy.check("agent-a", {"messages": [{"role": "assistant", "content": text_500}]})
        structural.check("agent-a", request_10)
        ngram.check("agent-a", text_500)
        risk.record_signal(
            "session-1",
            RiskSignal(category="data_exfiltration", confidence=0.4, severity="low", source="bench", description="x"),
        )
        risk.evaluate("session-1")
        ars.compute_all()
        validate_tool_chain(chain_20)
        _ = TelemetryRecord(
            session_id="session-1",
            agent_id="agent-a",
            model_requested="gpt-4o-mini",
            model_used="gpt-4o-mini",
            total_ms=20.0,
            upstream_ms=15.0,
            input_tokens=200,
            output_tokens=120,
            cost_usd=0.001,
            threat_matches=["ORCH-TA-001"],
            threat_categories=["prompt_injection"],
            blocked=False,
            cache_hit=False,
            loop_detected=False,
            session_risk_score=22.3,
            status_code=200,
        )

    entropy_cold = EntropyDetector({"min_observations": 10, "window_size": 50})
    structural_cold = StructuralPatternDetector({"history_size": 120, "max_pattern_length": 5, "min_occurrences": 3})
    ngram_cold = NgramProfiler({"baseline_messages": 20, "window_size": 10, "min_tokens": 50, "top_k": 200})
    risk_cold = SessionRiskAccumulator()
    ars_cold = AgentReliabilityScore()
    context_router = ContextStrategyRouter()
    cost_optimizer = CostOptimizer({"strategies": ["trim_whitespace", "remove_redundant_context"]})
    compression_v2 = ContextCompressionV2({"algorithm": "importance_scoring", "target_ratio": 0.7})
    sampler = RequestSampler({"strategy": "random", "rate": 0.5, "seed": 1337})
    context_window_optimizer = ContextWindowOptimizer({"safety_margin": 0.1})
    prioritizer = RequestPrioritizer({"default": "normal"})

    def full_pipeline_cold() -> None:
        entropy_cold.check("cold-agent", {"messages": [{"role": "assistant", "content": text_500}]})
        structural_cold.check("cold-agent", request_10)
        ngram_cold.check("cold-agent", text_500)
        risk_cold.record_signal(
            "cold-session",
            RiskSignal(category="prompt_injection", confidence=0.2, severity="low", source="bench", description="cold"),
        )
        risk_cold.evaluate("cold-session")
        ars_cold.update("cold-agent", latency_ms=100.0, token_count=50)
        ars_cold.compute_all()
        validate_tool_chain(chain_20)
        _ = TelemetryRecord(agent_id="cold-agent", session_id="cold-session")

    return {
        "entropy_analyze_message": benchmark(lambda: entropy.analyze_message(text_500, role="assistant")),
        "entropy_check_with_baseline": benchmark(lambda: entropy.check("agent-a", {"messages": [{"role": "assistant", "content": text_500}]})),
        "structural_extract_signature": benchmark(lambda: structural.extract_signature(request_10)),
        "structural_check_with_history": benchmark(lambda: structural.check("agent-a", request_10)),
        "ngram_build_profile": benchmark(lambda: ngram.build_profile(text_500)),
        "ngram_check_with_baseline": benchmark(lambda: ngram.check("agent-a", text_500)),
        "ngram_cosine_similarity": benchmark(lambda: cosine_similarity(vec_a, vec_b)),
        "session_risk_observe": benchmark(
            lambda: risk.record_signal(
                "session-1",
                RiskSignal(category="path_traversal", confidence=0.4, severity="medium", source="bench", description="obs"),
            )
        ),
        "session_risk_score": benchmark(lambda: risk.evaluate("session-1")),
        "ars_compute": benchmark(lambda: ars.compute_all()),
        "message_chain_validate": benchmark(lambda: validate_tool_chain(chain_20)),
        "message_chain_validate_large": benchmark(lambda: validate_tool_chain(chain_100)),
        "openclaw_audit_config": benchmark(lambda: auditor.audit_config(str(cfg_path))),
        "telemetry_record_creation": benchmark(
            lambda: TelemetryRecord(
                request_id="req-1",
                session_id="s1",
                agent_id="a1",
                model_requested="gpt-4o-mini",
                model_used="gpt-4o-mini",
                total_ms=11.2,
                upstream_ms=8.8,
                proxy_overhead_ms=2.4,
                input_tokens=120,
                output_tokens=66,
                cost_usd=0.0004,
                threat_matches=["ORCH-TA-002"],
                threat_categories=["command_injection"],
                threat_max_severity="medium",
                blocked=False,
                cache_hit=False,
                cache_type="miss",
                loop_detected=False,
                loop_count=0,
                content_hash_blocked=False,
                heartbeat_detected=False,
                session_risk_score=10.0,
                session_risk_level="observe",
                turn_number=3,
                tool_calls_count=2,
                has_tool_results=True,
                is_streaming=False,
                failure_mode="",
                budget_remaining_usd=9.0,
                spend_rate_5min_usd=0.1,
                budget_blocked=False,
                was_cascaded=False,
                cascade_reason="",
                status_code=200,
                error_type="",
            )
        ),
        "context_router_classify": benchmark(
            lambda: context_router.classify(
                request_10["messages"],
                ["search", "read_file"],
            )
        ),
        "cost_optimizer_optimize": benchmark(lambda: cost_optimizer.optimize(request_10["messages"])),
        "context_compression_v2_compress": benchmark(lambda: compression_v2.compress(request_10["messages"], budget_tokens=1200)),
        "request_sampler_should_record": benchmark(lambda: sampler.should_record({"decision": "ALLOW", "risk_score": 0.2})),
        "context_window_optimizer_optimize": benchmark(
            lambda: context_window_optimizer.optimize_for_model(request_10["messages"], "gpt-4o-mini")
        ),
        "request_prioritizer_assign_priority": benchmark(
            lambda: prioritizer.assign_priority(
                {
                    "messages": request_10["messages"],
                    "role": "user",
                    "batch_size": 1,
                }
            )
        ),
        "all_detectors_combined": benchmark(full_pipeline_warm),
        "all_detectors_cold_start": benchmark(full_pipeline_cold),
    }


def test_benchmark_runs_1000_iterations() -> None:
    assert all(int(v["iterations"]) == ITERATIONS for v in _module_results().values())


def test_perf_entropy_analyze_message() -> None:
    assert _module_results()["entropy_analyze_message"]["mean_us"] < _th(1500.0)


def test_perf_entropy_check_with_baseline() -> None:
    assert _module_results()["entropy_check_with_baseline"]["mean_us"] < _th(2500.0)


def test_perf_structural_extract_signature() -> None:
    assert _module_results()["structural_extract_signature"]["mean_us"] < _th(300.0)


def test_perf_structural_check_with_history() -> None:
    assert _module_results()["structural_check_with_history"]["mean_us"] < _th(2000.0)


def test_perf_ngram_build_profile() -> None:
    assert _module_results()["ngram_build_profile"]["mean_us"] < _th(1000.0)


def test_perf_ngram_check_with_baseline() -> None:
    assert _module_results()["ngram_check_with_baseline"]["mean_us"] < _th(7000.0)


def test_perf_ngram_cosine_similarity() -> None:
    assert _module_results()["ngram_cosine_similarity"]["mean_us"] < _th(150.0)


def test_perf_session_risk_observe() -> None:
    assert _module_results()["session_risk_observe"]["mean_us"] < _th(360.0)


def test_perf_session_risk_score() -> None:
    assert _module_results()["session_risk_score"]["mean_us"] < _th(140.0)


def test_perf_ars_compute() -> None:
    assert _module_results()["ars_compute"]["mean_us"] < _th(200.0)


def test_perf_message_chain_validate() -> None:
    assert _module_results()["message_chain_validate"]["mean_us"] < _th(200.0)


def test_perf_message_chain_validate_large() -> None:
    assert _module_results()["message_chain_validate_large"]["mean_us"] < _th(1000.0)


def test_perf_openclaw_audit_config() -> None:
    assert _module_results()["openclaw_audit_config"]["mean_us"] < _th(5000.0)


def test_perf_telemetry_record_creation() -> None:
    assert _module_results()["telemetry_record_creation"]["mean_us"] < _th(50.0)


def test_perf_all_detectors_combined() -> None:
    assert _module_results()["all_detectors_combined"]["mean_us"] < _th(5000.0)


def test_perf_all_detectors_cold_start() -> None:
    assert _module_results()["all_detectors_cold_start"]["mean_us"] < _th(7000.0)


def test_perf_context_router_classify() -> None:
    assert _module_results()["context_router_classify"]["mean_us"] < _th(500.0)


def test_perf_cost_optimizer_optimize() -> None:
    assert _module_results()["cost_optimizer_optimize"]["mean_us"] < _th(500.0)


def test_perf_request_sampler_should_record() -> None:
    assert _module_results()["request_sampler_should_record"]["mean_us"] < _th(500.0)


def test_perf_par_abduce() -> None:
    """PAR abduce < 500 us."""
    from orchesis.par_reasoning import PARReasoner

    par = PARReasoner()
    event = {"reasons": ["prompt_injection", "credential_leak"]}
    results = _run_benchmark(lambda: par.abduce(event), n=1000)
    assert results["mean_us"] < _th(500.0)


def test_perf_criticality_control() -> None:
    """CriticalityController.compute_control < 200 us."""
    from orchesis.criticality_control import CriticalityController

    cc = CriticalityController()
    results = _run_benchmark(lambda: cc.compute_control(0.5), n=1000)
    assert results["mean_us"] < _th(200.0)


def test_perf_kolmogorov_estimate() -> None:
    """KolmogorovImportance.estimate_k < 1000 us."""
    from orchesis.kolmogorov_importance import KolmogorovImportance

    ki = KolmogorovImportance()
    text = "This is a test message for Kolmogorov complexity estimation."
    results = _run_benchmark(lambda: ki.estimate_k(text), n=500)
    assert results["mean_us"] < _th(1000.0)


def test_perf_keystone_score() -> None:
    """KeystoneDetector.compute_keystone_score < 500 us."""
    from orchesis.keystone_agent import KeystoneDetector

    kd = KeystoneDetector()
    for i in range(10):
        for j in range(5):
            kd.record_uci(f"agent_{i}", 0.5 + j * 0.1)
    results = _run_benchmark(lambda: kd.compute_keystone_score("agent_0"), n=500)
    assert results["mean_us"] < _th(500.0)


def test_perf_discourse_coherence() -> None:
    """compute_iacs_full < 500 us for 10 messages."""
    from orchesis.discourse_coherence import compute_iacs_full

    messages = [
        {"role": "user", "content": f"Message {i} about context management."}
        for i in range(10)
    ]
    results = _run_benchmark(lambda: compute_iacs_full(messages), n=500)
    assert results["mean_us"] < _th(500.0)


def test_perf_pipeline_under_load() -> None:
    text = _words(500)
    req = _request_10_messages()
    chain = _tool_chain_messages(20)
    entropy = EntropyDetector({"min_observations": 5})
    structural = StructuralPatternDetector({"history_size": 50, "max_pattern_length": 4})
    ngram = NgramProfiler({"baseline_messages": 10, "min_tokens": 50})
    risk = SessionRiskAccumulator()
    ars = AgentReliabilityScore()

    for i in range(12):
        ngram.check("agent-load", f"{_words(70)} warm {i}")

    def worker(i: int) -> None:
        entropy.check("agent-load", {"messages": [{"role": "assistant", "content": text}]})
        structural.check("agent-load", req)
        ngram.check("agent-load", text)
        risk.record_signal(
            "session-load",
            RiskSignal(category="prompt_injection", confidence=0.2, severity="low", source="bench", description=str(i)),
        )
        risk.evaluate("session-load")
        ars.update("agent-load", latency_ms=100.0, token_count=100, has_threat=False)
        ars.compute_all()
        validate_tool_chain(chain)
        _ = TelemetryRecord(agent_id="agent-load", session_id="session-load")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(100)]
    started = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.perf_counter() - started
    assert elapsed < _th(2.0)


def test_memory_entropy_baseline_100_agents() -> None:
    detector = EntropyDetector({"window_size": 50, "min_observations": 10})
    for a in range(100):
        for i in range(50):
            detector.check(f"a{a}", {"messages": [{"role": "assistant", "content": f"{_words(60)} {i}"}], "timestamp": float(i)})
    assert get_memory_bytes(detector.get_all_baselines()) < _th(10 * 1024 * 1024)


def test_memory_structural_history_100_agents() -> None:
    detector = StructuralPatternDetector({"history_size": 100})
    req = _request_10_messages()
    for a in range(100):
        for _ in range(100):
            detector.check(f"s{a}", req)
    assert get_memory_bytes(detector.get_all_agents()) < _th(10 * 1024 * 1024)


def test_memory_ngram_profiles_100_agents() -> None:
    profiler = NgramProfiler({"baseline_messages": 20, "window_size": 10, "top_k": 100})
    text = _words(120)
    for a in range(100):
        for _ in range(20):
            profiler.check(f"n{a}", text)
    assert get_memory_bytes(profiler.get_all_profiles()) < _th(20 * 1024 * 1024)


def test_memory_session_risk_1000_sessions() -> None:
    acc = SessionRiskAccumulator()
    for i in range(1000):
        acc.record_signal(
            f"sess{i}",
            RiskSignal(category="prompt_injection", confidence=0.3, severity="low", source="bench", description="x"),
        )
    assert get_memory_bytes(acc.stats) + get_memory_bytes([acc.get_session_state(f"sess{i}") for i in range(1000)]) < _th(5 * 1024 * 1024)


def test_memory_total_all_modules() -> None:
    entropy = EntropyDetector({"window_size": 30})
    structural = StructuralPatternDetector({"history_size": 80})
    ngram = NgramProfiler({"baseline_messages": 10, "window_size": 8, "top_k": 80})
    risk = SessionRiskAccumulator()
    ars = AgentReliabilityScore()
    req = _request_10_messages()
    text = _words(100)
    for a in range(100):
        aid = f"agent{a}"
        for i in range(20):
            entropy.check(aid, {"messages": [{"role": "assistant", "content": f"{text} {i}"}], "timestamp": float(i)})
            structural.check(aid, req)
            ngram.check(aid, text)
        risk.record_signal(aid, RiskSignal(category="path_traversal", confidence=0.3, severity="low", source="bench", description="x"))
        ars.update(aid, latency_ms=100.0, token_count=120)
    total = (
        get_memory_bytes(entropy.get_all_baselines())
        + get_memory_bytes(structural.get_all_agents())
        + get_memory_bytes(ngram.get_all_profiles())
        + get_memory_bytes(risk.stats)
        + get_memory_bytes(ars.stats)
    )
    assert total < _th(50 * 1024 * 1024)


@lru_cache(maxsize=1)
def _scaling_results() -> dict[str, list[float]]:
    entropy = EntropyDetector({"min_observations": 3})
    structural = StructuralPatternDetector({"history_size": 250, "max_pattern_length": 4, "min_occurrences": 3})
    ngram = NgramProfiler({"baseline_messages": 5, "window_size": 5, "min_tokens": 20})

    entropy_us = []
    for size in [100, 500, 1000, 5000]:
        entropy_us.append(benchmark(lambda s=size: entropy.analyze_message(_words(s)), iterations=ITERATIONS)["mean_us"])

    structural_us = []
    base_req = _request_10_messages()
    for size in [10, 50, 100, 200]:
        det = StructuralPatternDetector({"history_size": size + 10, "max_pattern_length": 4, "min_occurrences": 3})
        for i in range(size):
            det.check("scale", {"messages": base_req["messages"], "model": "gpt-4o-mini", "tools": ["read" if i % 2 else "write"]})
        structural_us.append(benchmark(lambda d=det: d.check("scale", base_req), iterations=ITERATIONS)["mean_us"])

    ngram_us = []
    for size in [100, 500, 1000, 5000]:
        ngram_us.append(benchmark(lambda s=size: ngram.build_profile(_words(s)), iterations=ITERATIONS)["mean_us"])

    chain_us = []
    for size in [10, 50, 100, 200]:
        messages = _tool_chain_messages(size)
        chain_us.append(benchmark(lambda m=messages: validate_tool_chain(m), iterations=ITERATIONS)["mean_us"])

    _ = structural  # avoid "unused variable" in some linters
    return {
        "entropy": entropy_us,
        "structural": structural_us,
        "ngram": ngram_us,
        "message_chain": chain_us,
    }


def test_scaling_entropy_vs_text_length() -> None:
    vals = _scaling_results()["entropy"]
    assert vals[-1] < _th(14000.0)
    # More forgiving linearity check: allow ~3x growth per 5x text increase.
    assert vals[-1] < vals[0] * _th(75.0)


def test_scaling_structural_vs_history_size() -> None:
    vals = _scaling_results()["structural"]
    assert vals[-1] < _th(10000.0)
    assert vals[-1] < vals[0] * _th(15.0)


def test_scaling_ngram_vs_text_length() -> None:
    vals = _scaling_results()["ngram"]
    assert vals[-1] < _th(10000.0)
    assert vals[-1] < vals[0] * _th(80.0)


def test_scaling_message_chain_vs_messages() -> None:
    vals = _scaling_results()["message_chain"]
    assert vals[-1] < _th(2000.0)
    assert vals[-1] < vals[0] * _th(30.0)
