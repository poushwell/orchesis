"""Performance report generator for Orchesis detectors."""

from __future__ import annotations

import os
import statistics
import time
from datetime import date
from typing import Any, Callable

from orchesis.ars import AgentReliabilityScore
from orchesis.entropy_detector import EntropyDetector
from orchesis.message_chain import validate_tool_chain
from orchesis.ngram_profiler import NgramProfiler
from orchesis.session_risk import RiskSignal, SessionRiskAccumulator
from orchesis.structural_patterns import StructuralPatternDetector
from orchesis.telemetry_export import TelemetryRecord

_ITERATIONS = 1000
_CI_FACTOR = 3.0 if os.environ.get("CI") else 1.0


def _bench(func: Callable[[], Any], iterations: int = _ITERATIONS) -> dict[str, float]:
    samples = []
    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        func()
        samples.append((time.perf_counter_ns() - t0) / 1000.0)
    ordered = sorted(samples)
    return {
        "mean_us": statistics.fmean(samples),
        "p99_us": ordered[min(len(ordered) - 1, int(len(ordered) * 0.99))],
        "max_us": max(samples),
    }


def _words(n: int) -> str:
    vocab = ["agent", "pipeline", "security", "context", "tool", "policy", "telemetry", "model"]
    return " ".join(vocab[i % len(vocab)] for i in range(n))


def _mem_bytes(obj: Any) -> int:
    import sys

    seen: set[int] = set()

    def walk(item: Any) -> int:
        oid = id(item)
        if oid in seen:
            return 0
        seen.add(oid)
        size = sys.getsizeof(item)
        if isinstance(item, dict):
            return size + sum(walk(k) + walk(v) for k, v in item.items())
        if isinstance(item, (list, tuple, set, frozenset)):
            return size + sum(walk(v) for v in item)
        return size

    return walk(obj)


def _table_row(name: str, mean_us: float, p99_us: float, max_us: float) -> str:
    return f"│ {name:<22} │ {mean_us:>5.0f} │ {p99_us:>5.0f} │ {max_us:>5.0f} │"


def _mem_row(name: str, mb: float) -> str:
    return f"│ {name:<22} │ {mb:>7.1f} │"


def generate_performance_report() -> str:
    """Run detector micro-benchmarks and return a plain-text report."""

    text = _words(500)
    req = {
        "messages": [{"role": "user", "content": "check"}, {"role": "assistant", "content": "ok"}],
        "model": "gpt-4o-mini",
        "tools": ["read", "write"],
    }
    chain = [
        {"role": "user", "content": "do"},
        {
            "role": "assistant",
            "content": "calling",
            "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "read", "arguments": "{}"}}],
        },
        {"role": "tool", "tool_call_id": "c1", "content": "done"},
    ]

    entropy = EntropyDetector({"min_observations": 5})
    structural = StructuralPatternDetector({"history_size": 80, "max_pattern_length": 4})
    ngram = NgramProfiler({"baseline_messages": 10, "window_size": 10, "min_tokens": 50})
    risk = SessionRiskAccumulator()
    ars = AgentReliabilityScore()

    for i in range(20):
        entropy.check("a", {"messages": [{"role": "assistant", "content": f"{_words(80)} {i}"}]})
        structural.check("a", req)
        ngram.check("a", f"{_words(80)} warm{i}")
        risk.record_signal(
            "s1",
            RiskSignal(category="prompt_injection", confidence=0.3, severity="low", source="bench", description=str(i)),
        )
        ars.update("a", latency_ms=130.0, token_count=180, has_threat=(i % 10 == 0))

    benches = {
        "entropy.check()": _bench(lambda: entropy.check("a", {"messages": [{"role": "assistant", "content": text}]})),
        "structural.check()": _bench(lambda: structural.check("a", req)),
        "ngram.check()": _bench(lambda: ngram.check("a", text)),
        "session_risk.score()": _bench(lambda: risk.evaluate("s1")),
        "ars.compute()": _bench(lambda: ars.compute_all()),
        "message_chain.validate": _bench(lambda: validate_tool_chain(chain)),
        "telemetry.record()": _bench(lambda: TelemetryRecord(agent_id="a", session_id="s1", total_ms=10.0, upstream_ms=8.0)),
    }

    def full_pipeline() -> None:
        entropy.check("a", {"messages": [{"role": "assistant", "content": text}]})
        structural.check("a", req)
        ngram.check("a", text)
        risk.evaluate("s1")
        ars.compute_all()
        validate_tool_chain(chain)
        _ = TelemetryRecord(agent_id="a", session_id="s1")

    total = _bench(full_pipeline)
    budget_us = 5000.0 * _CI_FACTOR
    status = "WITHIN BUDGET" if total["mean_us"] <= budget_us else "OVER BUDGET"
    mark = "✅" if status == "WITHIN BUDGET" else "❌"

    # Memory model: 100 agents/sessions for comparability.
    entropy_m = EntropyDetector({"window_size": 50})
    structural_m = StructuralPatternDetector({"history_size": 100})
    ngram_m = NgramProfiler({"baseline_messages": 20, "window_size": 10, "top_k": 100})
    risk_m = SessionRiskAccumulator()
    ars_m = AgentReliabilityScore()

    for a in range(100):
        aid = f"agent{a}"
        for i in range(20):
            entropy_m.check(aid, {"messages": [{"role": "assistant", "content": f"{_words(60)} {i}"}]})
            structural_m.check(aid, req)
            ngram_m.check(aid, _words(120))
        risk_m.record_signal(
            aid,
            RiskSignal(category="path_traversal", confidence=0.2, severity="low", source="bench", description="m"),
        )
        ars_m.update(aid, latency_ms=100.0, token_count=120)

    entropy_mb = _mem_bytes(entropy_m.get_all_baselines()) / (1024 * 1024)
    structural_mb = _mem_bytes(structural_m.get_all_agents()) / (1024 * 1024)
    ngram_mb = _mem_bytes(ngram_m.get_all_profiles()) / (1024 * 1024)
    risk_mb = _mem_bytes(risk_m.stats) / (1024 * 1024)
    ars_mb = _mem_bytes(ars_m.stats) / (1024 * 1024)
    total_mb = entropy_mb + structural_mb + ngram_mb + risk_mb + ars_mb
    mem_budget = 50.0 * _CI_FACTOR
    mem_status = "WITHIN BUDGET" if total_mb <= mem_budget else "OVER BUDGET"
    mem_mark = "✅" if mem_status == "WITHIN BUDGET" else "❌"

    lines = [
        "═══════════════════════════════════════════",
        "Orchesis Performance Report",
        f"Date: {date.today().isoformat()}",
        "═══════════════════════════════════════════",
        "",
        "Module Timings (µs):",
        "┌────────────────────────┬───────┬───────┬───────┐",
        "│ Module                 │ Mean  │ P99   │ Max   │",
        "├────────────────────────┼───────┼───────┼───────┤",
    ]
    for name, row in benches.items():
        lines.append(_table_row(name, row["mean_us"], row["p99_us"], row["max_us"]))
    lines.extend(
        [
            "├────────────────────────┼───────┼───────┼───────┤",
            _table_row("TOTAL PIPELINE", total["mean_us"], total["p99_us"], total["max_us"]),
            "└────────────────────────┴───────┴───────┴───────┘",
            "",
            f"Budget: {budget_us:.0f}µs",
            f"Status: {mark} {status} (mean {total['mean_us']:.0f}µs)",
            "",
            "Memory (100 agents):",
            "┌────────────────────────┬─────────┐",
            "│ Module                 │ MB      │",
            "├────────────────────────┼─────────┤",
            _mem_row("entropy baselines", entropy_mb),
            _mem_row("structural histories", structural_mb),
            _mem_row("ngram profiles", ngram_mb),
            _mem_row("session risk", risk_mb),
            _mem_row("ars", ars_mb),
            "├────────────────────────┼─────────┤",
            _mem_row("TOTAL", total_mb),
            "└────────────────────────┴─────────┘",
            "",
            f"Budget: {mem_budget:.1f}MB",
            f"Status: {mem_mark} {mem_status}",
        ]
    )
    return "\n".join(lines)

