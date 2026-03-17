from __future__ import annotations

from pathlib import Path

from orchesis.context_dna import ContextDNA
from orchesis.context_dna_store import ContextDNAStore


def _request(
    *,
    model: str = "gpt-4o",
    content: str = "hello world",
    tools: list[str] | None = None,
    topic: str = "general",
) -> dict:
    return {
        "model": model,
        "messages": [{"role": "user", "content": content}],
        "tools": tools or [],
        "topic": topic,
    }


def _decision(
    *,
    decision: str = "ALLOW",
    duration_ms: float = 100.0,
    cache_hit: bool = False,
    error: bool = False,
) -> dict:
    return {
        "decision": decision,
        "duration_ms": duration_ms,
        "cache_hit": cache_hit,
        "error": error,
    }


def test_dna_cold_start_flag() -> None:
    dna = ContextDNA("agent-1")
    assert dna.cold_start is True


def test_observe_updates_dimensions() -> None:
    dna = ContextDNA("agent-1")
    dna.observe(
        _request(content="A" * 200, tools=["read_file"], topic="ops"),
        _decision(duration_ms=250.0, cache_hit=True),
    )
    baseline = dna.compute_baseline()
    assert baseline["avg_prompt_length"] > 0
    assert baseline["tool_call_frequency"] >= 1.0
    assert baseline["session_duration_avg"] == 250.0
    assert baseline["cache_hit_rate"] == 1.0
    assert "ops" in baseline["topic_distribution"]


def test_baseline_computed_after_observations() -> None:
    dna = ContextDNA("agent-1")
    for _ in range(3):
        dna.observe(_request(content="x" * 40), _decision(duration_ms=100.0))
    baseline = dna.compute_baseline()
    assert isinstance(baseline, dict)
    for dim in ContextDNA.DIMENSIONS:
        assert dim in baseline


def test_anomaly_score_high_on_deviation() -> None:
    dna = ContextDNA("agent-1")
    for _ in range(10):
        dna.observe(_request(content="x" * 20, tools=[]), _decision(duration_ms=100.0, cache_hit=False))
    dna.compute_baseline()
    current = {
        "avg_prompt_length": 5000.0,
        "tool_call_frequency": 12.0,
        "model_switch_rate": 1.0,
        "session_duration_avg": 8000.0,
        "cache_hit_rate": 1.0,
        "error_rate": 1.0,
    }
    assert dna.anomaly_score(current) > 0.5


def test_anomaly_score_low_on_normal() -> None:
    dna = ContextDNA("agent-1")
    for _ in range(10):
        dna.observe(_request(content="x" * 80, tools=["read_file"]), _decision(duration_ms=200.0, cache_hit=True))
    baseline = dna.compute_baseline()
    current = {
        "avg_prompt_length": baseline["avg_prompt_length"],
        "tool_call_frequency": baseline["tool_call_frequency"],
        "model_switch_rate": baseline["model_switch_rate"],
        "session_duration_avg": baseline["session_duration_avg"],
        "cache_hit_rate": baseline["cache_hit_rate"],
        "error_rate": baseline["error_rate"],
    }
    assert dna.anomaly_score(current) <= 0.5


def test_export_and_load_roundtrip() -> None:
    dna = ContextDNA("agent-1")
    dna.observe(_request(topic="secops"), _decision(duration_ms=123.0))
    dna.compute_baseline()
    blob = dna.export()

    loaded = ContextDNA("placeholder")
    loaded.load(blob)
    assert loaded.agent_id == "agent-1"
    assert loaded.baseline is not None
    assert loaded.baseline["session_duration_avg"] == 123.0


def test_store_save_and_retrieve(tmp_path: Path) -> None:
    store = ContextDNAStore(storage_path=str(tmp_path / "dna"))
    dna = ContextDNA("agent-xyz")
    dna.observe(_request(content="abc"), _decision())
    dna.compute_baseline()
    store.save(dna)

    restored = store.get("agent-xyz")
    assert restored is not None
    assert restored.agent_id == "agent-xyz"
    assert restored.baseline is not None
    assert "agent-xyz" in store.list_agents()

