from __future__ import annotations

from orchesis.proxy import LLMHTTPProxy, _RequestContext
from orchesis.uci_compression import UCICompressor


def _msg(role: str, content: str) -> dict:
    return {"role": role, "content": content}


def test_uci_score_computed() -> None:
    comp = UCICompressor({})
    context = [_msg("user", "compile report"), _msg("assistant", "report compiled")]
    score = comp.compute_uci(context[0], context)
    assert 0.0 <= score <= 1.0


def test_shapley_higher_for_referenced_messages() -> None:
    comp = UCICompressor({})
    base = _msg("user", "alpha unique")
    referenced = _msg("user", "database migration plan")
    context = [
        base,
        referenced,
        _msg("assistant", "about the database migration we should add rollback"),
        _msg("user", "confirm migration plan with rollback"),
    ]
    assert comp.shapley_value(referenced, context) > comp.shapley_value(base, context)


def test_tig_decays_with_age() -> None:
    comp = UCICompressor({})
    older = comp.tig_score(_msg("user", "old"), position=0, total=5)
    recent = comp.tig_score(_msg("user", "new"), position=4, total=5)
    assert recent > older


def test_compression_keeps_high_uci() -> None:
    comp = UCICompressor({})
    high = _msg("user", "critical migration rollback recovery strategy")
    low = _msg("assistant", "ok ok ok ok ok")
    messages = [low, high, _msg("user", "rollback strategy for migration again"), _msg("assistant", "noted")]
    result = comp.compress(messages, budget_tokens=25)
    kept = [m.get("content", "") for m in result["messages"]]
    assert any("migration" in text for text in kept)


def test_compression_budget_respected() -> None:
    comp = UCICompressor({})
    messages = [_msg("user", "x" * 120) for _ in range(12)]
    result = comp.compress(messages, budget_tokens=40)
    assert int(result["compressed_count"]) <= int(result["original_count"])
    assert int(result["tokens_saved"]) >= 0


def test_stats_tracked() -> None:
    comp = UCICompressor({})
    comp.compress([_msg("user", "a"), _msg("assistant", "b"), _msg("user", "c")], budget_tokens=6)
    stats = comp.get_stats()
    assert int(stats["compressions"]) == 1
    assert "avg_ratio" in stats


def test_proxy_integration() -> None:
    class FakeHandler:
        pass

    proxy = LLMHTTPProxy(policy_path=None)
    proxy._context_engine = None
    proxy._context_budget = None
    proxy._uci_compressor = UCICompressor({"enabled": True})
    messages = [_msg("system", "You are helpful")] + [_msg("user", "long text " * 80) for _ in range(8)]
    ctx = _RequestContext(
        handler=FakeHandler(),
        body={"messages": messages, "model": "gpt-4o-mini", "max_tokens": 120},
    )
    ok = proxy._phase_context(ctx)
    assert ok is True
    assert "uci_compression" in ctx.proc_result
    info = ctx.proc_result["uci_compression"]
    assert int(info["compressed_count"]) <= int(info["original_count"])


def test_empty_messages_safe() -> None:
    comp = UCICompressor({})
    out = comp.compress([], budget_tokens=100)
    assert out["messages"] == []
    assert out["tokens_saved"] == 0
