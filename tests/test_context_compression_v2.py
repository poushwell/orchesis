from __future__ import annotations

from orchesis.context_budget import ContextBudget
from orchesis.context_compression_v2 import ContextCompressionV2
from orchesis.proxy import LLMHTTPProxy, _RequestContext


def _msg(role: str, content: str) -> dict:
    return {"role": role, "content": content}


def test_compression_reduces_messages() -> None:
    cc = ContextCompressionV2({"algorithm": "importance_scoring", "target_ratio": 0.5})
    messages = [_msg("user", f"message {i}") for i in range(10)]
    result = cc.compress(messages, budget_tokens=1000)
    assert result["compressed_count"] < result["original_count"]


def test_importance_scoring_keeps_recent() -> None:
    cc = ContextCompressionV2({"algorithm": "importance_scoring", "target_ratio": 0.5})
    context = [_msg("user", "old repeated text"), _msg("assistant", "latest tool result with error")]
    old_score = cc.score_importance(context[0], context)
    new_score = cc.score_importance(context[1], context)
    assert new_score >= old_score


def test_semantic_dedup_removes_similar() -> None:
    cc = ContextCompressionV2({"algorithm": "semantic_dedup", "target_ratio": 1.0})
    messages = [
        _msg("user", "Repeat this request"),
        _msg("user", "Repeat this   request"),
        _msg("assistant", "Different response"),
    ]
    deduped = cc.semantic_dedup(messages)
    assert len(deduped) == 2


def test_quality_score_above_threshold() -> None:
    cc = ContextCompressionV2({"algorithm": "importance_scoring", "target_ratio": 0.7})
    messages = [_msg("user", f"text {i}") for i in range(12)]
    result = cc.compress(messages, budget_tokens=1000)
    assert float(result["quality_score"]) >= 0.6


def test_tokens_saved_positive() -> None:
    cc = ContextCompressionV2({"algorithm": "importance_scoring", "target_ratio": 0.5})
    messages = [_msg("user", "x" * 400) for _ in range(8)]
    result = cc.compress(messages, budget_tokens=10_000)
    assert int(result["tokens_saved"]) > 0


def test_stats_tracked() -> None:
    cc = ContextCompressionV2({"algorithm": "recency_weighted", "target_ratio": 0.5})
    cc.compress([_msg("user", "a"), _msg("assistant", "b"), _msg("user", "c")], budget_tokens=1000)
    stats = cc.get_stats()
    assert int(stats["runs"]) == 1
    assert "avg_ratio" in stats
    assert "avg_quality" in stats


def test_empty_messages_safe() -> None:
    cc = ContextCompressionV2({"algorithm": "topic_clustering", "target_ratio": 0.7})
    result = cc.compress([], budget_tokens=100)
    assert result["compressed_messages"] == []
    assert result["tokens_saved"] == 0


def test_proxy_integration() -> None:
    class FakeHandler:
        pass

    proxy = LLMHTTPProxy(policy_path=None)
    proxy._context_engine = None
    proxy._context_budget = ContextBudget(
        {
            "enabled": True,
            "model_context_windows": {"gpt-4o-mini": 20},
            "l0_threshold": 0.5,
            "l1_threshold": 0.7,
            "l2_threshold": 0.9,
        }
    )
    proxy._compression_v2 = ContextCompressionV2({"enabled": True, "algorithm": "importance_scoring", "target_ratio": 0.5})
    messages = [_msg("system", "you are helpful")] + [_msg("user", "x" * 200) for _ in range(10)]
    ctx = _RequestContext(
        handler=FakeHandler(),
        body={"messages": messages, "model": "gpt-4o-mini", "max_tokens": 0},
    )
    ok = proxy._phase_context(ctx)
    assert ok is True
    assert "context_budget_level" in ctx.proc_result
    assert "compression_v2" in ctx.proc_result
    info = ctx.proc_result["compression_v2"]
    assert int(info["compressed_count"]) <= int(info["original_count"])
