from __future__ import annotations

from orchesis.context_window_optimizer import ContextWindowOptimizer
from orchesis.proxy import LLMHTTPProxy, _RequestContext


def _msg(role: str, content: str) -> dict:
    return {"role": role, "content": content}


def test_available_tokens_computed() -> None:
    opt = ContextWindowOptimizer({"safety_margin": 0.1})
    available = opt.get_available_tokens("gpt-4o-mini", 1000)
    assert available == int(128000 * 0.9) - 1000


def test_model_recommendation() -> None:
    opt = ContextWindowOptimizer({"safety_margin": 0.1})
    model = opt.recommend_model(50_000)
    assert model in {"gpt-4o-mini", "gpt-4-turbo", "gpt-4o"}


def test_optimize_fits_window() -> None:
    opt = ContextWindowOptimizer({"safety_margin": 0.1})
    messages = [_msg("system", "You are helpful")] + [_msg("user", "x" * 10000) for _ in range(120)]
    result = opt.optimize_for_model(messages, "gpt-4o-mini")
    assert result["optimized_tokens"] <= result["original_tokens"]
    assert isinstance(result["messages"], list)
    assert result["fits"] in {True, False}


def test_split_long_context() -> None:
    opt = ContextWindowOptimizer({"safety_margin": 0.1})
    messages = [_msg("user", "y" * 60000) for _ in range(12)]
    chunks = opt.split_for_context(messages, "gpt-4o-mini")
    assert len(chunks) >= 2
    assert all(isinstance(chunk, list) and chunk for chunk in chunks)


def test_safety_margin_respected() -> None:
    opt = ContextWindowOptimizer({"safety_margin": 0.2})
    available = opt.get_available_tokens("gpt-4o-mini", 0)
    assert available == int(128000 * 0.8)


def test_unknown_model_fallback() -> None:
    opt = ContextWindowOptimizer({"safety_margin": 0.1})
    available = opt.get_available_tokens("unknown-model", 100)
    assert available == int(128000 * 0.9) - 100


def test_proxy_integration() -> None:
    class FakeHandler:
        pass

    proxy = LLMHTTPProxy(policy_path=None)
    proxy._context_engine = None
    proxy._context_budget = None
    proxy._context_window_optimizer = ContextWindowOptimizer({"safety_margin": 0.1})

    messages = [_msg("system", "You are concise")] + [_msg("user", "z" * 10000) for _ in range(120)]
    ctx = _RequestContext(
        handler=FakeHandler(),
        body={"messages": messages, "model": "gpt-4o-mini", "max_tokens": 0},
    )
    ok = proxy._phase_context(ctx)
    assert ok is True
    assert "context_window_optimizer" in ctx.proc_result
    info = ctx.proc_result["context_window_optimizer"]
    assert int(info["optimized_tokens"]) <= int(info["original_tokens"])
