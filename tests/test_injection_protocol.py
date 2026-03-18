from __future__ import annotations

from orchesis.injection_protocol import ContextInjectionProtocol
from orchesis.proxy import LLMHTTPProxy, _RequestContext


def _msg(role: str, content: str) -> dict:
    return {"role": role, "content": content}


def test_should_inject_below_threshold() -> None:
    ip = ContextInjectionProtocol({"strategy": "reactive", "quality_threshold": 0.7, "max_tokens": 120})
    decision = ip.should_inject({"request_count": 1}, {"quality_score": 0.4, "budget_level": "normal"})
    assert decision["inject"] is True
    assert decision["reason"] == "quality_below_threshold"


def test_no_injection_above_threshold() -> None:
    ip = ContextInjectionProtocol({"strategy": "reactive", "quality_threshold": 0.5})
    decision = ip.should_inject({"request_count": 2}, {"quality_score": 0.9, "budget_level": "normal"})
    assert decision["inject"] is False


def test_content_selected_within_budget() -> None:
    ip = ContextInjectionProtocol({"strategy": "adaptive", "max_tokens": 20})
    pool = [
        _msg("system", "a" * 40),
        _msg("assistant", "b" * 40),
        _msg("assistant", "c" * 200),
    ]
    selected = ip.select_content(pool, budget=20)
    # 20 token budget ~= 80 chars
    total_chars = sum(len(item["content"]) for item in selected)
    assert total_chars <= 80


def test_injection_applied_to_messages() -> None:
    ip = ContextInjectionProtocol({"strategy": "proactive", "max_tokens": 100})
    messages = [_msg("system", "policy"), _msg("user", "question")]
    result = ip.inject(messages, [_msg("system", "extra context")])
    assert result["injected_count"] == 1
    assert result["tokens_injected"] > 0
    assert len(result["messages"]) == 3


def test_injection_log_tracked() -> None:
    ip = ContextInjectionProtocol({"strategy": "adaptive"})
    _ = ip.inject([_msg("user", "q")], [_msg("system", "hint")])
    assert ip._injection_log  # noqa: SLF001


def test_adaptive_strategy_uses_kalman() -> None:
    # "adaptive" should react to budget pressure even if quality is not yet below threshold.
    ip = ContextInjectionProtocol({"strategy": "adaptive", "quality_threshold": 0.6})
    decision = ip.should_inject({"request_count": 3}, {"quality_score": 0.9, "budget_level": "L2"})
    assert decision["inject"] is True
    assert decision["reason"] in {"adaptive_budget_pressure", "quality_below_threshold"}


def test_proxy_integration() -> None:
    class FakeHandler:
        pass

    proxy = LLMHTTPProxy(policy_path=None)
    proxy._context_engine = None
    proxy._context_optimizer = None
    proxy._cost_optimizer = None
    proxy._context_window_optimizer = None
    proxy._context_budget = None
    proxy._apoptosis = None
    proxy._injection_protocol = ContextInjectionProtocol(
        {"strategy": "reactive", "quality_threshold": 0.8, "max_tokens": 80}
    )
    ctx = _RequestContext(
        handler=FakeHandler(),
        body={
            "model": "gpt-4o-mini",
            "messages": [
                _msg("system", "existing system context"),
                _msg("assistant", "cached prior decision"),
                _msg("user", "current question"),
            ],
            "orchesis_context": [_msg("system", "inject me first")],
        },
    )
    ctx.proc_result["quality_score"] = 0.3
    ok = proxy._phase_context(ctx)
    assert ok is True
    assert "injection_protocol" in ctx.proc_result
    assert int(ctx.proc_result["injection_protocol"]["injected_count"]) >= 1


def test_stats_updated() -> None:
    ip = ContextInjectionProtocol({"strategy": "scheduled", "max_tokens": 120})
    decision = ip.should_inject({"request_count": 5}, {"quality_score": 0.9, "budget_level": "normal"})
    assert decision["inject"] is True
    selected = ip.select_content([_msg("system", "context")], 120)
    _ = ip.inject([_msg("user", "q")], selected)
    stats = ip.get_injection_stats()
    assert int(stats["total_injections"]) == 1
    assert float(stats["avg_tokens_injected"]) >= 0.0
