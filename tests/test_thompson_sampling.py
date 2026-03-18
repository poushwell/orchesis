from __future__ import annotations

from orchesis.proxy import LLMHTTPProxy, _RequestContext
from orchesis.thompson_sampling import ThompsonSampler


def test_sample_returns_valid_arm() -> None:
    sampler = ThompsonSampler({"seed": 7, "explore_rate": 0.0})
    arm = sampler.sample("coding", ["gpt-4o", "gpt-4o-mini"])
    assert arm in {"gpt-4o", "gpt-4o-mini"}


def test_update_shifts_distribution() -> None:
    sampler = ThompsonSampler({"seed": 7, "explore_rate": 0.0})
    before = sampler.get_best_arm("coding")
    for _ in range(200):
        sampler.update("gpt-4o-mini", "coding", 0.95)
        sampler.update("gpt-4o", "coding", 0.05)
    after = sampler.get_best_arm("coding")
    assert before in ThompsonSampler.ARMS
    assert after == "gpt-4o-mini"


def test_best_arm_after_many_updates() -> None:
    sampler = ThompsonSampler({"seed": 42, "explore_rate": 0.0})
    for _ in range(300):
        sampler.update("gpt-4o", "analysis", 0.9)
        sampler.update("claude-3-haiku", "analysis", 0.2)
    assert sampler.get_best_arm("analysis") == "gpt-4o"


def test_regret_decreases_over_time() -> None:
    sampler = ThompsonSampler({"seed": 123, "explore_rate": 0.2})
    arms = ["gpt-4o", "gpt-4o-mini"]
    # Best arm is gpt-4o-mini for research in this synthetic environment.
    for idx in range(300):
        chosen = sampler.sample("research", arms)
        reward = 0.9 if chosen == "gpt-4o-mini" else 0.2
        sampler.update(chosen, "research", reward)
        if idx == 99:
            regret_early = sampler.get_regret() / max(1, len(sampler._observations))
    regret_late = sampler.get_regret() / max(1, len(sampler._observations))
    assert regret_late < regret_early


def test_per_task_type_different_winners() -> None:
    sampler = ThompsonSampler({"seed": 9, "explore_rate": 0.0})
    for _ in range(250):
        sampler.update("gpt-4o", "coding", 0.92)
        sampler.update("gpt-4o-mini", "coding", 0.2)
        sampler.update("gpt-4o-mini", "research", 0.9)
        sampler.update("gpt-4o", "research", 0.25)
    assert sampler.get_best_arm("coding") == "gpt-4o"
    assert sampler.get_best_arm("research") == "gpt-4o-mini"


def test_reset_arm_clears_history() -> None:
    sampler = ThompsonSampler({"seed": 10})
    for _ in range(50):
        sampler.update("claude-3-haiku", "unknown", 0.8)
    assert sampler.get_arm_stats("claude-3-haiku")["total_samples"] == 50
    sampler.reset_arm("claude-3-haiku")
    stats = sampler.get_arm_stats("claude-3-haiku")
    assert stats["total_samples"] == 0
    assert stats["avg_reward"] == 0.0


def test_proxy_integration() -> None:
    class _FakeHandler:
        headers = {}
        path = "/v1/chat/completions"

    class _ParsedReq:
        provider = "openai"
        content_text = "please write code and refactor"
        tool_calls = []
        model = "gpt-4o"

    proxy = LLMHTTPProxy(policy_path=None)
    proxy._thompson = None
    proxy._thompson_sampler = ThompsonSampler({"seed": 1, "explore_rate": 0.0})
    ctx = _RequestContext(
        handler=_FakeHandler(),
        body={
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "please write code and refactor"}],
            "tools": [{"name": "read_file"}],
        },
        parsed_req=_ParsedReq(),
    )
    ok = proxy._phase_model_router(ctx)
    assert ok is True
    assert ctx.body["model"] in ThompsonSampler.ARMS
    assert "X-Orchesis-TS-Model" in ctx.session_headers
    assert "thompson_sampling" in ctx.proc_result
