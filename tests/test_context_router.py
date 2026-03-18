from __future__ import annotations

from orchesis.context_router import ContextStrategyRouter


def test_classify_coding_task() -> None:
    router = ContextStrategyRouter()
    messages = [{"role": "user", "content": "Please implement a Python function and debug this class."}]
    task_type = router.classify(messages, tools_used=["read_file"])
    assert task_type == "coding"


def test_classify_research_task() -> None:
    router = ContextStrategyRouter()
    messages = [{"role": "user", "content": "Find sources and browse references."}]
    task_type = router.classify(messages, tools_used=["web_fetch"])
    assert task_type == "research"


def test_classify_unknown_falls_back() -> None:
    router = ContextStrategyRouter()
    messages = [{"role": "user", "content": "hello there"}]
    task_type = router.classify(messages, tools_used=[])
    assert task_type == "unknown"


def test_strategy_selected_per_type() -> None:
    router = ContextStrategyRouter()
    assert router.get_strategy("coding") == "preserve_structure"
    assert router.get_strategy("research") == "summarize_old"
    assert router.get_strategy("missing") == "balanced"


def test_coding_strategy_preserves_code_blocks() -> None:
    router = ContextStrategyRouter()
    messages = [
        {"role": "system", "content": "You are helpful."},
        {"role": "user", "content": "small prose"},
        {"role": "assistant", "content": "```python\ndef f():\n    return 1\n```"},
        {"role": "assistant", "content": "extra filler text " * 200},
    ]
    optimized = router.apply_strategy(messages, "preserve_structure", max_tokens=40)
    combined = "\n".join(str(item.get("content", "")) for item in optimized)
    assert "```python" in combined


def test_research_strategy_summarizes_old() -> None:
    router = ContextStrategyRouter()
    messages = [{"role": "user", "content": f"message {i} about search"} for i in range(20)]
    optimized = router.apply_strategy(messages, "summarize_old", max_tokens=40)
    assert any("Summary:" in str(item.get("content", "")) for item in optimized)


def test_stats_tracked_per_type() -> None:
    router = ContextStrategyRouter()
    router.classify([{"role": "user", "content": "implement function"}], [])
    router.classify([{"role": "user", "content": "web_fetch and search"}], [])
    stats = router.get_stats()
    assert stats["total_classifications"] == 2
    assert stats["distribution"]["coding"] >= 1
    assert stats["distribution"]["research"] >= 1
