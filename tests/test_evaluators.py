from __future__ import annotations

from orchesis.engine import evaluate
from orchesis.evaluators import (
    AllowlistEvaluator,
    BaseEvaluator,
    EvaluatorRegistry,
    EvaluatorResult,
    KeywordBlockEvaluator,
)


class _AlwaysDenyEvaluator(BaseEvaluator):
    @property
    def name(self) -> str:
        return "always_deny"

    def evaluate(self, request: dict, context: dict) -> EvaluatorResult:
        _ = request, context
        return EvaluatorResult("deny", "forced deny")


def test_custom_evaluator_blocks_request() -> None:
    registry = EvaluatorRegistry()
    registry.register(_AlwaysDenyEvaluator())
    decision = evaluate({"tool": "read_file", "params": {}, "cost": 0.0}, {"rules": []}, registry=registry)
    assert decision.allowed is False
    assert any(reason.startswith("evaluator:") for reason in decision.reasons)


def test_evaluator_registry_runs_all() -> None:
    registry = EvaluatorRegistry()
    registry.register(KeywordBlockEvaluator(keywords=["DROP TABLE"]))
    registry.register(AllowlistEvaluator(patterns=[r"^read_file .*"], action="warn"))
    results = registry.run_all({"tool": "read_file", "params": {"query": "DROP TABLE users"}}, {})
    assert len(results) == 2
    assert all(isinstance(item, EvaluatorResult) for item in results)


def test_keyword_block_evaluator() -> None:
    evaluator = KeywordBlockEvaluator(keywords=["rm -rf"], action="deny")
    result = evaluator.evaluate({"tool": "shell", "params": {"cmd": "rm -rf /tmp"}}, {})
    assert result.action == "deny"
    assert "matched keyword" in result.reason


def test_allowlist_evaluator() -> None:
    evaluator = AllowlistEvaluator(patterns=[r"^[a-zA-Z0-9 .,?!]+$"], action="deny")
    allow_result = evaluator.evaluate({"tool": "ask", "params": {"text": "Hello world"}}, {})
    deny_result = evaluator.evaluate({"tool": "ask", "params": {"text": "DROP TABLE users;"}}, {})
    assert allow_result.action == "allow"
    assert deny_result.action == "deny"


def test_evaluator_loaded_from_config() -> None:
    registry = EvaluatorRegistry()
    registry.load_from_config(
        {
            "evaluators": [
                {"type": "keyword_block", "keywords": ["DROP TABLE"], "action": "deny"},
                {"type": "allowlist", "patterns": ["^[a-zA-Z0-9 .,?!]+$"]},
                {"type": "rate_limit", "max_requests": 10, "window_seconds": 60},
            ]
        }
    )
    results = registry.run_all({"tool": "sql", "params": {"q": "DROP TABLE users"}}, {})
    assert len(results) == 3


def test_evaluator_result_allow_deny_warn() -> None:
    allow = EvaluatorResult("allow", "ok")
    deny = EvaluatorResult("deny", "blocked")
    warn = EvaluatorResult("warn", "careful")
    assert allow.action == "allow"
    assert deny.action == "deny"
    assert warn.action == "warn"
