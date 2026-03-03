from __future__ import annotations

from orchesis.model_router import ModelRouter


def test_low_complexity_keyword_routes_to_mini() -> None:
    router = ModelRouter({"default": "gpt-4o"})
    result = router.route("Please rename this file")
    assert result["complexity"] == "low"
    assert result["model"] == "gpt-4o-mini"


def test_high_complexity_keyword_routes_to_default() -> None:
    router = ModelRouter({"default": "gpt-4o"})
    result = router.route("Please analyze and design this architecture")
    assert result["complexity"] == "high"
    assert result["model"] == "gpt-4o"


def test_short_prompt_routes_low() -> None:
    router = ModelRouter({"default": "gpt-4o"})
    result = router.route("hi")
    assert result["complexity"] == "low"


def test_long_prompt_routes_high() -> None:
    router = ModelRouter({"default": "gpt-4o"})
    result = router.route("x" * 2501)
    assert result["complexity"] == "high"


def test_no_keywords_medium_default_model() -> None:
    router = ModelRouter({"default": "gpt-4o"})
    result = router.route("This is a normal request with moderate amount of details and no special triggers")
    assert result["complexity"] == "medium"
    assert result["model"] == "gpt-4o"


def test_custom_keywords_from_config() -> None:
    router = ModelRouter({"default": "gpt-4o", "low_keywords": ["tinytask"], "high_keywords": ["megatask"]})
    assert router.route("please tinytask now")["complexity"] == "low"
    assert router.route("please megatask now")["complexity"] == "high"


def test_cost_ratio_calculation_positive() -> None:
    router = ModelRouter({"default": "gpt-4o"})
    result = router.route("rename file")
    assert result["cost_ratio"] > 0


def test_savings_estimate_nonzero_after_low_routes() -> None:
    router = ModelRouter({"default": "gpt-4o"})
    router.route("rename this")
    router.route("format this")
    estimate = router.get_savings_estimate()
    assert estimate["calls_downgraded"] >= 1
    assert estimate["estimated_savings_percent"] >= 0


def test_routing_log_recorded() -> None:
    router = ModelRouter({"default": "gpt-4o"})
    router.route("rename this")
    stats = router.get_savings_estimate()
    assert stats["total_calls_routed"] == 1


def test_none_prompt_handled() -> None:
    router = ModelRouter({"default": "gpt-4o"})
    result = router.route(None)
    assert "model" in result


def test_empty_prompt_handled() -> None:
    router = ModelRouter({"default": "gpt-4o"})
    result = router.route("")
    assert result["complexity"] == "low"


def test_tool_name_considered_for_simple_hint() -> None:
    router = ModelRouter({"default": "gpt-4o"})
    result = router.route("no keywords here but enough chars to avoid short prompt fallback " * 2, tool_name="read_file")
    assert result["complexity"] == "low"


def test_custom_rule_for_medium_complexity() -> None:
    router = ModelRouter(
        {
            "default": "gpt-4o",
            "rules": [
                {"complexity": "low", "model": "gpt-4o-mini"},
                {"complexity": "medium", "model": "gpt-4.1-mini"},
                {"complexity": "high", "model": "gpt-4o"},
            ],
        }
    )
    result = router.route("This request has moderate context and should map to medium routing.")
    assert result["model"] == "gpt-4.1-mini"


def test_reason_contains_keyword_on_high_match() -> None:
    router = ModelRouter({"default": "gpt-4o"})
    result = router.route("please audit this system")
    assert "keyword" in result["reason"]


def test_reason_contains_keyword_on_low_match() -> None:
    router = ModelRouter({"default": "gpt-4o"})
    result = router.route("please list files")
    assert "keyword" in result["reason"]


def test_savings_estimate_zero_when_no_calls() -> None:
    router = ModelRouter({"default": "gpt-4o"})
    estimate = router.get_savings_estimate()
    assert estimate["estimated_savings_percent"] == 0

