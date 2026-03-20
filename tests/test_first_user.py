from __future__ import annotations


def test_install_and_import() -> None:
    """Everything a user does after pip install works."""
    import orchesis
    from orchesis.api import create_api_app
    from orchesis.cli import main
    from orchesis.dashboard import get_dashboard_html
    from orchesis.proxy import LLMHTTPProxy

    _ = (LLMHTTPProxy, main, create_api_app, get_dashboard_html)
    assert orchesis.__version__ is not None


def test_dashboard_html_valid() -> None:
    """Dashboard HTML is valid and has key elements."""
    from orchesis.dashboard import get_dashboard_html

    html = get_dashboard_html()
    assert "<html" in html or "<!DOCTYPE" in html
    assert "orchesis" in html.lower() or "Orchesis" in html


def test_openai_drop_in() -> None:
    """OpenAI compat layer normalizes real-looking request."""
    from orchesis.compat.openai import OpenAICompatLayer

    layer = OpenAICompatLayer()
    req = {
        "model": "gpt-4o",
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "What is 2+2?"},
        ],
        "temperature": 0.7,
    }
    normalized = layer.normalize_request(req)
    assert normalized["model"] == "gpt-4o"
    assert normalized["cost"] > 0
    assert normalized["metadata"]["provider"] == "openai"


def test_anthropic_drop_in() -> None:
    """Anthropic compat layer handles system prompt correctly."""
    from orchesis.compat.anthropic import AnthropicCompatLayer

    layer = AnthropicCompatLayer()
    req = {
        "model": "claude-sonnet-4-6",
        "system": "You are helpful.",
        "messages": [{"role": "user", "content": "Hello"}],
        "max_tokens": 100,
    }
    normalized = layer.normalize_request(req)
    system_msgs = [m for m in normalized["messages"] if m["role"] == "system"]
    assert len(system_msgs) == 1


def test_cost_calculator_real_scenario() -> None:
    """Cost calculator gives realistic numbers for typical usage."""
    from orchesis.cost_of_freedom import CostOfFreedomCalculator

    calc = CostOfFreedomCalculator()
    result = calc.calculate(
        {
            "daily_requests": 10000,
            "avg_tokens_per_request": 2000,
            "cost_per_ktok": 0.005,
        }
    )
    assert result["total_monthly_savings"] > 50
    assert result["roi"] > 10


def test_policy_library_templates_valid() -> None:
    """All 5 policy templates are valid and loadable."""
    from orchesis.config_validator import ConfigValidator
    from orchesis.policy_library import LIBRARY, PolicyLibrary

    lib = PolicyLibrary()
    validator = ConfigValidator()
    for template_id in LIBRARY:
        policy = lib.get_policy(template_id)
        assert policy is not None
        result = validator.validate(policy)
        assert result["errors"] == [], f"Template {template_id} has errors: {result['errors']}"


def test_autopsy_real_scenario() -> None:
    """Autopsy correctly diagnoses a loop scenario."""
    from orchesis.agent_autopsy import AgentAutopsy

    autopsy = AgentAutopsy()
    events = [
        {"session_id": "s1", "decision": "ALLOW", "tokens": 1000, "reasons": []},
        {"session_id": "s1", "decision": "ALLOW", "tokens": 2000, "reasons": []},
        {"session_id": "s1", "decision": "DENY", "tokens": 3000, "reasons": ["loop_detected"]},
    ]
    result = autopsy.perform("s1", events)
    assert result["cause_of_death"] == "loop_detected"
    assert result["preventable"] is True
    assert len(result["recommendations"]) > 0


def test_sdk_all_methods_exist() -> None:
    """SDK has all documented methods."""
    from orchesis.sdk import OrchesisClient

    client = OrchesisClient()
    expected = [
        "get_health",
        "evaluate",
        "get_stats",
        "run_autopsy",
        "create_incident",
        "get_aabb_leaderboard",
        "get_are_report",
    ]
    for method in expected:
        assert hasattr(client, method), f"Missing SDK method: {method}"
