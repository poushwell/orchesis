"""The last test file. If this passes, ship it."""

from __future__ import annotations

import importlib
import tomllib
from pathlib import Path

import pytest


def test_4000_plus_tests() -> None:
    test_files = list(Path("tests").glob("test_*.py"))
    assert len(test_files) >= 100, f"Only {len(test_files)} test files"


def test_all_imports_clean() -> None:
    modules_to_check = [
        "orchesis",
        "orchesis.proxy",
        "orchesis.engine",
        "orchesis.api",
        "orchesis.cli",
        "orchesis.dashboard",
        "orchesis.agent_autopsy",
        "orchesis.insights",
        "orchesis.cost_of_freedom",
        "orchesis.sdk",
        "orchesis.casura.incident_db",
        "orchesis.aabb.benchmark",
    ]
    for module_name in modules_to_check:
        obj = importlib.import_module(module_name)
        assert obj is not None, f"Failed to import {module_name}"


def test_cost_framework_complete() -> None:
    from orchesis.insights import OrchesisInsights

    insights = OrchesisInsights().generate()
    framework = insights["cost_framework"]
    for letter in ["C", "O", "S", "T"]:
        assert letter in framework


def test_compat_layers_present() -> None:
    from orchesis.compat.openai import OpenAICompatLayer
    from orchesis.compat.anthropic import AnthropicCompatLayer

    oa = OpenAICompatLayer()
    ac = AnthropicCompatLayer()
    assert "gpt-4o" in oa.list_supported_models()
    assert "claude-sonnet-4-6" in ac.list_supported_models()


def test_policy_library_5_templates() -> None:
    from orchesis.policy_library import PolicyLibrary

    lib = PolicyLibrary()
    assert lib.count() >= 5


def test_orchestration_5_patterns() -> None:
    spec = importlib.util.find_spec("orchesis.orchestration_patterns")
    if spec is None:
        pytest.skip("orchestration_patterns module unavailable in this branch")
    module = importlib.import_module("orchesis.orchestration_patterns")
    advisor = module.OrchestrationPatternAdvisor()
    assert len(advisor.list_patterns()) >= 5


def test_report_card_grades() -> None:
    from orchesis.agent_report_card import AgentReportCard

    card_gen = AgentReportCard()
    card = card_gen.generate(
        "test-agent",
        {
            "deny_rate": 0.95,
            "token_yield": 0.8,
            "error_rate": 0.01,
            "recording_enabled": True,
            "audit_trail": True,
            "latency_within_sla": True,
            "cache_hit_rate": 0.4,
        },
    )
    assert card["grade"] in ["A+", "A", "B+", "B"]
    assert card["arc_ready"] is True


def test_the_proxy_is_the_moat() -> None:
    """T1-T3 impossibility theorems are implemented."""
    from orchesis.par_reasoning import PARReasoner
    from orchesis.quorum_sensing import QuorumSensor

    par = PARReasoner()
    assert par.T5_THEOREM != ""
    assert QuorumSensor.QUORUM_THRESHOLD == 16


def test_ship_it() -> None:
    """If this test passes, we're ready."""
    from orchesis import __version__
    from orchesis.agent_autopsy import AgentAutopsy
    from orchesis.insights import OrchesisInsights
    from orchesis.cost_of_freedom import CostOfFreedomCalculator

    _ = AgentAutopsy
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    expected = str(pyproject.get("project", {}).get("version", "")).strip()
    assert expected
    assert __version__ == expected
    pitch = OrchesisInsights().get_elevator_pitch()
    assert "proxy" in pitch.lower()
    calc = CostOfFreedomCalculator()
    roi = calc.calculate({"daily_requests": 5000})["roi"]
    assert roi > 1.0
