from __future__ import annotations

from orchesis.policy_library import LIBRARY, PolicyLibrary


def test_templates_listed() -> None:
    lib = PolicyLibrary()
    rows = lib.list_templates()
    assert isinstance(rows, list)
    assert len(rows) >= 5


def test_template_retrieved() -> None:
    lib = PolicyLibrary()
    row = lib.get_template("minimal_dev")
    assert row is not None
    assert row["name"] == "Minimal Dev"


def test_policy_extracted() -> None:
    lib = PolicyLibrary()
    policy = lib.get_policy("cost_optimized")
    assert isinstance(policy, dict)
    assert policy["semantic_cache"]["enabled"] is True


def test_search_by_keyword() -> None:
    lib = PolicyLibrary()
    rows = lib.search("enterprise")
    assert any(item["id"] == "eu_ai_act_compliant" for item in rows)


def test_eu_ai_act_template_present() -> None:
    assert "eu_ai_act_compliant" in LIBRARY


def test_cost_optimized_template_present() -> None:
    assert "cost_optimized" in LIBRARY


def test_openclaw_template_present() -> None:
    assert "openclaw_secure" in LIBRARY


def test_count_correct() -> None:
    lib = PolicyLibrary()
    assert lib.count() == len(LIBRARY)

