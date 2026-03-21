from __future__ import annotations

from orchesis.presets.tool_sequences import (
    LANGCHAIN_STANDARD,
    PAPERCLIP_STANDARD,
    PAPERCLIP_STRICT,
    GENERIC_MINIMAL,
    PRESET_REGISTRY,
    get_frameworks,
    get_preset,
    list_presets,
)


def test_get_preset_exists() -> None:
    preset = get_preset("paperclip_standard")
    assert preset is not None
    assert preset.name == "paperclip_standard"


def test_get_preset_not_found() -> None:
    assert get_preset("nonexistent") is None


def test_list_presets() -> None:
    rows = list_presets()
    assert isinstance(rows, list)
    assert rows
    for row in rows:
        assert "name" in row
        assert "framework" in row
        assert "rule_count" in row


def test_get_frameworks() -> None:
    frameworks = get_frameworks()
    assert "paperclip" in frameworks
    assert "generic" in frameworks


def test_paperclip_standard_rules() -> None:
    assert len(PAPERCLIP_STANDARD.rules) == 7


def test_paperclip_strict_rules() -> None:
    assert len(PAPERCLIP_STRICT.rules) >= 10


def test_generic_minimal_rules() -> None:
    assert len(GENERIC_MINIMAL.rules) == 3


def test_langchain_standard_rules() -> None:
    assert len(LANGCHAIN_STANDARD.rules) == 3


def test_to_policy_rules() -> None:
    rules = PAPERCLIP_STANDARD.to_policy_rules()
    assert isinstance(rules, list)
    assert rules
    first = rules[0]
    assert "rule_id" in first
    assert first.get("type") == "tool_sequence"
    assert "sequence" in first


def test_get_deny_rules() -> None:
    deny = PAPERCLIP_STANDARD.get_deny_rules()
    assert len(deny) == 5


def test_get_warn_rules() -> None:
    warn = PAPERCLIP_STANDARD.get_warn_rules()
    assert len(warn) == 2


def test_rule_ids_unique() -> None:
    ids: list[str] = []
    for preset in PRESET_REGISTRY.values():
        for rule in preset.rules:
            ids.append(rule.rule_id)
    assert len(ids) == len(set(ids))


def test_all_rules_have_sequence() -> None:
    for preset in PRESET_REGISTRY.values():
        for rule in preset.rules:
            assert isinstance(rule.sequence, list)
            assert len(rule.sequence) > 0


def test_rule_to_policy_dict() -> None:
    row = PAPERCLIP_STANDARD.rules[0].to_policy_dict()
    for key in ("rule_id", "type", "action", "sequence"):
        assert key in row

