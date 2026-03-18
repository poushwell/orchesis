from __future__ import annotations

from pathlib import Path

import yaml
from tests.cli_test_utils import CliRunner

from orchesis.cli import main
from orchesis.policy_templates import POLICY_TEMPLATES, PolicyTemplateManager


def test_all_templates_have_required_fields() -> None:
    required = {"description", "use_case", "config"}
    for name, item in POLICY_TEMPLATES.items():
        assert name
        assert required.issubset(set(item.keys()))
        assert isinstance(item["config"], dict)


def test_apply_template_creates_file(tmp_path: Path) -> None:
    out = tmp_path / "orchesis.yaml"
    manager = PolicyTemplateManager()
    manager.apply_template("strict_security", str(out))
    assert out.exists()
    loaded = yaml.safe_load(out.read_text(encoding="utf-8"))
    assert loaded["threat_intel"]["enabled"] is True


def test_merge_template_preserves_existing() -> None:
    manager = PolicyTemplateManager()
    existing = {
        "budgets": {"daily": 55.0},
        "custom_rule": {"enabled": True},
        "loop_detection": {"enabled": False},
    }
    merged = manager.merge_template("cost_optimizer", existing)
    assert merged["custom_rule"]["enabled"] is True
    assert merged["budgets"]["daily"] == 55.0
    assert merged["loop_detection"]["enabled"] is False
    assert merged["semantic_cache"]["enabled"] is True


def test_list_templates_returns_all() -> None:
    manager = PolicyTemplateManager()
    rows = manager.list_templates()
    assert len(rows) == len(POLICY_TEMPLATES)
    names = {row["name"] for row in rows}
    assert names == set(POLICY_TEMPLATES.keys())


def test_cli_template_list() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["template", "--list"])
    assert result.exit_code == 0
    for name in POLICY_TEMPLATES:
        assert name in result.output


def test_cli_template_use() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            main,
            ["template", "--use", "strict_security", "--output", "orchesis.yaml"],
        )
        assert result.exit_code == 0
        assert Path("orchesis.yaml").exists()
        payload = yaml.safe_load(Path("orchesis.yaml").read_text(encoding="utf-8"))
        assert payload["threat_intel"]["enabled"] is True
