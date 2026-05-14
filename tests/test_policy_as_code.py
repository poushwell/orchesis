from __future__ import annotations

import json
from pathlib import Path

from orchesis.cli import main
from orchesis.policy_spec import PolicySpec
from tests.cli_test_utils import CliRunner


def _valid_policy() -> dict:
    return {
        "version": "0.2.0",
        "proxy": {"port": 8080},
        "recording": {"enabled": True},
        "semantic_cache": {"enabled": True},
        "loop_detection": {"enabled": True},
        "security": {"rate_limiting": True},
        "budgets": {"daily": 10.0},
    }


def test_valid_policy_passes_spec() -> None:
    spec = PolicySpec()
    result = spec.validate(_valid_policy())
    assert result["valid"] is True
    assert result["spec_version"] == "1.0.0"


def test_missing_required_field_fails() -> None:
    spec = PolicySpec()
    result = spec.validate({"recording": {"enabled": True}})
    assert result["valid"] is False
    assert any(item["path"] == "proxy" for item in result["violations"])


def test_eu_ai_act_mapping_correct() -> None:
    spec = PolicySpec()
    mapping = spec.export_eu_ai_act_alignment()
    assert mapping["framework"] == "EU AI Act"
    assert "recording.enabled" in mapping["articles"]


def test_owasp_mapping_correct() -> None:
    spec = PolicySpec()
    mapping = spec.export_owasp_alignment()
    assert mapping["framework"] == "OWASP Agentic Top 10"
    assert "loop_detection.enabled" in mapping["controls"]


def test_spec_doc_generated() -> None:
    spec = PolicySpec()
    doc = spec.generate_spec_doc()
    assert "# Orchesis Policy Spec v1.0.0" in doc
    assert "## OWASP Agentic Top 10 Mapping" in doc


def test_owasp_alignment_exported() -> None:
    spec = PolicySpec()
    payload = spec.export_owasp_alignment()
    assert payload["count"] >= 1


def test_cli_spec_validate(tmp_path: Path) -> None:
    policy = tmp_path / "orchesis.yaml"
    policy.write_text(
        """
proxy:
  port: 8080
recording:
  enabled: true
""".strip(),
        encoding="utf-8",
    )
    runner = CliRunner()
    result = runner.invoke(main, ["spec", "--validate", str(policy)])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["valid"] is True


def test_cli_spec_generate_doc(tmp_path: Path) -> None:
    output = tmp_path / "spec.md"
    runner = CliRunner()
    result = runner.invoke(main, ["spec", "--generate-doc", "--output", str(output)])
    assert result.exit_code == 0
    assert output.exists()
    content = output.read_text(encoding="utf-8")
    assert "Orchesis Policy Spec" in content
