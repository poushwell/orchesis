from __future__ import annotations

from pathlib import Path

import yaml
from click.testing import CliRunner

from orchesis.cli import main
from orchesis.quickstart import QuickstartWizard


def test_wizard_generates_valid_yaml(tmp_path: Path) -> None:
    out = tmp_path / "orchesis.yaml"
    wizard = QuickstartWizard()
    path = wizard.run(non_interactive=True, preset="generic", output_path=out)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    assert "proxy" in data


def test_preset_openclaw(tmp_path: Path) -> None:
    out = tmp_path / "o.yaml"
    path = QuickstartWizard().run(non_interactive=True, preset="openclaw", output_path=out)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert data["upstream"]["url"] == "https://api.anthropic.com"
    assert data["context_optimizer"]["enabled"] is True


def test_preset_openai(tmp_path: Path) -> None:
    out = tmp_path / "o.yaml"
    path = QuickstartWizard().run(non_interactive=True, preset="openai", output_path=out)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert data["upstream"]["url"] == "https://api.openai.com"
    assert data["semantic_cache"]["enabled"] is True


def test_preset_generic(tmp_path: Path) -> None:
    out = tmp_path / "g.yaml"
    path = QuickstartWizard().run(non_interactive=True, preset="generic", output_path=out)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert data["threat_intel"]["enabled"] is True


def test_preset_minimal(tmp_path: Path) -> None:
    out = tmp_path / "m.yaml"
    path = QuickstartWizard().run(non_interactive=True, preset="minimal", output_path=out)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert "budgets" not in data
    assert data["dashboard"]["enabled"] is True


def test_non_interactive_mode(tmp_path: Path) -> None:
    out = tmp_path / "out.yaml"
    path = QuickstartWizard().run(non_interactive=True, preset="generic", output_path=out)
    assert path.exists()


def test_custom_budget(tmp_path: Path) -> None:
    out = tmp_path / "b.yaml"
    path = QuickstartWizard().run(non_interactive=True, preset="generic", budget=42.5, output_path=out)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert float(data["budgets"]["daily"]) == 42.5


def test_detect_claude_directory(monkeypatch, tmp_path: Path) -> None:
    fake_home = tmp_path / "home"
    (fake_home / ".claude").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(Path, "home", lambda: fake_home)
    env = QuickstartWizard()._detect_environment()
    assert env["has_claude_dir"] is True


def test_detect_openai_key(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    env = QuickstartWizard()._detect_environment()
    assert env["has_openai_key"] is True


def test_output_path_custom(tmp_path: Path) -> None:
    out = tmp_path / "custom" / "x.yaml"
    path = QuickstartWizard().run(non_interactive=True, preset="generic", output_path=out)
    assert path == out.resolve()
    assert out.exists()


def test_config_has_required_sections(tmp_path: Path) -> None:
    out = tmp_path / "req.yaml"
    data = yaml.safe_load(
        QuickstartWizard().run(non_interactive=True, preset="generic", output_path=out).read_text(encoding="utf-8")
    )
    for key in ("rules", "proxy", "upstream", "dashboard"):
        assert key in data


def test_next_steps_printed(tmp_path: Path, capsys) -> None:
    out = tmp_path / "steps.yaml"
    QuickstartWizard().run(non_interactive=True, preset="generic", output_path=out)
    captured = capsys.readouterr()
    assert "Next steps:" in captured.out
    assert "orchesis proxy --config" in captured.out


def test_cli_quickstart_creates_file(tmp_path: Path) -> None:
    out = tmp_path / "cli.yaml"
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["quickstart", "--preset", "openclaw", "--non-interactive", "--output", str(out)],
    )
    assert result.exit_code == 0
    assert out.exists()


def test_cli_quickstart_budget(tmp_path: Path) -> None:
    out = tmp_path / "cli-budget.yaml"
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["quickstart", "--preset", "generic", "--non-interactive", "--budget", "25", "--output", str(out)],
    )
    assert result.exit_code == 0
    data = yaml.safe_load(out.read_text(encoding="utf-8"))
    assert float(data["budgets"]["daily"]) == 25.0


def test_interactive_defaults(monkeypatch, tmp_path: Path) -> None:
    responses = iter(["", "", ""])
    monkeypatch.setattr("builtins.input", lambda *_args, **_kwargs: next(responses))
    out = tmp_path / "interactive.yaml"
    path = QuickstartWizard().run(non_interactive=False, preset="generic", output_path=out)
    assert path.exists()

