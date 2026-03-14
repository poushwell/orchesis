from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from orchesis.cli import main
from orchesis.hooks import ClaudeCodeHooks, evaluate_hook_tool, ensure_default_hook_policy


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _policy_text() -> str:
    return """rules:
  - tool: shell
    pattern: "rm\\s+-rf"
    action: deny
    message: "Destructive command blocked"
  - tool: file_read
    pattern: "\\.env|id_rsa"
    action: warn
    message: "Accessing sensitive file"
  max_tool_calls_per_minute: 100
  log_file: ~/.orchesis/hooks.log
  log_format: jsonl
"""


def test_install_creates_hooks(tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    _write_json(settings, {})
    ClaudeCodeHooks.CLAUDE_SETTINGS_PATHS = [settings]
    result = ClaudeCodeHooks().install()
    data = json.loads(settings.read_text(encoding="utf-8"))
    assert result.success is True
    assert "PreToolUse" in data["hooks"]
    assert "PostToolUse" in data["hooks"]


def test_install_backs_up_settings(tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    _write_json(settings, {"hooks": {}})
    ClaudeCodeHooks.CLAUDE_SETTINGS_PATHS = [settings]
    ClaudeCodeHooks().install()
    backups = list(tmp_path.glob("settings.json.bak.*"))
    assert backups


def test_install_preserves_existing_hooks(tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    _write_json(
        settings,
        {"hooks": {"PreToolUse": [{"matcher": "x", "hook": "echo keep"}], "PostToolUse": []}},
    )
    ClaudeCodeHooks.CLAUDE_SETTINGS_PATHS = [settings]
    ClaudeCodeHooks().install()
    data = json.loads(settings.read_text(encoding="utf-8"))
    assert any(item["hook"] == "echo keep" for item in data["hooks"]["PreToolUse"])


def test_uninstall_removes_hooks(tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    _write_json(
        settings,
        {
            "hooks": {
                "PreToolUse": [{"matcher": ".*", "hook": "orchesis hook-check --tool $TOOL_NAME --input $TOOL_INPUT"}],
                "PostToolUse": [{"matcher": ".*", "hook": "orchesis hook-log --tool $TOOL_NAME --output $TOOL_OUTPUT"}],
            }
        },
    )
    ClaudeCodeHooks.CLAUDE_SETTINGS_PATHS = [settings]
    result = ClaudeCodeHooks().uninstall()
    data = json.loads(settings.read_text(encoding="utf-8"))
    assert result.success is True
    assert data["hooks"]["PreToolUse"] == []
    assert data["hooks"]["PostToolUse"] == []


def test_uninstall_preserves_other_hooks(tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    _write_json(
        settings,
        {
            "hooks": {
                "PreToolUse": [{"matcher": ".*", "hook": "echo keep"}],
                "PostToolUse": [{"matcher": ".*", "hook": "orchesis hook-log --tool $TOOL_NAME --output $TOOL_OUTPUT"}],
            }
        },
    )
    ClaudeCodeHooks.CLAUDE_SETTINGS_PATHS = [settings]
    ClaudeCodeHooks().uninstall()
    data = json.loads(settings.read_text(encoding="utf-8"))
    assert data["hooks"]["PreToolUse"] == [{"matcher": ".*", "hook": "echo keep"}]


def test_status_installed(tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    _write_json(settings, {})
    ClaudeCodeHooks.CLAUDE_SETTINGS_PATHS = [settings]
    ClaudeCodeHooks().install()
    status = ClaudeCodeHooks().status()
    assert status["installed"] is True
    assert status["hooks_registered"] == 2


def test_status_not_installed(tmp_path: Path) -> None:
    settings = tmp_path / "missing.json"
    ClaudeCodeHooks.CLAUDE_SETTINGS_PATHS = [settings]
    status = ClaudeCodeHooks().status()
    assert status["installed"] is False


def test_settings_not_found(tmp_path: Path) -> None:
    ClaudeCodeHooks.CLAUDE_SETTINGS_PATHS = [tmp_path / "none1.json", tmp_path / "none2.json"]
    result = ClaudeCodeHooks().uninstall()
    assert result.success is True


def test_hook_check_allow(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(_policy_text(), encoding="utf-8")
    code, output = evaluate_hook_tool("shell", "echo hello", str(policy))
    assert code == 0
    assert output == "ALLOW"


def test_hook_check_deny_rm_rf(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(_policy_text(), encoding="utf-8")
    code, output = evaluate_hook_tool("shell", "rm -rf /tmp/x", str(policy))
    assert code == 1
    assert "BLOCKED" in output


def test_hook_check_warn_env(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(_policy_text(), encoding="utf-8")
    code, output = evaluate_hook_tool("file_read", ".env", str(policy))
    assert code == 0
    assert "WARN" in output


def test_hook_check_no_config_uses_default(tmp_path: Path, monkeypatch) -> None:
    default_policy = tmp_path / ".orchesis" / "policy.yaml"
    monkeypatch.setattr("orchesis.hooks.DEFAULT_POLICY_PATH", default_policy)
    ensure_default_hook_policy(default_policy)
    code, output = evaluate_hook_tool("shell", "echo ok", None)
    assert code == 0
    assert output == "ALLOW"


def test_hook_check_exit_codes(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(_policy_text(), encoding="utf-8")
    runner = CliRunner()
    ok = runner.invoke(main, ["hook-check", "--tool", "shell", "--input", "echo ok", "--config", str(policy)])
    deny = runner.invoke(main, ["hook-check", "--tool", "shell", "--input", "rm -rf /", "--config", str(policy)])
    assert ok.exit_code == 0
    assert deny.exit_code == 1


def test_cli_hooks_install_command(tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    _write_json(settings, {})
    ClaudeCodeHooks.CLAUDE_SETTINGS_PATHS = [settings]
    runner = CliRunner()
    result = runner.invoke(main, ["hooks", "install"])
    assert result.exit_code == 0


def test_cli_hooks_status_command(tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    _write_json(settings, {})
    ClaudeCodeHooks.CLAUDE_SETTINGS_PATHS = [settings]
    ClaudeCodeHooks().install()
    runner = CliRunner()
    result = runner.invoke(main, ["hooks", "status"])
    assert result.exit_code == 0
    assert "installed" in result.output


def test_cli_hooks_uninstall_command(tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    _write_json(settings, {})
    ClaudeCodeHooks.CLAUDE_SETTINGS_PATHS = [settings]
    ClaudeCodeHooks().install()
    runner = CliRunner()
    result = runner.invoke(main, ["hooks", "uninstall"])
    assert result.exit_code == 0


def test_hook_log_writes_file(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(_policy_text(), encoding="utf-8")
    log_file = tmp_path / ".orchesis" / "hooks.log"
    text = policy.read_text(encoding="utf-8").replace("~/.orchesis/hooks.log", str(log_file).replace("\\", "/"))
    policy.write_text(text, encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(main, ["hook-log", "--tool", "shell", "--output", "ok", "--config", str(policy)])
    assert result.exit_code == 0
    assert log_file.exists()


def test_hook_rate_limit_blocks(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(_policy_text().replace("max_tool_calls_per_minute: 100", "max_tool_calls_per_minute: 1"), encoding="utf-8")
    first = evaluate_hook_tool("shell", "echo 1", str(policy))
    second = evaluate_hook_tool("shell", "echo 2", str(policy))
    assert first[0] == 0
    assert second[0] == 1


def test_install_idempotent(tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    _write_json(settings, {})
    ClaudeCodeHooks.CLAUDE_SETTINGS_PATHS = [settings]
    first = ClaudeCodeHooks().install()
    second = ClaudeCodeHooks().install()
    assert first.success is True
    assert second.hooks_registered == 0


def test_uninstall_without_hooks_noop(tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    _write_json(settings, {"hooks": {}})
    ClaudeCodeHooks.CLAUDE_SETTINGS_PATHS = [settings]
    result = ClaudeCodeHooks().uninstall()
    assert result.success is True
    assert result.hooks_registered == 0

