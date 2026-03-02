from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from click.testing import CliRunner

from orchesis.cli import main
from orchesis.integrity import IntegrityMonitor, build_integrity_alert_callback
from orchesis.integrations import SlackNotifier


def test_init_creates_baseline_file_structure(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\n", encoding="utf-8")
    monitor = IntegrityMonitor(baseline_path=str(tmp_path / ".orchesis/integrity.json"))
    report = monitor.init([str(policy)])
    assert report.files_count == 1
    payload = json.loads((tmp_path / ".orchesis/integrity.json").read_text(encoding="utf-8"))
    assert payload["version"] == "1.0"
    assert isinstance(payload["files"], dict)


def test_init_directory_recursively_finds_configs(tmp_path: Path) -> None:
    cfg_dir = tmp_path / "cfg"
    cfg_dir.mkdir()
    (cfg_dir / "a.json").write_text("{}", encoding="utf-8")
    (cfg_dir / "b.yaml").write_text("x: 1\n", encoding="utf-8")
    monitor = IntegrityMonitor(baseline_path=str(tmp_path / ".orchesis/integrity.json"))
    report = monitor.init([str(cfg_dir)])
    assert report.files_count == 2


def test_init_ignores_non_config_files(tmp_path: Path) -> None:
    cfg_dir = tmp_path / "cfg"
    cfg_dir.mkdir()
    (cfg_dir / "cache.pyc").write_bytes(b"x")
    monitor = IntegrityMonitor(baseline_path=str(tmp_path / ".orchesis/integrity.json"))
    report = monitor.init([str(cfg_dir)])
    assert report.files_count == 0


def test_auto_discover_finds_existing_paths(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    (home / ".cursor").mkdir(parents=True)
    (home / ".cursor/mcp.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr("pathlib.Path.home", lambda: home)
    monitor = IntegrityMonitor(baseline_path=str(tmp_path / ".orchesis/integrity.json"))
    found = monitor.auto_discover()
    assert any(item.endswith("mcp.json") for item in found)


def test_check_detects_modified_file(tmp_path: Path) -> None:
    file_path = tmp_path / "policy.yaml"
    file_path.write_text("rules: []\n", encoding="utf-8")
    monitor = IntegrityMonitor(baseline_path=str(tmp_path / ".orchesis/integrity.json"))
    _ = monitor.init([str(file_path)])
    file_path.write_text("rules:\n  - name: budget_limit\n", encoding="utf-8")
    report = monitor.check()
    assert len(report.modified) == 1


def test_check_detects_removed_file(tmp_path: Path) -> None:
    file_path = tmp_path / "policy.yaml"
    file_path.write_text("rules: []\n", encoding="utf-8")
    monitor = IntegrityMonitor(baseline_path=str(tmp_path / ".orchesis/integrity.json"))
    _ = monitor.init([str(file_path)])
    file_path.unlink()
    report = monitor.check()
    assert len(report.removed) == 1


def test_check_detects_added_file_in_monitored_dir(tmp_path: Path) -> None:
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    monitor = IntegrityMonitor(baseline_path=str(tmp_path / ".orchesis/integrity.json"))
    _ = monitor.init([str(cfg)])
    (cfg / "new.json").write_text("{}", encoding="utf-8")
    report = monitor.check()
    assert len(report.added) == 1


def test_check_detects_permission_change(tmp_path: Path) -> None:
    file_path = tmp_path / "policy.yaml"
    file_path.write_text("rules: []\n", encoding="utf-8")
    monitor = IntegrityMonitor(baseline_path=str(tmp_path / ".orchesis/integrity.json"))
    _ = monitor.init([str(file_path)])
    if os.name == "posix":
        os.chmod(file_path, 0o600)
    else:
        # emulate by mutating baseline for windows-friendly test
        payload = json.loads((tmp_path / ".orchesis/integrity.json").read_text(encoding="utf-8"))
        key = str(file_path.resolve())
        payload["files"][key]["permissions"] = "0000"
        (tmp_path / ".orchesis/integrity.json").write_text(json.dumps(payload), encoding="utf-8")
    report = monitor.check()
    assert len(report.permission_changed) == 1


def test_check_clean_report_when_unchanged(tmp_path: Path) -> None:
    file_path = tmp_path / "policy.yaml"
    file_path.write_text("rules: []\n", encoding="utf-8")
    monitor = IntegrityMonitor(baseline_path=str(tmp_path / ".orchesis/integrity.json"))
    _ = monitor.init([str(file_path)])
    report = monitor.check()
    assert report.has_changes is False
    assert report.unchanged >= 1


def test_update_single_file_refreshes_baseline(tmp_path: Path) -> None:
    file_path = tmp_path / "policy.yaml"
    file_path.write_text("rules: []\n", encoding="utf-8")
    monitor = IntegrityMonitor(baseline_path=str(tmp_path / ".orchesis/integrity.json"))
    _ = monitor.init([str(file_path)])
    file_path.write_text("rules:\n  - name: x\n", encoding="utf-8")
    _ = monitor.update([str(file_path)])
    report = monitor.check()
    assert report.has_changes is False


def test_update_all_files_refreshes_baseline(tmp_path: Path) -> None:
    file_path = tmp_path / "policy.yaml"
    file_path.write_text("rules: []\n", encoding="utf-8")
    monitor = IntegrityMonitor(baseline_path=str(tmp_path / ".orchesis/integrity.json"))
    _ = monitor.init([str(file_path)])
    file_path.write_text("rules:\n  - name: x\n", encoding="utf-8")
    _ = monitor.update()
    report = monitor.check()
    assert report.has_changes is False


def test_cli_check_strict_exit_code(tmp_path: Path) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("policy.yaml").write_text("rules: []\n", encoding="utf-8")
        _ = runner.invoke(main, ["integrity", "init", "--paths", "policy.yaml"])
        Path("policy.yaml").write_text("rules:\n  - name: x\n", encoding="utf-8")
        result = runner.invoke(main, ["integrity", "check", "--strict"])
        assert result.exit_code == 1


def test_baseline_file_is_valid_json(tmp_path: Path) -> None:
    file_path = tmp_path / "policy.yaml"
    file_path.write_text("rules: []\n", encoding="utf-8")
    monitor = IntegrityMonitor(baseline_path=str(tmp_path / ".orchesis/integrity.json"))
    _ = monitor.init([str(file_path)])
    loaded = json.loads((tmp_path / ".orchesis/integrity.json").read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)


def test_sha256_computation_known_value(tmp_path: Path) -> None:
    file_path = tmp_path / "policy.yaml"
    content = "abc"
    file_path.write_text(content, encoding="utf-8")
    monitor = IntegrityMonitor(baseline_path=str(tmp_path / ".orchesis/integrity.json"))
    _ = monitor.init([str(file_path)])
    payload = json.loads((tmp_path / ".orchesis/integrity.json").read_text(encoding="utf-8"))
    expected = hashlib.sha256(content.encode("utf-8")).hexdigest()
    actual = payload["files"][str(file_path.resolve())]["sha256"]
    assert actual == expected


def test_watch_calls_callback_on_change(tmp_path: Path) -> None:
    file_path = tmp_path / "policy.yaml"
    file_path.write_text("rules: []\n", encoding="utf-8")
    monitor = IntegrityMonitor(baseline_path=str(tmp_path / ".orchesis/integrity.json"))
    _ = monitor.init([str(file_path)])
    file_path.write_text("rules:\n  - name: x\n", encoding="utf-8")
    seen = []
    monitor.watch(1, lambda report: seen.append(report), max_iterations=1)
    assert len(seen) == 1


def test_watch_no_callback_when_clean(tmp_path: Path) -> None:
    file_path = tmp_path / "policy.yaml"
    file_path.write_text("rules: []\n", encoding="utf-8")
    monitor = IntegrityMonitor(baseline_path=str(tmp_path / ".orchesis/integrity.json"))
    _ = monitor.init([str(file_path)])
    seen = []
    monitor.watch(1, lambda report: seen.append(report), max_iterations=1)
    assert seen == []


def test_alert_callback_sends_messages(monkeypatch) -> None:
    sent: list[str] = []
    monkeypatch.setattr(SlackNotifier, "send", lambda self, message: sent.append(message))
    policy = {"alerts": {"slack": {"webhook_url": "https://hooks.slack.com/services/T/B/X"}}}
    callback = build_integrity_alert_callback(policy)
    from orchesis.integrity import FileChange, IntegrityReport

    report = IntegrityReport(
        modified=[FileChange(path="policy.yaml", change_type="hash", old_value="a", new_value="b")],
        added=[],
        removed=[],
        permission_changed=[],
        unchanged=0,
    )
    callback(report)
    assert sent


def test_cli_integrity_status_and_update(tmp_path: Path) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("policy.yaml").write_text("rules: []\n", encoding="utf-8")
        _ = runner.invoke(main, ["integrity", "init", "--paths", "policy.yaml"])
        status = runner.invoke(main, ["integrity", "status"])
        assert status.exit_code == 0
        assert "Files tracked" in status.output
        update = runner.invoke(main, ["integrity", "update", "--path", "policy.yaml"])
        assert update.exit_code == 0
