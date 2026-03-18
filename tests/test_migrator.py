from __future__ import annotations

from pathlib import Path

from orchesis.cli import main
from orchesis.migrator import PolicyMigrator
from tests.cli_test_utils import CliRunner


def test_version_detection() -> None:
    migrator = PolicyMigrator()
    assert migrator.detect_version({"rules": []}) == "0.1.x"
    assert migrator.detect_version({"semantic_cache": {"enabled": True}}) == "0.2.x"
    assert migrator.detect_version({"context_budget": {"enabled": False}}) == "0.3.x"


def test_migrate_adds_missing_keys() -> None:
    migrator = PolicyMigrator()
    result = migrator.migrate({"rules": []}, "0.2.x")
    policy = result["policy"]
    assert "semantic_cache" in policy
    assert "recording" in policy
    assert "loop_detection" in policy
    assert result["changes"]


def test_dry_run_no_changes() -> None:
    migrator = PolicyMigrator()
    initial = {
        "rules": [],
        "semantic_cache": {"enabled": True, "similarity_threshold": 0.85},
        "recording": {"enabled": True},
        "loop_detection": {"enabled": True, "warn_threshold": 3, "block_threshold": 5},
    }
    result = migrator.dry_run(initial, "0.2.x")
    assert result["changes"] == []
    assert result["policy"] == initial


def test_backup_created(tmp_path: Path) -> None:
    migrator = PolicyMigrator()
    path = tmp_path / "orchesis.yaml"
    path.write_text("rules: []\n", encoding="utf-8")
    backup_path = Path(migrator.backup(str(path)))
    assert backup_path.exists()
    assert backup_path.read_text(encoding="utf-8") == "rules: []\n"
    assert backup_path.name.startswith("orchesis.yaml.bak.")


def test_cli_migrate_command(tmp_path: Path) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        cfg = Path("orchesis.yaml")
        cfg.write_text("rules: []\n", encoding="utf-8")
        result = runner.invoke(main, ["migrate", "--config", str(cfg), "--target", "0.2.x", "--no-backup"])
        assert result.exit_code == 0
        content = cfg.read_text(encoding="utf-8")
        assert "semantic_cache" in content
        assert "recording" in content
        assert "loop_detection" in content
        assert "Detected version: 0.1.x" in result.output
        assert "Target version:   0.2.x" in result.output
        assert "✓ Migration complete" in result.output


def test_migrate_idempotent() -> None:
    migrator = PolicyMigrator()
    start = {"rules": []}
    first = migrator.migrate(start, "0.2.x")["policy"]
    second = migrator.migrate(first, "0.2.x")
    assert second["policy"] == first
    assert second["changes"] == []
