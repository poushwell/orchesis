from __future__ import annotations

from pathlib import Path
import zipfile

from orchesis.backup_manager import BackupManager
from orchesis.cli import main
from tests.cli_test_utils import CliRunner


def _seed_workspace(root: Path) -> None:
    (root / ".orchesis").mkdir(parents=True, exist_ok=True)
    (root / ".orchesis" / "tenants").mkdir(parents=True, exist_ok=True)
    (root / ".orchesis" / "dna").mkdir(parents=True, exist_ok=True)
    (root / ".orchesis" / "decisions.jsonl").write_text('{"decision":"ALLOW"}\n', encoding="utf-8")
    (root / ".orchesis" / "signatures.json").write_text('{"items":[]}\n', encoding="utf-8")
    (root / ".orchesis" / "tenants" / "tenant-a.json").write_text('{"tenant_id":"tenant-a"}\n', encoding="utf-8")
    (root / ".orchesis" / "dna" / "agent-a.json").write_text('{"agent_id":"agent-a"}\n', encoding="utf-8")
    (root / "orchesis.yaml").write_text("rules: []\n", encoding="utf-8")


def test_create_backup_creates_zip(tmp_path: Path) -> None:
    _seed_workspace(tmp_path)
    manager = BackupManager(str(tmp_path))
    backup_path = Path(manager.create())
    assert backup_path.exists()
    assert backup_path.suffix == ".zip"


def test_backup_includes_key_files(tmp_path: Path) -> None:
    _seed_workspace(tmp_path)
    manager = BackupManager(str(tmp_path))
    backup_path = Path(manager.create())
    with zipfile.ZipFile(backup_path, "r") as zf:
        names = set(zf.namelist())
    assert ".orchesis/decisions.jsonl" in names
    assert ".orchesis/signatures.json" in names
    assert ".orchesis/tenants/tenant-a.json" in names
    assert ".orchesis/dna/agent-a.json" in names
    assert "orchesis.yaml" in names


def test_restore_from_backup(tmp_path: Path) -> None:
    _seed_workspace(tmp_path)
    manager = BackupManager(str(tmp_path))
    backup_path = Path(manager.create())
    (tmp_path / "orchesis.yaml").write_text("rules:\n  - name: changed\n", encoding="utf-8")
    (tmp_path / ".orchesis" / "decisions.jsonl").write_text("corrupted\n", encoding="utf-8")
    result = manager.restore(str(backup_path), dry_run=False)
    assert not result["errors"]
    assert "rules: []" in (tmp_path / "orchesis.yaml").read_text(encoding="utf-8")
    assert '{"decision":"ALLOW"}' in (tmp_path / ".orchesis" / "decisions.jsonl").read_text(encoding="utf-8")


def test_dry_run_no_changes(tmp_path: Path) -> None:
    _seed_workspace(tmp_path)
    manager = BackupManager(str(tmp_path))
    backup_path = Path(manager.create())
    original = "rules:\n  - name: changed\n"
    (tmp_path / "orchesis.yaml").write_text(original, encoding="utf-8")
    result = manager.restore(str(backup_path), dry_run=True)
    assert not result["errors"]
    assert result["restored"] == []
    assert (tmp_path / "orchesis.yaml").read_text(encoding="utf-8") == original


def test_verify_valid_backup(tmp_path: Path) -> None:
    _seed_workspace(tmp_path)
    manager = BackupManager(str(tmp_path))
    backup_path = Path(manager.create())
    report = manager.verify(str(backup_path))
    assert report["valid"] is True
    assert int(report["files"]) >= 5
    assert int(report["size_bytes"]) > 0
    assert isinstance(report["created_at"], str) and report["created_at"]


def test_list_backups(tmp_path: Path) -> None:
    _seed_workspace(tmp_path)
    manager = BackupManager(str(tmp_path))
    path_a = manager.create(str(tmp_path / ".orchesis" / "backups" / "a.zip"))
    path_b = manager.create(str(tmp_path / ".orchesis" / "backups" / "b.zip"))
    rows = manager.list_backups()
    paths = {item["path"] for item in rows}
    assert path_a in paths
    assert path_b in paths
    assert all("files_count" in item for item in rows)


def test_cli_backup_command() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        root = Path(".")
        _seed_workspace(root)
        result = runner.invoke(main, ["backup"])
        assert result.exit_code == 0
        assert "Backup created:" in result.output
