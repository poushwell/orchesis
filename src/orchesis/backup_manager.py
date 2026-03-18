"""Backup and restore helpers for Orchesis data."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import zipfile


class BackupManager:
    """Backup and restore all Orchesis data."""

    BACKUP_INCLUDES = [
        ".orchesis/decisions.jsonl",
        ".orchesis/signatures.json",
        ".orchesis/tenants/",
        ".orchesis/dna/",
        "orchesis.yaml",
    ]

    def __init__(self, base_dir: str = "."):
        self.base_dir = Path(base_dir).expanduser().resolve()

    def _resolve(self, path: str) -> Path:
        candidate = Path(path).expanduser()
        if candidate.is_absolute():
            return candidate
        return (self.base_dir / candidate).resolve()

    @staticmethod
    def _iso_from_ts(ts: float) -> str:
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

    def _iter_sources(self) -> list[Path]:
        rows: list[Path] = []
        for item in self.BACKUP_INCLUDES:
            source = self._resolve(item)
            if source.is_dir():
                rows.extend([p for p in source.rglob("*") if p.is_file()])
            elif source.is_file():
                rows.append(source)
        # Stable dedup/order by string path.
        uniq: dict[str, Path] = {str(p): p for p in rows}
        return [uniq[key] for key in sorted(uniq.keys())]

    def create(self, output_path: str | None = None) -> str:
        """Create backup ZIP. Returns backup path."""
        if isinstance(output_path, str) and output_path.strip():
            target = self._resolve(output_path.strip())
        else:
            stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            target = self._resolve(f".orchesis/backups/orchesis_{stamp}.zip")
        target.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(target, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            for source in self._iter_sources():
                arcname = source.relative_to(self.base_dir).as_posix()
                zf.write(source, arcname=arcname)
        return str(target)

    def restore(self, backup_path: str, dry_run: bool = False) -> dict:
        """Restore from backup. Returns {restored, skipped, errors}."""
        source = self._resolve(backup_path)
        restored: list[str] = []
        skipped: list[str] = []
        errors: list[str] = []
        if not source.exists():
            return {"restored": restored, "skipped": skipped, "errors": [f"backup not found: {backup_path}"]}

        try:
            with zipfile.ZipFile(source, mode="r") as zf:
                for info in zf.infolist():
                    name = str(info.filename)
                    if info.is_dir():
                        skipped.append(name)
                        continue
                    target = (self.base_dir / name).resolve()
                    try:
                        target.relative_to(self.base_dir)
                    except ValueError:
                        skipped.append(name)
                        continue
                    if dry_run:
                        skipped.append(name)
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    payload = zf.read(info.filename)
                    target.write_bytes(payload)
                    restored.append(name)
        except Exception as exc:  # noqa: BLE001
            errors.append(str(exc))
        return {"restored": restored, "skipped": skipped, "errors": errors}

    def list_backups(self, backup_dir: str = ".orchesis/backups") -> list[dict]:
        """List backups with metadata: path, size, created_at, files_count."""
        root = self._resolve(backup_dir)
        if not root.exists() or not root.is_dir():
            return []
        rows: list[dict] = []
        for path in sorted(root.glob("*.zip"), key=lambda p: p.stat().st_mtime, reverse=True):
            files_count = 0
            try:
                with zipfile.ZipFile(path, mode="r") as zf:
                    files_count = sum(1 for item in zf.infolist() if not item.is_dir())
            except Exception:
                files_count = 0
            st = path.stat()
            rows.append(
                {
                    "path": str(path),
                    "size": int(st.st_size),
                    "created_at": self._iso_from_ts(float(st.st_mtime)),
                    "files_count": files_count,
                }
            )
        return rows

    def verify(self, backup_path: str) -> dict:
        """Verify integrity: {valid, files, size_bytes, created_at}."""
        source = self._resolve(backup_path)
        if not source.exists():
            return {"valid": False, "files": 0, "size_bytes": 0, "created_at": "", "error": "backup not found"}
        st = source.stat()
        try:
            with zipfile.ZipFile(source, mode="r") as zf:
                bad = zf.testzip()
                files = sum(1 for item in zf.infolist() if not item.is_dir())
            return {
                "valid": bad is None,
                "files": files,
                "size_bytes": int(st.st_size),
                "created_at": self._iso_from_ts(float(st.st_mtime)),
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "valid": False,
                "files": 0,
                "size_bytes": int(st.st_size),
                "created_at": self._iso_from_ts(float(st.st_mtime)),
                "error": str(exc),
            }
