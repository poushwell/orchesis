"""Integrity monitoring with cryptographic baselines."""

from __future__ import annotations

import hashlib
import json
import stat
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from orchesis.integrations import SlackNotifier, TelegramNotifier

_ALLOWED_SUFFIXES = {".json", ".yaml", ".yml", ".toml", ".md", ".env"}


@dataclass(frozen=True)
class FileChange:
    path: str
    change_type: str
    old_value: str
    new_value: str


@dataclass(frozen=True)
class BaselineReport:
    files_count: int
    baseline_path: str


@dataclass(frozen=True)
class IntegrityReport:
    modified: list[FileChange]
    added: list[str]
    removed: list[str]
    permission_changed: list[FileChange]
    unchanged: int

    @property
    def has_changes(self) -> bool:
        return bool(self.modified or self.added or self.removed or self.permission_changed)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _permissions_octal(path: Path) -> str:
    mode = stat.S_IMODE(path.stat().st_mode)
    return f"{mode:04o}"


def _file_type(path: Path) -> str:
    name = path.name.lower()
    if name in {"policy.yaml", "policy.yml"}:
        return "policy"
    return "config"


class IntegrityMonitor:
    def __init__(self, baseline_path: str = ".orchesis/integrity.json"):
        self._baseline_path = Path(baseline_path)

    @property
    def baseline_path(self) -> Path:
        return self._baseline_path

    def auto_discover(self) -> list[str]:
        home = Path.home()
        candidates = [
            home / ".openclaw",
            home / ".cursor" / "mcp.json",
            home / ".config" / "claude" / "claude_desktop_config.json",
            home / ".moltbot",
            home / ".clawdbot",
            Path("policy.yaml"),
            Path(".orchesis"),
        ]
        found: list[str] = []
        for item in candidates:
            expanded = item.expanduser()
            if expanded.exists():
                found.append(str(expanded))
        return found

    def _iter_files_from_path(self, path: Path) -> list[Path]:
        if not path.exists():
            return []
        if path.is_file():
            if path.name.startswith(".") and path.suffix == "":
                return [path]
            if path.suffix.lower() in _ALLOWED_SUFFIXES or path.name.lower() in {"policy.yaml", "policy.yml"}:
                return [path]
            return []
        output: list[Path] = []
        for item in path.rglob("*"):
            if not item.is_file():
                continue
            if any(part in {".git", "__pycache__", ".pytest_cache"} for part in item.parts):
                continue
            if item.suffix.lower() in _ALLOWED_SUFFIXES or item.name.lower() in {"policy.yaml", "policy.yml"}:
                output.append(item)
        return sorted(output)

    def _record_for_file(self, file_path: Path) -> dict[str, Any]:
        stat_info = file_path.stat()
        return {
            "sha256": _sha256_file(file_path),
            "size": int(stat_info.st_size),
            "permissions": _permissions_octal(file_path),
            "last_modified": datetime.fromtimestamp(stat_info.st_mtime, tz=timezone.utc).isoformat().replace("+00:00", "Z"),
            "file_type": _file_type(file_path),
        }

    def _save_baseline(self, payload: dict[str, Any]) -> None:
        self._baseline_path.parent.mkdir(parents=True, exist_ok=True)
        self._baseline_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    def _load_baseline(self) -> dict[str, Any]:
        if not self._baseline_path.exists():
            return {"version": "1.0", "files": {}, "monitored_paths": []}
        try:
            payload = json.loads(self._baseline_path.read_text(encoding="utf-8"))
        except Exception:
            return {"version": "1.0", "files": {}, "monitored_paths": []}
        if not isinstance(payload, dict):
            return {"version": "1.0", "files": {}, "monitored_paths": []}
        if not isinstance(payload.get("files"), dict):
            payload["files"] = {}
        if not isinstance(payload.get("monitored_paths"), list):
            payload["monitored_paths"] = []
        return payload

    def init(self, paths: list[str]) -> BaselineReport:
        expanded_paths = [Path(item).expanduser() for item in paths if isinstance(item, str) and item.strip()]
        files: dict[str, dict[str, Any]] = {}
        for root in expanded_paths:
            for file_path in self._iter_files_from_path(root):
                files[str(file_path.resolve())] = self._record_for_file(file_path)
        timestamp = _now_iso()
        payload = {
            "version": "1.0",
            "created_at": timestamp,
            "updated_at": timestamp,
            "monitored_paths": [str(item.resolve()) for item in expanded_paths if item.exists()],
            "files": files,
        }
        self._save_baseline(payload)
        return BaselineReport(files_count=len(files), baseline_path=str(self._baseline_path))

    def check(self) -> IntegrityReport:
        baseline = self._load_baseline()
        files = baseline.get("files", {})
        baseline_files = files if isinstance(files, dict) else {}
        modified: list[FileChange] = []
        removed: list[str] = []
        permission_changed: list[FileChange] = []
        unchanged = 0

        for path_str, old in baseline_files.items():
            if not isinstance(path_str, str) or not isinstance(old, dict):
                continue
            path = Path(path_str)
            if not path.exists():
                removed.append(path_str)
                continue
            new_record = self._record_for_file(path)
            old_sha = str(old.get("sha256", ""))
            old_perm = str(old.get("permissions", ""))
            if new_record["sha256"] != old_sha:
                modified.append(FileChange(path=path_str, change_type="hash", old_value=old_sha, new_value=str(new_record["sha256"])))
                continue
            if new_record["permissions"] != old_perm:
                permission_changed.append(
                    FileChange(path=path_str, change_type="permissions", old_value=old_perm, new_value=str(new_record["permissions"]))
                )
                continue
            unchanged += 1

        added: list[str] = []
        monitored_paths = baseline.get("monitored_paths", [])
        if isinstance(monitored_paths, list):
            known = {item for item in baseline_files.keys() if isinstance(item, str)}
            for root_raw in monitored_paths:
                if not isinstance(root_raw, str):
                    continue
                root = Path(root_raw)
                for file_path in self._iter_files_from_path(root):
                    resolved = str(file_path.resolve())
                    if resolved not in known:
                        added.append(resolved)

        return IntegrityReport(
            modified=sorted(modified, key=lambda item: item.path),
            added=sorted(dict.fromkeys(added)),
            removed=sorted(dict.fromkeys(removed)),
            permission_changed=sorted(permission_changed, key=lambda item: item.path),
            unchanged=unchanged,
        )

    def update(self, paths: list[str] | None = None) -> BaselineReport:
        baseline = self._load_baseline()
        files = baseline.get("files")
        baseline_files: dict[str, dict[str, Any]] = files if isinstance(files, dict) else {}

        if paths is None:
            monitored = baseline.get("monitored_paths", [])
            monitored_paths = [item for item in monitored if isinstance(item, str)]
            return self.init(monitored_paths)

        for entry in paths:
            target = Path(entry).expanduser()
            if target.exists() and target.is_file():
                baseline_files[str(target.resolve())] = self._record_for_file(target)
            elif target.exists() and target.is_dir():
                for file_path in self._iter_files_from_path(target):
                    baseline_files[str(file_path.resolve())] = self._record_for_file(file_path)

        baseline["files"] = baseline_files
        baseline["updated_at"] = _now_iso()
        self._save_baseline(baseline)
        return BaselineReport(files_count=len(baseline_files), baseline_path=str(self._baseline_path))

    def watch(
        self,
        interval: int,
        callback: Callable[[IntegrityReport], None],
        *,
        max_iterations: int | None = None,
    ) -> None:
        checks = 0
        try:
            while True:
                report = self.check()
                if report.has_changes:
                    callback(report)
                checks += 1
                if isinstance(max_iterations, int) and checks >= max_iterations:
                    break
                time.sleep(max(1, int(interval)))
        except KeyboardInterrupt:
            return


def build_integrity_alert_callback(policy: dict[str, Any]) -> Callable[[IntegrityReport], None]:
    alerts = policy.get("alerts") if isinstance(policy.get("alerts"), dict) else {}
    notifiers: list[Any] = []
    slack_cfg = alerts.get("slack")
    if isinstance(slack_cfg, dict):
        webhook = slack_cfg.get("webhook_url")
        if isinstance(webhook, str) and webhook.strip():
            notifiers.append(SlackNotifier(webhook_url=webhook.strip()))
    telegram_cfg = alerts.get("telegram")
    if isinstance(telegram_cfg, dict):
        token = telegram_cfg.get("bot_token")
        chat_id = telegram_cfg.get("chat_id")
        if isinstance(token, str) and token.strip() and isinstance(chat_id, str) and chat_id.strip():
            notifiers.append(TelegramNotifier(bot_token=token.strip(), chat_id=chat_id.strip()))

    def _callback(report: IntegrityReport) -> None:
        messages: list[str] = []
        for item in report.modified:
            severity = "HIGH" if item.path.lower().endswith(("policy.yaml", "policy.yml")) else "MEDIUM"
            messages.append(f"[{severity}] Integrity violation: {item.path} modified (hash changed)")
        for item in report.permission_changed:
            old_perm = int(item.old_value, 8) if item.old_value.isdigit() else 0o600
            new_perm = int(item.new_value, 8) if item.new_value.isdigit() else 0o600
            severity = "HIGH" if (new_perm & 0o077) > (old_perm & 0o077) else "MEDIUM"
            messages.append(f"[{severity}] Integrity violation: {item.path} permissions changed {item.old_value}->{item.new_value}")
        for item in report.removed:
            messages.append(f"[MEDIUM] Integrity violation: {item} removed")
        for item in report.added:
            messages.append(f"[LOW] Integrity event: new monitored file {item}")
        for notifier in notifiers:
            for message in messages:
                try:
                    notifier.send(message)
                except Exception:
                    continue

    return _callback
