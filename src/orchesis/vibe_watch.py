"""Polling file watcher for Vibe Code Audit."""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

DEFAULT_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx"}
DEFAULT_EXCLUDES = {
    "__pycache__",
    "node_modules",
    ".git",
    ".venv",
    "venv",
    "dist",
    "build",
    ".tox",
    ".mypy_cache",
}


@dataclass
class WatchEvent:
    event_type: str  # "created", "modified", "deleted"
    filepath: str
    timestamp: float


@dataclass
class WatchSummary:
    files_watched: int = 0
    changes_detected: int = 0
    issues_high: int = 0
    issues_medium: int = 0
    issues_low: int = 0
    duration_seconds: float = 0.0

    def format(self) -> str:
        total_seconds = max(0, int(self.duration_seconds))
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        seconds = total_seconds % 60
        return "\n".join(
            [
                f"Files watched: {self.files_watched}",
                f"Changes detected: {self.changes_detected}",
                f"Issues found: {self.issues_high} HIGH, {self.issues_medium} MEDIUM, {self.issues_low} LOW",
                f"Duration: {hours:02d}:{minutes:02d}:{seconds:02d}",
            ]
        )


@dataclass
class AuditResult:
    filepath: str
    issues: list
    timestamp: float


class VibeWatcher:
    def __init__(
        self,
        target_dir: str,
        interval: float = 2.0,
        extensions: set[str] | None = None,
        exclude_patterns: set[str] | None = None,
        output_jsonl: str | None = None,
        on_change_callback: Callable[[WatchEvent, AuditResult], None] | None = None,
    ):
        self.target_dir = Path(target_dir).resolve()
        self.interval = float(interval)
        self.extensions = {str(ext).lower() for ext in (extensions or DEFAULT_EXTENSIONS)}
        self.exclude_patterns = set(exclude_patterns or DEFAULT_EXCLUDES)
        self.output_jsonl = str(output_jsonl) if output_jsonl else None
        self.on_change_callback = on_change_callback

        self._stop_event = threading.Event()
        self._file_mtimes: dict[str, float] = {}
        self._results: list[AuditResult] = []
        self._events: list[WatchEvent] = []

        self._debounce: dict[str, float] = {}
        self._debounce_interval = 1.0
        self._thread: threading.Thread | None = None
        self._start_time: float | None = None

    def _should_watch(self, filepath: Path) -> bool:
        if filepath.suffix.lower() not in self.extensions:
            return False
        return not any(part in self.exclude_patterns for part in filepath.parts)

    def _scan_files(self) -> dict[str, float]:
        current: dict[str, float] = {}
        if not self.target_dir.exists():
            return current

        for root, dirs, files in os.walk(self.target_dir):
            dirs[:] = [item for item in dirs if item not in self.exclude_patterns]
            root_path = Path(root)
            for name in files:
                path = root_path / name
                if not self._should_watch(path):
                    continue
                try:
                    current[str(path.resolve())] = path.stat().st_mtime
                except OSError:
                    continue
        return current

    def _detect_changes(self, current: dict[str, float]) -> list[WatchEvent]:
        now = time.time()
        events: list[WatchEvent] = []
        old_keys = set(self._file_mtimes.keys())
        cur_keys = set(current.keys())

        for filepath in sorted(cur_keys - old_keys):
            events.append(WatchEvent(event_type="created", filepath=filepath, timestamp=now))

        for filepath in sorted(old_keys & cur_keys):
            if float(current[filepath]) != float(self._file_mtimes[filepath]):
                events.append(WatchEvent(event_type="modified", filepath=filepath, timestamp=now))

        for filepath in sorted(old_keys - cur_keys):
            events.append(WatchEvent(event_type="deleted", filepath=filepath, timestamp=now))

        return events

    def _should_debounce(self, filepath: str) -> bool:
        now = time.time()
        last = self._debounce.get(filepath)
        if last is None:
            self._debounce[filepath] = now
            return False
        if (now - last) < self._debounce_interval:
            return True
        self._debounce[filepath] = now
        return False

    @staticmethod
    def _normalize_issues(payload: Any) -> list[dict[str, Any]]:
        if isinstance(payload, list):
            items = payload
        elif isinstance(payload, dict):
            raw = payload.get("issues", payload.get("findings", []))
            items = raw if isinstance(raw, list) else []
        else:
            items = []

        normalized: list[dict[str, Any]] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            severity = str(item.get("severity", "low")).lower()
            line = item.get("line", 0)
            message = str(
                item.get("message")
                or item.get("check")
                or item.get("fix")
                or item.get("snippet")
                or "Issue detected"
            )
            normalized.append(
                {
                    "severity": severity,
                    "message": message,
                    "line": int(line) if isinstance(line, int | float) else 0,
                }
            )
        return normalized

    def _run_audit(self, filepath: str) -> AuditResult:
        now = time.time()
        try:
            from orchesis.vibe_audit import VibeCodeAuditor

            auditor = VibeCodeAuditor()
            payload = auditor.audit_file(filepath)
            return AuditResult(filepath=filepath, issues=self._normalize_issues(payload), timestamp=now)
        except ImportError:
            pass
        except Exception:
            pass

        # TODO: wire a hard dependency-free scanner fallback if no audit module is importable.
        return AuditResult(filepath=filepath, issues=[], timestamp=now)

    def _handle_event(self, event: WatchEvent):
        self._events.append(event)
        if event.event_type == "deleted":
            return
        if self._should_debounce(event.filepath):
            return
        result = self._run_audit(event.filepath)
        self._results.append(result)
        if self.output_jsonl:
            self._write_jsonl(event, result)
        if callable(self.on_change_callback):
            self.on_change_callback(event, result)

    def _write_jsonl(self, event: WatchEvent, result: AuditResult):
        if not self.output_jsonl:
            return
        path = Path(self.output_jsonl)
        path.parent.mkdir(parents=True, exist_ok=True)
        row = {
            "event_type": event.event_type,
            "filepath": event.filepath,
            "event_ts": event.timestamp,
            "audit_ts": result.timestamp,
            "issues": result.issues,
        }
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    def _poll_loop(self):
        self._file_mtimes = self._scan_files()
        while not self._stop_event.is_set():
            if self._stop_event.wait(self.interval):
                break
            current = self._scan_files()
            events = self._detect_changes(current)
            for event in events:
                self._handle_event(event)
            self._file_mtimes = current

    def start(self, blocking: bool = True):
        self._start_time = time.time()
        self._stop_event.clear()
        if blocking:
            try:
                self._poll_loop()
            except KeyboardInterrupt:
                self.stop()
            return
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=max(1.0, self.interval + 0.5))

    def get_summary(self) -> WatchSummary:
        high = 0
        medium = 0
        low = 0
        for result in self._results:
            for issue in result.issues:
                sev = str(issue.get("severity", "low")).lower()
                if sev == "high":
                    high += 1
                elif sev == "medium":
                    medium += 1
                elif sev == "low":
                    low += 1
        duration = 0.0
        if self._start_time is not None:
            duration = max(0.0, time.time() - self._start_time)
        return WatchSummary(
            files_watched=len(self._file_mtimes),
            changes_detected=len(self._events),
            issues_high=high,
            issues_medium=medium,
            issues_low=low,
            duration_seconds=duration,
        )

    def get_results(self) -> list[AuditResult]:
        return list(self._results)
