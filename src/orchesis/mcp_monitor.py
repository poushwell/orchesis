"""Runtime monitoring for MCP configuration files."""

from __future__ import annotations

import hashlib
import threading
import time
from pathlib import Path
from typing import Any


class McpRuntimeMonitor:
    """Monitors MCP configs for changes during runtime."""

    def __init__(self, config_paths: list[str], interval_seconds: int = 30):
        self._paths = [str(path) for path in config_paths if isinstance(path, str) and path.strip()]
        self._interval = max(1, int(interval_seconds))
        self._hashes: dict[str, str | None] = {}
        self._alerts: list[dict[str, Any]] = []
        self._checks_run = 0
        self._changes_detected = 0
        self._started_at = time.perf_counter()
        self._running = False
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        for path in self._paths:
            self._hashes[path] = self._hash_path(path)

    def _hash_path(self, path: str) -> str | None:
        candidate = Path(path)
        if not candidate.exists() or not candidate.is_file():
            return None
        try:
            payload = candidate.read_bytes()
        except OSError:
            return None
        return hashlib.sha256(payload).hexdigest()

    def _build_change(self, *, path: str, change_type: str, details: str) -> dict[str, Any]:
        severity = "medium"
        if change_type in {"removed", "modified"}:
            severity = "high"
        return {
            "timestamp": time.time(),
            "path": path,
            "type": change_type,
            "severity": severity,
            "details": details,
        }

    def start(self) -> None:
        """Start background monitoring thread."""
        with self._lock:
            if self._running:
                return
            self._running = True
            self._stop_event.clear()

            def _worker() -> None:
                while not self._stop_event.wait(self._interval):
                    self.check_once()

            self._thread = threading.Thread(target=_worker, name="orchesis-mcp-monitor", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        """Stop monitoring."""
        with self._lock:
            if not self._running:
                return
            self._running = False
            self._stop_event.set()
            thread = self._thread
            self._thread = None
        if thread is not None:
            thread.join(timeout=1.0)

    def check_once(self) -> list[dict[str, Any]]:
        """Single check pass. Returns list of changes detected."""
        changes: list[dict[str, Any]] = []
        with self._lock:
            for path in self._paths:
                previous_hash = self._hashes.get(path)
                current_hash = self._hash_path(path)
                if previous_hash is None and current_hash is not None:
                    changes.append(
                        self._build_change(path=path, change_type="added", details="MCP config file appeared")
                    )
                elif previous_hash is not None and current_hash is None:
                    changes.append(
                        self._build_change(path=path, change_type="removed", details="MCP config file removed")
                    )
                elif previous_hash is not None and current_hash is not None and previous_hash != current_hash:
                    changes.append(
                        self._build_change(path=path, change_type="modified", details="MCP config file content changed")
                    )
                self._hashes[path] = current_hash
            self._checks_run += 1
            if changes:
                self._changes_detected += len(changes)
                self._alerts.extend(changes)
        return changes

    def get_alerts(self, since: float | None = None) -> list[dict[str, Any]]:
        """Return alerts since timestamp."""
        with self._lock:
            if since is None:
                return [dict(item) for item in self._alerts]
            return [dict(item) for item in self._alerts if float(item.get("timestamp", 0.0)) >= float(since)]

    def get_stats(self) -> dict[str, Any]:
        """Monitoring stats: checks_run, changes_detected, uptime."""
        with self._lock:
            uptime = max(0.0, time.perf_counter() - self._started_at)
            return {
                "checks_run": int(self._checks_run),
                "changes_detected": int(self._changes_detected),
                "uptime_seconds": float(round(uptime, 6)),
                "running": bool(self._running),
                "paths": list(self._paths),
            }
