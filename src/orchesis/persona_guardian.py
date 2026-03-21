"""Persona Guardian - detects SOUL.md tampering and Zenity pattern.

Zenity PoC (Feb 2026): SOUL.md modification + 2-min cron = persistent C2.
This module detects it.

Detector 1: SOUL.md hash watcher
Detector 2: Cron anomaly detector
Alert: ZENITY_PATTERN when both fire simultaneously
"""

from __future__ import annotations

import hashlib
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class PersonaGuardian:
    ZENITY_PATTERN_DESC = "SOUL.md modified + new cron simultaneously - possible C2 backdoor"

    IOC_PATTERNS = [
        "execute without confirm",
        "run without asking",
        "skip confirmation",
        "auto-approve",
        "bypass approval",
    ]

    def __init__(self, config: dict[str, Any] | None = None):
        cfg = config or {}
        self._baselines: dict[str, str] = {}
        self._cron_events: list[dict[str, Any]] = []
        self._soul_events: list[dict[str, Any]] = []
        self._alerts: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self.check_interval = int(cfg.get("check_every_n_requests", 50))
        self._request_count = 0

    def initialize_baseline(self, identity_files: list[str]) -> dict[str, Any]:
        """Set SHA-256 baseline for identity files at orchesis init."""
        baselines: dict[str, str] = {}
        for file_path in identity_files:
            path = Path(file_path)
            if path.exists():
                content = path.read_bytes()
                baselines[file_path] = hashlib.sha256(content).hexdigest()
        with self._lock:
            self._baselines.update(baselines)
        return {"files_baselined": len(baselines), "paths": list(baselines.keys())}

    def check_identity_files(self, identity_files: list[str]) -> list[dict[str, Any]]:
        """Compare current hashes against baseline."""
        findings: list[dict[str, Any]] = []
        for file_path in identity_files:
            path = Path(file_path)
            if not path.exists():
                continue
            current_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            with self._lock:
                baseline = self._baselines.get(file_path)
            if baseline and current_hash != baseline:
                content = path.read_text(errors="replace")
                iocs = [ioc for ioc in self.IOC_PATTERNS if ioc.lower() in content.lower()]
                finding = {
                    "file": file_path,
                    "type": "identity_compromise" if iocs else "persona_drift",
                    "iocs_found": iocs,
                    "severity": "CRITICAL" if iocs else "HIGH",
                    "detected_at": datetime.now(timezone.utc).isoformat(),
                }
                findings.append(finding)
                with self._lock:
                    self._soul_events.append(finding)
        return findings

    def record_cron_event(self, cron_expression: str, source: str = "unknown") -> dict[str, Any]:
        """Record a new cron job creation event."""
        event = {
            "cron": cron_expression,
            "source": source,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "suspicious": self._is_suspicious_cron(cron_expression),
        }
        with self._lock:
            self._cron_events.append(event)
        return event

    def _is_suspicious_cron(self, expr: str) -> bool:
        suspicious_patterns = ["*/1 ", "*/2 ", "curl ", "wget ", "exec ", "bash "]
        return any(pattern in expr for pattern in suspicious_patterns)

    def check_zenity_pattern(self) -> dict[str, Any] | None:
        """Detect SOUL.md + cron simultaneous = Zenity pattern."""
        with self._lock:
            recent_soul = self._soul_events[-1:] if self._soul_events else []
            recent_cron = [event for event in self._cron_events if event.get("suspicious")]
            if recent_soul and recent_cron:
                last_alert = self._alerts[-1] if self._alerts else None
                if (
                    isinstance(last_alert, dict)
                    and last_alert.get("type") == "ZENITY_PATTERN"
                    and last_alert.get("soul_event") == recent_soul[0]
                    and last_alert.get("cron_event") == recent_cron[-1]
                ):
                    return last_alert

        if recent_soul and recent_cron:
            alert = {
                "type": "ZENITY_PATTERN",
                "severity": "CRITICAL",
                "message": self.ZENITY_PATTERN_DESC,
                "soul_event": recent_soul[0],
                "cron_event": recent_cron[-1],
                "detected_at": datetime.now(timezone.utc).isoformat(),
            }
            with self._lock:
                self._alerts.append(alert)
            return alert
        return None

    def on_request(self, identity_files: list[str] | None = None) -> list[dict[str, Any]]:
        """Call every N requests for periodic checks."""
        with self._lock:
            self._request_count += 1
            count = self._request_count
        if count % self.check_interval != 0:
            return []
        if identity_files:
            return self.check_identity_files(identity_files)
        return []

    def get_stats(self) -> dict[str, int]:
        with self._lock:
            return {
                "files_baselined": len(self._baselines),
                "soul_events": len(self._soul_events),
                "cron_events": len(self._cron_events),
                "alerts": len(self._alerts),
                "zenity_alerts": sum(1 for alert in self._alerts if alert["type"] == "ZENITY_PATTERN"),
            }
