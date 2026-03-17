"""External threat intelligence feed integration."""

from __future__ import annotations

import json
import time
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.request import Request as UrlRequest, urlopen

import yaml


class ThreatFeed:
    """Manages threat signature updates from community feed."""

    def __init__(self, config: dict | None = None):
        cfg = config or {}
        self.feed_url = str(cfg.get("feed_url", "https://orchesis.io/api/threat-feed"))
        self.update_interval = int(cfg.get("update_interval_hours", 24))
        self.auto_update = bool(cfg.get("auto_update", False))
        self._signatures: list[dict[str, Any]] = []
        self._last_updated: float = 0.0

    @staticmethod
    def _signature_key(item: dict[str, Any]) -> str:
        if isinstance(item.get("threat_id"), str) and item.get("threat_id"):
            return str(item["threat_id"])
        if isinstance(item.get("id"), str) and item.get("id"):
            return str(item["id"])
        payload = json.dumps(item, sort_keys=True, ensure_ascii=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def fetch(self) -> list[dict[str, Any]]:
        """Fetch latest signatures. Returns new signatures added."""
        req = UrlRequest(self.feed_url, headers={"Accept": "application/json"})
        with urlopen(req, timeout=10) as response:
            raw = response.read().decode("utf-8")
        payload = json.loads(raw)
        if isinstance(payload, dict):
            entries = payload.get("signatures", [])
        else:
            entries = payload
        if not isinstance(entries, list):
            return []
        existing = {self._signature_key(item) for item in self._signatures if isinstance(item, dict)}
        new_entries: list[dict[str, Any]] = []
        for item in entries:
            if not isinstance(item, dict):
                continue
            key = self._signature_key(item)
            if key in existing:
                continue
            self._signatures.append(dict(item))
            existing.add(key)
            new_entries.append(dict(item))
        self._last_updated = time.time()
        return new_entries

    def apply(self, threat_intel) -> int:  # noqa: ANN001
        """Apply fetched signatures to ThreatIntel instance. Returns count added."""
        if threat_intel is None:
            return 0
        applied = 0
        add_method = getattr(threat_intel, "add_signature", None)
        add_custom_method = getattr(threat_intel, "add_custom_signature", None)
        for item in self._signatures:
            if callable(add_method):
                add_method(dict(item))
                applied += 1
                continue
            if callable(add_custom_method):
                add_custom_method(dict(item))
                applied += 1
                continue
            if hasattr(threat_intel, "_threats") and isinstance(getattr(threat_intel, "_threats"), dict):
                store = getattr(threat_intel, "_threats")
                key = self._signature_key(item)
                if key not in store:
                    store[key] = dict(item)
                    applied += 1
        return applied

    def get_stats(self) -> dict[str, Any]:
        next_update_ts = self._last_updated + max(1, self.update_interval) * 3600 if self._last_updated else 0.0
        return {
            "signatures_count": len(self._signatures),
            "last_updated": (
                datetime.fromtimestamp(self._last_updated, tz=timezone.utc).isoformat()
                if self._last_updated
                else ""
            ),
            "next_update": (
                datetime.fromtimestamp(next_update_ts, tz=timezone.utc).isoformat() if next_update_ts else ""
            ),
            "auto_update": bool(self.auto_update),
            "feed_url": self.feed_url,
        }

    def export_signatures(self, path: str) -> None:
        """Export current signatures to YAML file."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = {"signatures": self._signatures}
        target.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")

    def import_signatures(self, path: str) -> int:
        """Import signatures from YAML file. Returns count imported."""
        source = Path(path)
        payload = yaml.safe_load(source.read_text(encoding="utf-8"))
        entries = payload.get("signatures", []) if isinstance(payload, dict) else payload
        if not isinstance(entries, list):
            return 0
        existing = {self._signature_key(item) for item in self._signatures if isinstance(item, dict)}
        added = 0
        for item in entries:
            if not isinstance(item, dict):
                continue
            key = self._signature_key(item)
            if key in existing:
                continue
            self._signatures.append(dict(item))
            existing.add(key)
            added += 1
        if added > 0:
            self._last_updated = time.time()
        return added
