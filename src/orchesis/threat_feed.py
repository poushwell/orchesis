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
        self.feed_limit = int(cfg.get("feed_limit", 1000))
        self._signatures: list[dict[str, Any]] = []
        self._last_updated: float = 0.0
        self._community_feed: list[dict[str, Any]] = []

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

    def get_community_feed(self) -> list[dict]:
        """Get aggregated community threat feed."""
        return [dict(item) for item in self._community_feed]

    def submit_threat(self, signature: str, severity: str, context: dict) -> dict:
        """Submit new threat to community feed."""
        sig = str(signature or "").strip()
        sev = str(severity or "").strip().lower() or "medium"
        if sev not in {"critical", "high", "medium", "low"}:
            sev = "medium"
        ctx = context if isinstance(context, dict) else {}
        now = datetime.now(timezone.utc).isoformat()

        for row in self._community_feed:
            if str(row.get("signature", "")) == sig:
                row["reports"] = int(row.get("reports", 0) or 0) + 1
                row["severity"] = sev
                row["verified"] = bool(row.get("verified", False) or ctx.get("verified", False))
                row["updated_at"] = now
                return dict(row)

        feed_id = f"feed-{int(time.time() * 1000)}-{len(self._community_feed) + 1}"
        item = {
            "feed_id": feed_id,
            "signature": sig,
            "severity": sev,
            "source": "community",
            "verified": bool(ctx.get("verified", False)),
            "reports": 1,
            "context": dict(ctx),
            "created_at": now,
            "updated_at": now,
        }
        self._community_feed.append(item)
        if len(self._community_feed) > max(1, self.feed_limit):
            self._community_feed = self._community_feed[-self.feed_limit :]
        return dict(item)

    def get_trending_threats(self, limit: int = 10) -> list[dict]:
        """Get trending threats by report count."""
        n = max(1, int(limit or 10))
        rows = sorted(self._community_feed, key=lambda r: int(r.get("reports", 0) or 0), reverse=True)
        return [dict(item) for item in rows[:n]]

    def export_feed(self, format: str = "json") -> str:
        """Export feed as JSON or YAML."""
        payload = {"feed": self.get_community_feed()}
        fmt = str(format or "json").strip().lower()
        if fmt == "yaml":
            return yaml.safe_dump(payload, sort_keys=False)
        return json.dumps(payload, ensure_ascii=False)
