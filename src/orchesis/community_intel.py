"""Opt-in community threat intelligence sharing."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any


class CommunityIntel:
    """Opt-in community threat intelligence sharing."""

    def __init__(self, config: dict | None = None):
        cfg = config if isinstance(config, dict) else {}
        self.enabled = bool(cfg.get("enabled", False))
        self.endpoint = str(cfg.get("endpoint", "https://orchesis.io/api/community"))
        self.share_signatures = bool(cfg.get("share_signatures", True))
        self.share_patterns = bool(cfg.get("share_patterns", False))
        self._threats_submitted = 0
        self._updates_pulled = 0
        self._community_signatures = 0
        self._last_sync = ""
        self._submitted: list[dict[str, Any]] = []
        raw_updates = cfg.get("seed_updates", [])
        self._seed_updates = [item for item in raw_updates if isinstance(item, dict)] if isinstance(raw_updates, list) else []

    def submit_threat(self, threat: dict) -> bool:
        """Submit anonymized threat to community feed."""
        if not self.enabled or not isinstance(threat, dict):
            return False
        payload = self.anonymize(threat)
        if not payload:
            return False
        self._submitted.append(payload)
        self._threats_submitted += 1
        self._last_sync = datetime.now(timezone.utc).isoformat()
        return True

    def pull_updates(self) -> list[dict]:
        """Pull community threat updates."""
        if not self.enabled:
            return []
        updates = [dict(item) for item in self._seed_updates]
        self._updates_pulled += len(updates)
        self._community_signatures += len(updates)
        self._last_sync = datetime.now(timezone.utc).isoformat()
        return updates

    def get_stats(self) -> dict:
        return {
            "enabled": bool(self.enabled),
            "threats_submitted": int(self._threats_submitted),
            "updates_pulled": int(self._updates_pulled),
            "community_signatures": int(self._community_signatures),
            "last_sync": str(self._last_sync),
        }

    def anonymize(self, threat: dict) -> dict:
        """Strip PII and identifying info before sharing."""
        if not isinstance(threat, dict):
            return {}
        threat_type = str(threat.get("threat_type", "") or "").strip()
        severity = str(threat.get("severity", "medium") or "medium").strip()
        timestamp = threat.get("timestamp")
        if isinstance(timestamp, (int, float)):
            ts_value: str | int | float = timestamp
        else:
            ts_value = str(timestamp or datetime.now(timezone.utc).isoformat())
        pattern_hash = str(threat.get("pattern_hash", "") or "").strip()
        if not pattern_hash and self.share_signatures:
            signature_source = str(threat.get("signature", "") or threat.get("pattern", "") or threat_type)
            pattern_hash = hashlib.sha256(signature_source.encode("utf-8")).hexdigest()[:16]
        payload: dict[str, Any] = {
            "threat_type": threat_type or "unknown",
            "severity": severity or "medium",
            "timestamp": ts_value,
        }
        if self.share_signatures and pattern_hash:
            payload["pattern_hash"] = pattern_hash
        if self.share_patterns:
            pattern = threat.get("pattern")
            if isinstance(pattern, str) and pattern.strip():
                payload["pattern"] = pattern.strip()
        return payload
