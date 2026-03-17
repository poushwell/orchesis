"""Evidence record export for EU AI Act Article 12."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4


class EvidenceRecord:
    """Compliance snapshot: what agent saw at decision moment."""

    @staticmethod
    def _extract_field(item: Any, field: str, default: Any = None) -> Any:
        if isinstance(item, dict):
            return item.get(field, default)
        return getattr(item, field, default)

    @classmethod
    def _normalize_decisions(cls, decisions_log: list[Any]) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []
        for item in decisions_log:
            state_snapshot = cls._extract_field(item, "state_snapshot", {})
            if not isinstance(state_snapshot, dict):
                state_snapshot = {}
            normalized.append(
                {
                    "timestamp": str(cls._extract_field(item, "timestamp", "")),
                    "agent_id": str(cls._extract_field(item, "agent_id", "unknown")),
                    "tool": str(cls._extract_field(item, "tool", "")),
                    "decision": str(cls._extract_field(item, "decision", "")),
                    "reasons": list(cls._extract_field(item, "reasons", []) or []),
                    "cost": float(cls._extract_field(item, "cost", 0.0) or 0.0),
                    "policy_version": str(cls._extract_field(item, "policy_version", "")),
                    "session_id": str(state_snapshot.get("session_id", "__default__")),
                }
            )
        return normalized

    @staticmethod
    def _compute_hash(payload: dict[str, Any]) -> str:
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def build(self, session_id: str, decisions_log: list[Any]) -> dict[str, Any]:
        """Build evidence record from session decisions."""
        decisions = self._normalize_decisions(decisions_log)
        total_requests = len(decisions)
        blocked = sum(1 for item in decisions if str(item.get("decision", "")).upper() == "DENY")
        allowed = sum(1 for item in decisions if str(item.get("decision", "")).upper() == "ALLOW")
        cost_usd = round(sum(float(item.get("cost", 0.0) or 0.0) for item in decisions), 6)
        agent_id = str(decisions[0].get("agent_id", "unknown")) if decisions else "unknown"
        record: dict[str, Any] = {
            "record_id": str(uuid4()),
            "session_id": str(session_id),
            "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "agent_id": agent_id,
            "eu_ai_act_article": "Article 12 - Record keeping",
            "decisions": decisions,
            "summary": {
                "total_requests": total_requests,
                "blocked": blocked,
                "allowed": allowed,
                "cost_usd": cost_usd,
            },
            "integrity": {
                "hash_algorithm": "sha256",
                "record_hash": "",
            },
        }
        hash_payload = dict(record)
        hash_payload["integrity"] = dict(record["integrity"])
        hash_payload["integrity"]["record_hash"] = ""
        record["integrity"]["record_hash"] = self._compute_hash(hash_payload)
        return record

    def export_json(self, record: dict[str, Any], path: str) -> str:
        """Export as JSON file. Returns file path."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
        return str(target)

    def export_text(self, record: dict[str, Any]) -> str:
        """Export as human-readable text report (no PDF deps)."""
        summary = record.get("summary", {}) if isinstance(record.get("summary"), dict) else {}
        lines = [
            "Orchesis Evidence Record",
            f"Record ID: {record.get('record_id', '')}",
            f"Session ID: {record.get('session_id', '')}",
            f"Agent ID: {record.get('agent_id', '')}",
            f"Generated At: {record.get('generated_at', '')}",
            f"EU AI Act: {record.get('eu_ai_act_article', '')}",
            "",
            "Summary",
            f"- total_requests: {summary.get('total_requests', 0)}",
            f"- blocked: {summary.get('blocked', 0)}",
            f"- allowed: {summary.get('allowed', 0)}",
            f"- cost_usd: {summary.get('cost_usd', 0)}",
            "",
            "Integrity",
            f"- hash_algorithm: {record.get('integrity', {}).get('hash_algorithm', '') if isinstance(record.get('integrity'), dict) else ''}",
            f"- record_hash: {record.get('integrity', {}).get('record_hash', '') if isinstance(record.get('integrity'), dict) else ''}",
        ]
        return "\n".join(lines) + "\n"
