"""Forensic Context Reconstruction.

Reconstruct what an agent saw at time of decision from audit trail.
EU AI Act Article 12: decisions must be explainable post-hoc.

Tier 3: requires fleet audit data.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any


class ForensicReconstructor:
    """Reconstructs agent context from audit trail for forensic analysis."""

    def __init__(self, decisions_log_path: str = ".orchesis/decisions.jsonl"):
        self.log_path = str(decisions_log_path)
        self._cache: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def reconstruct(self, request_id: str, decisions_log: list[dict[str, Any]]) -> dict[str, Any]:
        """Reconstruct full context for a specific request."""
        rid = str(request_id or "").strip()
        matching = [row for row in decisions_log if str(row.get("request_id", "")) == rid]

        if not matching:
            return {"error": f"No record found for request_id: {rid}"}

        record = matching[0]
        snapshot = record.get("state_snapshot", {})
        if not isinstance(snapshot, dict):
            snapshot = {}

        reconstruction: dict[str, Any] = {
            "request_id": rid,
            "reconstructed_at": datetime.now(timezone.utc).isoformat(),
            "original_timestamp": record.get("timestamp", "unknown"),
            "agent_id": record.get("agent_id", "unknown"),
            "decision": record.get("decision", "unknown"),
            "reasons": list(record.get("reasons", []) or []),
            "context_snapshot": {
                "messages_seen": int(record.get("message_count", 0) or 0),
                "estimated_tokens": int(record.get("tokens", 0) or 0),
                "phase": snapshot.get("phase", "unknown"),
                "psi": snapshot.get("psi", None),
            },
            "pipeline_phases": list(record.get("phases", []) or []),
            "eu_ai_act_compliant": True,
            "integrity_hash": record.get("hash", None),
        }

        with self._lock:
            self._cache[rid] = reconstruction
        return reconstruction

    def find_causal_chain(self, request_id: str, decisions_log: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Find chain of decisions leading to this request."""
        rid = str(request_id or "").strip()
        target = next((row for row in decisions_log if str(row.get("request_id", "")) == rid), None)
        if not isinstance(target, dict):
            return []

        agent_id = target.get("agent_id")
        target_time = str(target.get("timestamp", ""))
        prior = [
            row
            for row in decisions_log
            if row.get("agent_id") == agent_id and str(row.get("timestamp", "")) < target_time
        ]
        return sorted(prior, key=lambda row: str(row.get("timestamp", "")))[-5:]

    def generate_forensic_report(
        self, request_id: str, decisions_log: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Generate full forensic report for request."""
        rid = str(request_id or "").strip()
        reconstruction = self.reconstruct(rid, decisions_log)
        causal_chain = self.find_causal_chain(rid, decisions_log)
        return {
            "report_id": f"forensic-{rid[:8]}",
            "request_id": rid,
            "reconstruction": reconstruction,
            "causal_chain": causal_chain,
            "chain_length": len(causal_chain),
            "eu_ai_act_article": "Article 12 — Record keeping and traceability",
        }

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "cached_reconstructions": len(self._cache),
                "log_path": self.log_path,
            }
