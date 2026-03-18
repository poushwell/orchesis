"""Peer-to-peer style gossip for background context propagation."""

from __future__ import annotations

import threading
import uuid
from typing import Any


class GossipProtocol:
    """Eventual consistency for background context propagation."""

    def __init__(self, config: dict | None = None):
        cfg = config or {}
        self.fanout = max(1, int(cfg.get("fanout", 3)))
        self.ttl = max(1, int(cfg.get("ttl_rounds", 5)))
        self._messages: list[dict[str, Any]] = []
        self._archive: list[dict[str, Any]] = []
        self._delivered: set[str] = set()
        self._known_agents: set[str] = set()
        self._rounds = 0
        self._broadcasts = 0
        self._lock = threading.Lock()

    def broadcast(self, key: str, value: str, source_agent: str) -> str:
        """Broadcast context update. Returns message_id."""
        with self._lock:
            src = str(source_agent).strip() or "unknown"
            self._known_agents.add(src)
            message_id = f"gossip-{uuid.uuid4().hex[:12]}"
            row = {
                "message_id": message_id,
                "key": str(key),
                "value": str(value),
                "source_agent": src,
                "ttl_remaining": int(self.ttl),
                "delivered_to": set(),
            }
            self._messages.append(row)
            self._broadcasts += 1
            return message_id

    def receive(self, agent_id: str) -> list[dict]:
        """Pull pending gossip messages for agent."""
        with self._lock:
            aid = str(agent_id).strip()
            if not aid:
                return []
            self._known_agents.add(aid)
            out: list[dict] = []
            for row in self._messages:
                if int(row.get("ttl_remaining", 0)) <= 0:
                    continue
                if aid == str(row.get("source_agent", "")):
                    continue
                delivered = row.get("delivered_to")
                if not isinstance(delivered, set):
                    delivered = set()
                    row["delivered_to"] = delivered
                if aid in delivered:
                    continue
                delivered.add(aid)
                self._delivered.add(f"{row.get('message_id')}::{aid}")
                out.append(self._public_row(row))
            self._cleanup_locked()
            return out

    def propagate(self) -> int:
        """Run one gossip round. Returns messages propagated."""
        with self._lock:
            self._rounds += 1
            propagated = 0
            agents = sorted(self._known_agents)
            for row in self._messages:
                if int(row.get("ttl_remaining", 0)) <= 0:
                    continue
                source = str(row.get("source_agent", ""))
                delivered = row.get("delivered_to")
                if not isinstance(delivered, set):
                    delivered = set()
                    row["delivered_to"] = delivered
                pending = [aid for aid in agents if aid != source and aid not in delivered]
                if pending:
                    for aid in pending[: self.fanout]:
                        delivered.add(aid)
                        self._delivered.add(f"{row.get('message_id')}::{aid}")
                        propagated += 1
                row["ttl_remaining"] = int(row.get("ttl_remaining", 0)) - 1
            self._cleanup_locked()
            return propagated

    def get_convergence_status(self) -> dict:
        with self._lock:
            all_rows = list(self._archive) + list(self._messages)
            total = len(all_rows)
            delivered_to_all = sum(1 for row in all_rows if self._is_delivered_to_all(row))
            pending = sum(
                1
                for row in self._messages
                if int(row.get("ttl_remaining", 0)) > 0 and not self._is_delivered_to_all(row)
            )
            rate = (delivered_to_all / float(total)) if total else 1.0
            return {
                "total_messages": total,
                "delivered_to_all": delivered_to_all,
                "pending": pending,
                "convergence_rate": round(rate, 3),
            }

    def get_stats(self) -> dict:
        with self._lock:
            ttl_values = [int(row.get("ttl_remaining", 0)) for row in self._messages]
            avg_ttl = (sum(ttl_values) / float(len(ttl_values))) if ttl_values else 0.0
            return {
                "broadcasts": int(self._broadcasts),
                "rounds": int(self._rounds),
                "avg_ttl_remaining": round(avg_ttl, 3),
            }

    def _cleanup_locked(self) -> None:
        keep: list[dict[str, Any]] = []
        for row in self._messages:
            if int(row.get("ttl_remaining", 0)) <= 0 or self._is_delivered_to_all(row):
                archived = dict(row)
                delivered = row.get("delivered_to")
                if isinstance(delivered, set):
                    archived["delivered_to"] = set(delivered)
                self._archive.append(archived)
                continue
            keep.append(row)
        self._messages = keep

    def _is_delivered_to_all(self, row: dict[str, Any]) -> bool:
        source = str(row.get("source_agent", ""))
        targets = {aid for aid in self._known_agents if aid != source}
        delivered = row.get("delivered_to")
        if not isinstance(delivered, set):
            return False
        if not targets:
            return True
        return targets.issubset(delivered)

    @staticmethod
    def _public_row(row: dict[str, Any]) -> dict:
        return {
            "message_id": str(row.get("message_id", "")),
            "key": str(row.get("key", "")),
            "value": str(row.get("value", "")),
            "source_agent": str(row.get("source_agent", "")),
            "ttl_remaining": int(row.get("ttl_remaining", 0) or 0),
        }
