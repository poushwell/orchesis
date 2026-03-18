"""Simplified Raft-style context consistency tracking."""

from __future__ import annotations

import threading
from typing import Any


class RaftContextProtocol:
    """Proxy as Raft leader for context consistency."""

    def __init__(self, config: dict | None = None):
        _ = config or {}
        self._term = 0
        self._log: list[dict[str, Any]] = []
        self._committed = 0
        self._followers: dict[str, int] = {}
        self._lock = threading.Lock()

    def append_entry(self, key: str, value: str, agent_id: str) -> dict:
        """Leader appends new context entry."""
        with self._lock:
            self._term += 1
            follower_id = str(agent_id).strip() or "unknown"
            self._followers.setdefault(follower_id, 0)
            index = len(self._log) + 1
            entry = {
                "index": index,
                "term": self._term,
                "key": str(key),
                "value": str(value),
                "agent_id": follower_id,
                "committed": False,
            }
            self._log.append(entry)
            self._recompute_committed()
            return {
                "index": index,
                "term": self._term,
                "key": str(key),
                "committed": index <= self._committed,
            }

    def acknowledge(self, agent_id: str, index: int) -> bool:
        """Agent acknowledges receiving entry up to index."""
        with self._lock:
            follower_id = str(agent_id).strip()
            if not follower_id:
                return False
            bounded = max(0, min(int(index), len(self._log)))
            self._followers[follower_id] = max(self._followers.get(follower_id, 0), bounded)
            before = self._committed
            self._recompute_committed()
            return self._committed >= before

    def get_consistent_context(self, agent_id: str) -> dict:
        """Get committed context entries for agent."""
        with self._lock:
            follower_id = str(agent_id).strip()
            self._followers.setdefault(follower_id, 0)
            entries = [
                {"index": row["index"], "term": row["term"], "key": row["key"], "value": row["value"]}
                for row in self._log
                if int(row.get("index", 0)) <= self._committed
            ]
            return {
                "agent_id": follower_id,
                "committed_index": self._committed,
                "entries": entries,
            }

    def get_divergent_agents(self) -> list[str]:
        """Agents whose context is behind committed index."""
        with self._lock:
            return sorted(
                agent_id
                for agent_id, ack in self._followers.items()
                if int(ack) < int(self._committed)
            )

    def sync_agent(self, agent_id: str) -> dict:
        """Send missing entries to lagging agent."""
        with self._lock:
            follower_id = str(agent_id).strip()
            self._followers.setdefault(follower_id, 0)
            last_ack = int(self._followers.get(follower_id, 0))
            missing = [
                {"index": row["index"], "term": row["term"], "key": row["key"], "value": row["value"]}
                for row in self._log
                if last_ack < int(row.get("index", 0)) <= self._committed
            ]
            if self._committed > last_ack:
                self._followers[follower_id] = self._committed
            return {
                "agent_id": follower_id,
                "sent": len(missing),
                "entries": missing,
                "committed_index": self._committed,
            }

    def get_raft_stats(self) -> dict:
        with self._lock:
            followers = len(self._followers)
            divergent = sorted(
                agent_id
                for agent_id, ack in self._followers.items()
                if int(ack) < int(self._committed)
            )
            consistency_rate = 1.0
            if followers > 0:
                consistency_rate = max(0.0, min(1.0, (followers - len(divergent)) / float(followers)))
            return {
                "term": self._term,
                "log_size": len(self._log),
                "committed": self._committed,
                "followers": followers,
                "divergent_agents": divergent,
                "consistency_rate": round(consistency_rate, 3),
            }

    def _recompute_committed(self) -> None:
        max_index = len(self._log)
        committed = self._committed
        total_nodes = 1 + len(self._followers)  # leader + followers
        for idx in range(max_index, 0, -1):
            acks = 1 + sum(1 for value in self._followers.values() if int(value) >= idx)
            if acks > total_nodes / 2.0:
                committed = idx
                break
        self._committed = committed
        for row in self._log:
            row["committed"] = int(row.get("index", 0)) <= self._committed
