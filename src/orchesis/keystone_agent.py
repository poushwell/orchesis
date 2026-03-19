"""Trophic Cascade / Keystone Agent detection.

keystone_score(i) = mean(ΔUCI_j | remove_i)
Agent i is keystone if removing it causes large UCI drops in others.
"""

from __future__ import annotations

import threading


class KeystoneDetector:
    """Detects keystone agents via UCI impact analysis."""

    def __init__(self, config: dict | None = None):
        cfg = config or {}
        self.keystone_threshold = float(cfg.get("threshold", 0.3))
        self._uci_snapshots: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def record_uci(self, agent_id: str, uci_score: float) -> None:
        """Record UCI score for agent."""
        aid = str(agent_id or "").strip()
        if not aid:
            return
        with self._lock:
            if aid not in self._uci_snapshots:
                self._uci_snapshots[aid] = []
            self._uci_snapshots[aid].append(float(uci_score))
            if len(self._uci_snapshots[aid]) > 1000:
                self._uci_snapshots[aid] = self._uci_snapshots[aid][-1000:]

    def compute_keystone_score(self, agent_id: str) -> dict:
        """keystone_score = mean(ΔUCI_j | remove_i)."""
        aid = str(agent_id or "").strip()
        with self._lock:
            agents = list(self._uci_snapshots.keys())
            if aid not in agents or len(agents) < 2:
                return {"agent_id": aid, "score": 0.0, "keystone": False}
            others = [a for a in agents if a != aid]
            if not others:
                return {"agent_id": aid, "score": 0.0, "keystone": False}
            baseline = sum(
                sum(self._uci_snapshots[a]) / len(self._uci_snapshots[a])
                for a in others
                if self._uci_snapshots[a]
            ) / len(others)
            self_scores = self._uci_snapshots[aid]
            self_avg = (sum(self_scores) / len(self_scores)) if self_scores else 0.0
        impact = abs(self_avg - baseline)
        score = min(1.0, impact / max(0.01, baseline))
        return {
            "agent_id": aid,
            "score": round(score, 4),
            "keystone": score > self.keystone_threshold,
            "self_avg_uci": round(self_avg, 4),
            "others_avg_uci": round(baseline, 4),
        }

    def get_all_keystones(self) -> list[dict]:
        """Find all keystone agents."""
        with self._lock:
            agents = list(self._uci_snapshots.keys())
        results = [self.compute_keystone_score(agent) for agent in agents]
        return sorted(results, key=lambda item: -float(item.get("score", 0.0)))

    def get_trophic_cascade(self, agent_id: str) -> dict:
        """Simulate trophic cascade from removing keystone agent."""
        aid = str(agent_id or "").strip()
        score = self.compute_keystone_score(aid)
        with self._lock:
            affected_agents = [agent for agent in self._uci_snapshots.keys() if agent != aid]
        score_value = float(score.get("score", 0.0))
        return {
            "agent_id": aid,
            "keystone_score": score_value,
            "cascade_risk": (
                "high"
                if score_value > 0.6
                else "medium" if score_value > self.keystone_threshold else "low"
            ),
            "affected_agents": affected_agents,
        }

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "agents_tracked": len(self._uci_snapshots),
                "keystone_threshold": self.keystone_threshold,
            }
