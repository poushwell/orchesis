"""HGT Protocol — Horizontal Gene Transfer for agent fleets.

H42: When agent DNA similarity < 0.35, transfer successful behavioral
patterns between agents (like horizontal gene transfer in bacteria).

Activation: fleet >= 5 agents + Exp 2 data.
Currently: stub mode, records outcomes for future activation.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone


class HGTProtocol:
    """Horizontal Gene Transfer — cross-agent behavioral pattern sharing.

    Phase: STUB (activates when fleet >= 5 + Exp 2 data available)
    """

    MIN_FLEET_SIZE = 5
    DNA_SIMILARITY_THRESHOLD = 0.35  # transfer when similarity < threshold

    def __init__(self, config: dict | None = None):
        cfg = config or {}
        self.enabled = bool(cfg.get("enabled", False))
        self.min_fleet = int(cfg.get("min_fleet", self.MIN_FLEET_SIZE))
        self._outcomes: list[dict] = []
        self._transfers: list[dict] = []
        self._lock = threading.Lock()

    def should_transfer(self, agent_a: str, agent_b: str, dna_similarity: float) -> bool:
        """Returns True if HGT transfer should occur."""
        _ = agent_a, agent_b
        return self.enabled and dna_similarity < self.DNA_SIMILARITY_THRESHOLD

    def record_outcome(self, agent_id: str, outcome: dict) -> None:
        """Record agent outcome for future HGT analysis."""
        with self._lock:
            self._outcomes.append(
                {
                    "agent_id": agent_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "outcome": outcome,
                }
            )
            # Bounded: keep last 10000
            if len(self._outcomes) > 10000:
                self._outcomes = self._outcomes[-10000:]

    def transfer(self, from_agent: str, to_agent: str, pattern: dict) -> dict:
        """Execute HGT transfer (stub mode: logs only)."""
        with self._lock:
            transfer = {
                "transfer_id": f"hgt-{len(self._transfers)+1:04d}",
                "from_agent": from_agent,
                "to_agent": to_agent,
                "pattern_type": pattern.get("type", "behavioral"),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "stub_mode": not self.enabled,
            }
            self._transfers.append(transfer)
            return transfer

    def get_transfer_candidates(self, dna_scores: dict[str, float]) -> list[tuple]:
        """Find agent pairs with low DNA similarity (candidates for transfer)."""
        candidates = []
        agents = list(dna_scores.keys())
        for i, a in enumerate(agents):
            for b in agents[i + 1 :]:
                sim = abs(dna_scores[a] - dna_scores[b])
                if sim < self.DNA_SIMILARITY_THRESHOLD:
                    candidates.append((a, b, sim))
        return sorted(candidates, key=lambda x: x[2])

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "enabled": self.enabled,
                "stub_mode": not self.enabled,
                "outcomes_recorded": len(self._outcomes),
                "transfers_executed": len(self._transfers),
                "min_fleet_required": self.min_fleet,
                "activation_condition": f"fleet >= {self.min_fleet} AND Exp2 data",
            }

