"""Fleet-level Byzantine fault detection for agents."""

from __future__ import annotations

import threading
from typing import Any


class ByzantineDetector:
    """Detects compromised agents in fleet."""

    MIN_FLEET_SIZE = 5

    SIGNALS = {
        "behavior_drift": "Agent behavior deviates from baseline",
        "response_inconsistency": "Contradicting responses to same query",
        "cost_anomaly": "Unusual token consumption pattern",
        "timing_anomaly": "Response latency outlier",
        "tool_abuse": "Abnormal tool call patterns",
    }

    def __init__(self, config: dict | None = None):
        cfg = config or {}
        self.threshold = float(cfg.get("threshold", 0.7))
        self._observations: dict[str, list[dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def observe(self, agent_id: str, metrics: dict) -> None:
        """Record agent observation."""
        if not isinstance(agent_id, str) or not agent_id.strip():
            return
        payload = dict(metrics) if isinstance(metrics, dict) else {}
        with self._lock:
            rows = self._observations.setdefault(agent_id.strip(), [])
            rows.append(payload)
            if len(rows) > 500:
                del rows[:-500]

    def detect(self) -> list[dict]:
        """Run Byzantine detection across fleet."""
        with self._lock:
            snapshot = {agent_id: list(rows) for agent_id, rows in self._observations.items()}
        if len(snapshot) < self.MIN_FLEET_SIZE:
            return []
        out: list[dict] = []
        for agent_id, rows in snapshot.items():
            probability, signals = self._agent_probability(rows)
            if probability < self.threshold:
                continue
            recommendation = "monitor"
            if probability >= 0.9:
                recommendation = "ban"
            elif probability >= 0.8:
                recommendation = "quarantine"
            out.append(
                {
                    "agent_id": agent_id,
                    "byzantine_probability": round(probability, 3),
                    "signals": signals,
                    "recommendation": recommendation,
                }
            )
        out.sort(key=lambda item: float(item.get("byzantine_probability", 0.0)), reverse=True)
        return out

    def cross_validate(self, agent_a: str, agent_b: str, query: str) -> dict:
        """Compare responses from two agents to same query."""
        with self._lock:
            rows_a = list(self._observations.get(str(agent_a), []))
            rows_b = list(self._observations.get(str(agent_b), []))
        response_a = self._response_for_query(rows_a, query)
        response_b = self._response_for_query(rows_b, query)
        score = self._similarity_score(response_a, response_b)
        inconsistent = score < 0.7
        return {
            "agent_a": str(agent_a),
            "agent_b": str(agent_b),
            "query": str(query),
            "consistency_score": round(score, 3),
            "inconsistent": inconsistent,
            "signals": ["response_inconsistency"] if inconsistent else [],
        }

    def get_fleet_health(self) -> dict:
        with self._lock:
            snapshot = {agent_id: list(rows) for agent_id, rows in self._observations.items()}
        size = len(snapshot)
        suspicious = 0
        quarantined = 0
        for rows in snapshot.values():
            probability, _ = self._agent_probability(rows)
            if probability >= 0.85:
                quarantined += 1
            elif probability >= self.threshold:
                suspicious += 1
        healthy = max(0, size - suspicious - quarantined)
        return {
            "fleet_size": size,
            "healthy": healthy,
            "suspicious": suspicious,
            "quarantined": quarantined,
            "detection_ready": size >= self.MIN_FLEET_SIZE,
        }

    def _agent_probability(self, rows: list[dict[str, Any]]) -> tuple[float, list[str]]:
        if not rows:
            return 0.0, []
        behavior = self._avg(rows, "behavior_drift", "drift", "drift_score")
        response = self._avg(rows, "response_inconsistency", "inconsistency")
        cost = self._avg(rows, "cost_anomaly", "cost_spike", "cost_risk")
        timing = self._avg(rows, "timing_anomaly", "latency_outlier", "latency_risk")
        tools = self._avg(rows, "tool_abuse", "tool_risk", "tool_anomaly")
        scores = {
            "behavior_drift": behavior,
            "response_inconsistency": response,
            "cost_anomaly": cost,
            "timing_anomaly": timing,
            "tool_abuse": tools,
        }
        probability = sum(scores.values()) / float(len(scores))
        matched = [name for name, value in scores.items() if value >= 0.6]
        return max(0.0, min(1.0, probability)), matched

    @staticmethod
    def _coerce_score(value: Any) -> float:
        if isinstance(value, bool):
            return 1.0 if value else 0.0
        try:
            return max(0.0, min(1.0, float(value)))
        except (TypeError, ValueError):
            return 0.0

    @classmethod
    def _avg(cls, rows: list[dict[str, Any]], *keys: str) -> float:
        vals: list[float] = []
        for row in rows:
            for key in keys:
                if key in row:
                    vals.append(cls._coerce_score(row.get(key)))
                    break
        if not vals:
            return 0.0
        return sum(vals) / float(len(vals))

    @staticmethod
    def _response_for_query(rows: list[dict[str, Any]], query: str) -> str:
        query_norm = str(query).strip().lower()
        for row in reversed(rows):
            candidate_query = str(row.get("query", "")).strip().lower()
            if query_norm and candidate_query and candidate_query != query_norm:
                continue
            for key in ("response", "response_text", "output"):
                value = row.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip().lower()
        return ""

    @staticmethod
    def _similarity_score(a: str, b: str) -> float:
        if not a and not b:
            return 1.0
        if not a or not b:
            return 0.0
        left = {token for token in a.split() if token}
        right = {token for token in b.split() if token}
        if not left or not right:
            return 0.0
        return len(left & right) / float(len(left | right))
