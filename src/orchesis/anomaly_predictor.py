"""Predictive anomaly signals from recent telemetry trends."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


class AnomalyPredictor:
    """Predicts anomalies before they happen using trend analysis."""

    def __init__(self, config: dict | None = None):
        cfg = config or {}
        self.lookahead_requests = int(cfg.get("lookahead", 10))
        self.confidence_threshold = float(cfg.get("confidence", 0.7))
        self._history: dict[str, list[dict[str, Any]]] = {}

    def predict(self, recent_metrics: list[dict]) -> dict:
        signal_values = self._extract_signal_values(recent_metrics)
        trend = self.detect_trend(signal_values)
        predicted_type: str | None = None
        signals: list[str] = []
        confidence = 0.0
        predicted_in_requests: int | None = None

        if trend["trend"] == "increasing":
            confidence = min(0.98, 0.55 + float(trend["rate"]) * 2.0 + float(trend["volatility"]) * 0.4)
            signals.append("rising anomaly trend")
        elif trend["trend"] == "volatile":
            confidence = min(0.9, 0.45 + float(trend["volatility"]) * 0.6)
            signals.append("high volatility")
        elif trend["trend"] == "stable":
            confidence = 0.25
        else:
            confidence = 0.2

        if confidence >= self.confidence_threshold:
            avg = (sum(signal_values) / float(len(signal_values))) if signal_values else 0.0
            if avg >= 0.8:
                predicted_type = "security_spike"
            elif avg >= 0.55:
                predicted_type = "policy_violations"
            else:
                predicted_type = "latency_degradation"
            predicted_in_requests = max(1, int(self.lookahead_requests * max(0.1, (1.0 - confidence))))
            signals.append(f"predicted_type={predicted_type}")

        anomaly_likely = confidence >= self.confidence_threshold and predicted_type is not None
        recommendation = (
            "Increase monitoring and tighten controls."
            if anomaly_likely
            else "Continue normal monitoring; no immediate anomaly forecast."
        )
        return {
            "anomaly_likely": bool(anomaly_likely),
            "confidence": round(float(confidence), 3),
            "predicted_type": predicted_type,
            "predicted_in_requests": predicted_in_requests,
            "signals": signals,
            "recommendation": recommendation,
        }

    def detect_trend(self, values: list[float]) -> dict:
        if not isinstance(values, list) or len(values) < 2:
            return {"trend": "stable", "rate": 0.0, "volatility": 0.0}
        cleaned = [float(item) for item in values]
        n = len(cleaned)
        rate = (cleaned[-1] - cleaned[0]) / float(max(1, n - 1))
        mean = sum(cleaned) / float(n)
        variance = sum((item - mean) ** 2 for item in cleaned) / float(n)
        volatility = variance ** 0.5
        if volatility > 0.35:
            trend = "volatile"
        elif rate > 0.05:
            trend = "increasing"
        elif rate < -0.05:
            trend = "decreasing"
        else:
            trend = "stable"
        return {"trend": trend, "rate": round(rate, 4), "volatility": round(volatility, 4)}

    def early_warning(self, agent_id: str, decisions_log: list) -> dict:
        """EWS: early warning signal for context phase transitions."""
        rows = []
        for item in decisions_log if isinstance(decisions_log, list) else []:
            if getattr(item, "agent_id", None) is not None:
                current_agent = str(getattr(item, "agent_id", ""))
                snapshot = getattr(item, "state_snapshot", {})
            elif isinstance(item, dict):
                current_agent = str(item.get("agent_id", ""))
                snapshot = item.get("state_snapshot", {})
            else:
                continue
            if current_agent != str(agent_id):
                continue
            score = 0.0
            if isinstance(snapshot, dict):
                raw = snapshot.get("adaptive_anomaly_score", snapshot.get("anomaly_score", 0.0))
                try:
                    score = float(raw)
                except (TypeError, ValueError):
                    score = 0.0
                level = str(snapshot.get("context_budget_level", "normal"))
                if level in {"L1", "L2"}:
                    score = max(score, 0.8 if level == "L2" else 0.6)
            rows.append({"score": score})
        prediction = self.predict(rows)
        self._history.setdefault(str(agent_id), []).append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "agent_id": str(agent_id),
                **prediction,
            }
        )
        return prediction

    def get_predictions_history(self, agent_id: str) -> list[dict]:
        """Past predictions with accuracy tracking."""
        return list(self._history.get(str(agent_id), []))

    def record_prediction(self, agent_id: str, prediction: dict[str, Any]) -> None:
        entry = {"timestamp": datetime.now(timezone.utc).isoformat(), "agent_id": str(agent_id), **dict(prediction)}
        self._history.setdefault(str(agent_id), []).append(entry)

    def get_all_history(self) -> dict[str, list[dict[str, Any]]]:
        return {key: list(value) for key, value in self._history.items()}

    @staticmethod
    def _extract_signal_values(recent_metrics: list[dict]) -> list[float]:
        values: list[float] = []
        for item in recent_metrics if isinstance(recent_metrics, list) else []:
            if not isinstance(item, dict):
                continue
            for key in ("score", "anomaly_score", "risk_score", "value"):
                if key not in item:
                    continue
                try:
                    values.append(max(0.0, min(1.0, float(item.get(key, 0.0)))))
                    break
                except (TypeError, ValueError):
                    continue
        return values
