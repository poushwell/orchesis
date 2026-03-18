"""ML-lite cost forecasting with linear regression."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import math
from typing import Any


class CostForecaster:
    """Predicts future costs using linear regression on history."""

    def __init__(self, config: dict | None = None):
        cfg = config or {}
        self.history_days = int(cfg.get("history_days", 7))
        self.confidence_interval = float(cfg.get("confidence", 0.95))
        self._a = 0.0
        self._b = 0.0
        self._residual_std = 0.0
        self._n = 0
        self._fitted = False
        self._last_x = 0.0
        self._last_y = 0.0

    @staticmethod
    def _z_value(confidence: float) -> float:
        # No external deps: small lookup with practical default.
        if confidence >= 0.99:
            return 2.576
        if confidence >= 0.95:
            return 1.96
        if confidence >= 0.90:
            return 1.645
        return 1.282

    def fit(self, hourly_costs: list[dict]) -> None:
        """Fit model on hourly cost data."""
        points: list[tuple[float, float]] = []
        for idx, item in enumerate(hourly_costs):
            if not isinstance(item, dict):
                continue
            x_raw = item.get("hour_index", item.get("x", idx))
            y_raw = item.get("cost", item.get("cost_usd", item.get("value", 0.0)))
            try:
                x = float(x_raw)
                y = float(y_raw)
            except (TypeError, ValueError):
                continue
            points.append((x, y))

        self._n = len(points)
        if self._n == 0:
            self._a = 0.0
            self._b = 0.0
            self._residual_std = 0.0
            self._fitted = False
            self._last_x = 0.0
            self._last_y = 0.0
            return

        if self._n == 1:
            self._a = 0.0
            self._b = points[0][1]
            self._residual_std = 0.0
            self._fitted = True
            self._last_x = points[-1][0]
            self._last_y = points[-1][1]
            return

        xs = [p[0] for p in points]
        ys = [p[1] for p in points]
        x_mean = sum(xs) / self._n
        y_mean = sum(ys) / self._n
        var_x = sum((x - x_mean) ** 2 for x in xs)
        cov_xy = sum((x - x_mean) * (y - y_mean) for x, y in points)

        if var_x <= 0.0:
            self._a = 0.0
            self._b = y_mean
        else:
            self._a = cov_xy / var_x
            self._b = y_mean - self._a * x_mean

        residuals = [y - (self._a * x + self._b) for x, y in points]
        mse = sum(r * r for r in residuals) / max(1, self._n - 2)
        self._residual_std = math.sqrt(max(0.0, mse))
        self._fitted = True
        self._last_x = points[-1][0]
        self._last_y = points[-1][1]

    def predict(self, hours_ahead: int = 24) -> dict:
        if not self._fitted:
            return {
                "hours_ahead": int(hours_ahead),
                "predicted_cost": 0.0,
                "confidence_low": 0.0,
                "confidence_high": 0.0,
                "trend": "stable",
                "anomaly_detected": False,
            }

        horizon = max(1, int(hours_ahead))
        total = 0.0
        for step in range(1, horizon + 1):
            x = self._last_x + step
            total += max(0.0, self._a * x + self._b)

        z = self._z_value(self.confidence_interval)
        margin = z * self._residual_std * math.sqrt(float(horizon))
        low = max(0.0, total - margin)
        high = max(low, total + margin)

        slope = self._a
        if slope > 0.01:
            trend = "increasing"
        elif slope < -0.01:
            trend = "decreasing"
        else:
            trend = "stable"

        anomaly = bool(self._residual_std > 0.0 and abs(self._last_y - (self._a * self._last_x + self._b)) > (2.5 * self._residual_std))
        return {
            "hours_ahead": horizon,
            "predicted_cost": round(total, 6),
            "confidence_low": round(low, 6),
            "confidence_high": round(high, 6),
            "trend": trend,
            "anomaly_detected": anomaly,
        }

    def predict_monthly(self) -> dict:
        """30-day projection from current trend."""
        horizon = 24 * 30
        result = self.predict(hours_ahead=horizon)
        return {
            "hours_ahead": horizon,
            "predicted_monthly_cost": result["predicted_cost"],
            "confidence_low": result["confidence_low"],
            "confidence_high": result["confidence_high"],
            "trend": result["trend"],
            "anomaly_detected": result["anomaly_detected"],
        }

    def get_breakeven(self, monthly_budget: float) -> dict:
        """Predict when budget will be exhausted."""
        try:
            budget = float(monthly_budget)
        except (TypeError, ValueError):
            budget = 0.0
        if budget <= 0.0:
            return {"days_until_exhausted": None, "exhaustion_date": None, "safe": False}

        monthly = self.predict_monthly()
        projected = float(monthly.get("predicted_monthly_cost", 0.0) or 0.0)
        if projected <= 0.0:
            return {"days_until_exhausted": None, "exhaustion_date": None, "safe": True}
        if projected <= budget:
            return {"days_until_exhausted": None, "exhaustion_date": None, "safe": True}

        avg_daily = projected / 30.0
        if avg_daily <= 0.0:
            return {"days_until_exhausted": None, "exhaustion_date": None, "safe": True}
        days = budget / avg_daily
        exhaustion = datetime.now(timezone.utc) + timedelta(days=days)
        return {
            "days_until_exhausted": round(days, 4),
            "exhaustion_date": exhaustion.isoformat(),
            "safe": False,
        }
