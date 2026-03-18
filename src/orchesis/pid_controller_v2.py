"""PID Controller v2 with three-level early warning."""

from __future__ import annotations

from math import log, sqrt
import threading
from typing import Any


class PIDControllerV2:
    """Three-level early warning system for context management.

    Level 1 (EWS τ): Kendall τ > 0.5 -> warning 15 requests before failure
    Level 2 (alpha drift): Zipf exponent drift -> warning 8 requests before
    Level 3 (latency z-score): latency spike -> warning 3 requests before
    """

    def __init__(self, config: dict | None = None):
        cfg = config if isinstance(config, dict) else {}
        self.kp = float(cfg.get("kp", 1.0))  # proportional
        self.ki = float(cfg.get("ki", 0.1))  # integral
        self.kd = float(cfg.get("kd", 0.05))  # derivative
        self._error_history: list[float] = []
        self._integral = 0.0
        self._last_error = 0.0
        self._lock = threading.Lock()

    def update(self, current_value: float, setpoint: float) -> float:
        """PID update. Returns correction signal."""
        err = float(setpoint) - float(current_value)
        with self._lock:
            self._integral += err
            derivative = err - self._last_error
            self._last_error = err
            self._error_history.append(err)
            if len(self._error_history) > 1000:
                self._error_history = self._error_history[-1000:]
            output = (self.kp * err) + (self.ki * self._integral) + (self.kd * derivative)
        return float(output)

    @staticmethod
    def _kendall_tau(values: list[float]) -> float:
        n = len(values)
        if n < 2:
            return 0.0
        concordant = 0
        discordant = 0
        ties = 0
        for i in range(n):
            for j in range(i + 1, n):
                a = values[i]
                b = values[j]
                if a == b:
                    ties += 1
                elif a < b:
                    concordant += 1
                else:
                    discordant += 1
        denom = concordant + discordant + ties
        if denom == 0:
            return 0.0
        return float(concordant - discordant) / float(denom)

    def check_ews_tau(self, values: list[float]) -> dict:
        """Level 1: Kendall τ trend correlation."""
        seq = [float(v) for v in values if isinstance(v, int | float)]
        tau = self._kendall_tau(seq)
        warning = bool(tau > 0.5)
        return {
            "tau": round(float(tau), 6),
            "warning": warning,
            "requests_to_failure": 15 if warning else None,
        }

    @staticmethod
    def _zipf_alpha(token_frequencies: list[int]) -> float:
        freqs = [float(v) for v in token_frequencies if isinstance(v, int | float) and float(v) > 0]
        if len(freqs) < 2:
            return 1.0
        freqs.sort(reverse=True)
        xs = [log(float(i + 1)) for i in range(len(freqs))]
        ys = [log(v) for v in freqs]
        n = float(len(xs))
        sum_x = sum(xs)
        sum_y = sum(ys)
        sum_xx = sum(x * x for x in xs)
        sum_xy = sum(x * y for x, y in zip(xs, ys))
        denom = (n * sum_xx) - (sum_x * sum_x)
        if denom == 0:
            return 1.0
        slope = ((n * sum_xy) - (sum_x * sum_y)) / denom
        alpha = -slope
        return float(alpha)

    def check_zipf_drift(self, token_frequencies: list[int]) -> dict:
        """Level 2: Zipf exponent drift detection."""
        alpha = self._zipf_alpha(token_frequencies)
        baseline_alpha = 1.0
        drift = abs(alpha - baseline_alpha)
        warning = bool(drift >= 0.2)
        return {
            "alpha": round(float(alpha), 6),
            "baseline_alpha": baseline_alpha,
            "drift": round(float(drift), 6),
            "warning": warning,
        }

    def check_latency_zscore(self, latencies_ms: list[float]) -> dict:
        """Level 3: Latency z-score anomaly."""
        seq = [float(v) for v in latencies_ms if isinstance(v, int | float)]
        if len(seq) < 3:
            return {"zscore": 0.0, "warning": False, "spike_detected": False}
        baseline = seq[:-1]
        last = seq[-1]
        mean = sum(baseline) / float(len(baseline))
        variance = sum((x - mean) ** 2 for x in baseline) / float(len(baseline))
        std = sqrt(max(variance, 0.0))
        zscore = 0.0 if std <= 1e-9 else (last - mean) / std
        warning = bool(zscore >= 2.5)
        return {
            "zscore": round(float(zscore), 6),
            "warning": warning,
            "spike_detected": warning,
        }

    def get_warning_level(self, session_id: str, metrics: dict) -> dict:
        """Combined warning level from all three checks."""
        payload = metrics if isinstance(metrics, dict) else {}
        ews = self.check_ews_tau(payload.get("values", []) if isinstance(payload.get("values"), list) else [])
        zipf = self.check_zipf_drift(
            payload.get("token_frequencies", []) if isinstance(payload.get("token_frequencies"), list) else []
        )
        latency = self.check_latency_zscore(
            payload.get("latencies_ms", []) if isinstance(payload.get("latencies_ms"), list) else []
        )
        warnings: list[str] = []
        if ews["warning"]:
            warnings.append("ews_tau")
        if zipf["warning"]:
            warnings.append("zipf_drift")
        if latency["warning"]:
            warnings.append("latency_spike")

        if len(warnings) == 0:
            level = "green"
            action = "No action required; continue monitoring."
        elif len(warnings) == 1:
            level = "yellow"
            action = "Reduce context growth and monitor next 15 requests."
        elif len(warnings) == 2:
            level = "orange"
            action = "Apply context pruning and lower request concurrency."
        else:
            level = "red"
            action = "Trigger mitigation: compact context and throttle session traffic."

        _ = session_id  # reserved for future per-session state
        return {
            "level": level,
            "active_warnings": warnings,
            "recommended_action": action,
            "details": {"ews": ews, "zipf": zipf, "latency": latency},
        }

