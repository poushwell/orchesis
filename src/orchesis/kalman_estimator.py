"""Kalman-based latent state estimation for sessions."""

from __future__ import annotations

import threading
from typing import Any


class KalmanStateEstimator:
    """Latent agent state estimation using Kalman filter.

    State vector: [cognitive_load, context_quality, coherence]
    Stdlib only - no numpy, pure Python Kalman.
    NLCE Layer 2 implementation.
    """

    STATE_DIMS = ["cognitive_load", "context_quality", "coherence"]

    def __init__(self, config: dict | None = None):
        cfg = config if isinstance(config, dict) else {}
        self.process_noise = float(cfg.get("process_noise", 0.1))
        self.observation_noise = float(cfg.get("observation_noise", 0.2))
        self._states: dict[str, dict[str, float]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
        return max(lo, min(hi, float(value)))

    @staticmethod
    def _as_float(value: Any, default: float = 0.0) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return float(default)

    def initialize(self, session_id: str) -> dict:
        """Initialize state for new session."""
        state = self._default_state()
        with self._lock:
            self._states[str(session_id)] = dict(state)
        return dict(state)

    @staticmethod
    def _default_state() -> dict[str, float]:
        return {
            "cognitive_load": 0.5,
            "context_quality": 1.0,
            "coherence": 1.0,
            "uncertainty": 1.0,
        }

    def _ensure_state(self, session_id: str) -> dict[str, float]:
        sid = str(session_id)
        state = self._states.get(sid)
        if not isinstance(state, dict):
            state = self._default_state()
            self._states[sid] = dict(state)
        return dict(state)

    def predict(self, session_id: str) -> dict:
        """Kalman predict step - project state forward."""
        sid = str(session_id)
        with self._lock:
            state = self._ensure_state(sid)
            state["uncertainty"] = max(1e-6, float(state.get("uncertainty", 1.0)) + self.process_noise)
            self._states[sid] = state
            return dict(state)

    def _observation_vector(self, observation: dict[str, Any]) -> dict[str, float]:
        obs = observation if isinstance(observation, dict) else {}
        tokens_used = max(0.0, self._as_float(obs.get("tokens_used"), 0.0))
        response_quality = self._clamp(self._as_float(obs.get("response_quality"), 0.7))
        latency_ms = max(0.0, self._as_float(obs.get("latency_ms"), 0.0))

        # Tokens and latency raise load; quality reduces perceived load.
        token_pressure = self._clamp(tokens_used / 8000.0)
        latency_pressure = self._clamp(latency_ms / 3000.0)
        cognitive_load = self._clamp((token_pressure * 0.6) + (latency_pressure * 0.4))

        context_quality = self._clamp(response_quality)
        coherence = self._clamp((response_quality * 0.8) + ((1.0 - latency_pressure) * 0.2))
        return {
            "cognitive_load": cognitive_load,
            "context_quality": context_quality,
            "coherence": coherence,
        }

    def update(self, session_id: str, observation: dict) -> dict:
        """Kalman update step - incorporate new observation.
        observation: {tokens_used, response_quality, latency_ms}
        """
        sid = str(session_id)
        with self._lock:
            state = self._ensure_state(sid)
            p = max(1e-6, float(state.get("uncertainty", 1.0)))
            r = max(1e-6, float(self.observation_noise))
            k = p / (p + r)
            z = self._observation_vector(observation if isinstance(observation, dict) else {})
            for dim in self.STATE_DIMS:
                x_prev = self._clamp(self._as_float(state.get(dim), 0.5))
                state[dim] = self._clamp(x_prev + (k * (z[dim] - x_prev)))
            state["uncertainty"] = max(1e-6, (1.0 - k) * p)
            self._states[sid] = state
            return dict(state)

    def get_state(self, session_id: str) -> dict:
        """Current estimated state."""
        sid = str(session_id)
        with self._lock:
            state = self._states.get(sid)
            if not isinstance(state, dict):
                state = self._default_state()
                self._states[sid] = dict(state)
            return dict(state)

    def get_alert_level(self, session_id: str) -> str:
        """Returns green|yellow|orange|red based on state."""
        state = self.get_state(session_id)
        load = self._as_float(state.get("cognitive_load"), 0.5)
        quality = self._as_float(state.get("context_quality"), 1.0)
        coherence = self._as_float(state.get("coherence"), 1.0)
        weakest = min(quality, coherence)
        if load >= 0.9 or weakest <= 0.25:
            return "red"
        if load >= 0.75 or weakest <= 0.45:
            return "orange"
        if load >= 0.6 or weakest <= 0.65:
            return "yellow"
        return "green"

    def get_all_sessions(self) -> list[dict]:
        """All tracked sessions with states."""
        with self._lock:
            sessions = sorted(self._states.keys())
            out: list[dict[str, Any]] = []
            for sid in sessions:
                row = dict(self._states.get(sid, {}))
                row["session_id"] = sid
                out.append(row)
            return out
