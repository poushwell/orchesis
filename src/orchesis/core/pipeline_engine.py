"""Core pipeline helpers."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from orchesis.message_consistency import compute_iacs_full
from orchesis.behavior_sync import BehaviorSync
from orchesis.bandit_sampler import BanditSampler

ORCHESIS_FEATURES = {
    "behavior_transfer": False,  # activates at fleet >= 5
}


@dataclass
class PipelineState:
    """State carrier for pipeline phases."""

    iacs: float = 0.0
    iacs_breakdown: dict[str, Any] = field(default_factory=dict)


def phase9_iacs(messages: list[dict], state: PipelineState) -> dict[str, Any]:
    """Message-consistency stage."""
    iacs_result = compute_iacs_full(messages)
    state.iacs = float(iacs_result["iacs"])
    state.iacs_breakdown = dict(iacs_result)
    return iacs_result


@dataclass
class AgentState:
    """State container used by quality-check stage."""

    quality_score: float = 0.5
    zipf_alpha: float = 1.672
    causal_fan_out_variance: float = 0.0
    state_x: list[float] = field(default_factory=lambda: [0.5, 1.0, 1.0])
    observation_noise: float = 0.2

    psi: float = 0.5
    phase: str = "LIQUID"
    psi_history: list[float] = field(
        default_factory=list
    )  # internal: used for state transition tracking
    state_counter: int = 0  # internal: used for state transition tracking
    slope_window: list[float] = field(default_factory=list)
    state_P_full: list[float] = field(default_factory=lambda: [1, 0, 0, 0, 1, 0, 0, 0, 1])
    slope_alert: bool = False
    stale_crystal: bool = False
    slope_quality: float = 0.0
    ews_tau: float = 0.0
    state_lifecycle: str = "nominal"
    state_P_before: list[float] = field(default_factory=lambda: [1, 0, 0, 0, 1, 0, 0, 0, 1])
    update_magnitude: float = 0.0
    agent_id: str = ""
    task_type: str = "default"

    @property
    def cognitive_load(self) -> float:
        return self.state_x[0] if self.state_x else 0.5

    @property
    def context_quality(self) -> float:
        return self.state_x[1] if len(self.state_x) > 1 else 1.0

    @property
    def coherence(self) -> float:
        return self.state_x[2] if len(self.state_x) > 2 else 1.0


@dataclass
class InjectionResult:
    should_inject: bool
    injection_type: str = "none"
    reason: str = "adaptive"
    iv_proxy: float = 0.0


class Phase2_ContextQualityAssessment:
    """Quality stage core signals: slope, quality score, full 3x3 state update."""

    def __init__(self, config: dict | None = None):
        cfg = config or {}
        self._behavior_sync = BehaviorSync(cfg.get("behavior_sync", {}))

    def _compute_slope(self, state: AgentState, window: int = 8) -> float:
        """slope of quality score (w=8) - primary collapse detector."""
        history = getattr(state, "slope_window", [])
        if len(history) < 2:
            return 0.0
        n = min(len(history), window)
        xs = list(range(n))
        ys = list(history[-n:])
        x_mean = sum(xs) / n
        y_mean = sum(ys) / n
        num = sum((x - x_mean) * (y - y_mean) for x, y in zip(xs, ys))
        den = sum((x - x_mean) ** 2 for x in xs)
        return num / den if den > 0 else 0.0

    def _compute_psi(self, state: AgentState) -> float:
        """Quality score in [0,1]."""
        alpha = getattr(state, "zipf_alpha", 1.672)
        causal_var = getattr(state, "causal_fan_out_variance", 0.0)
        zci = max(0.0, min(1.0, (alpha - 1.0) / 2.0))
        gas_penalty = min(0.3, causal_var * 0.1)
        psi = max(0.0, zci - gas_penalty)
        return round(psi, 4)

    def _get_phase(self, psi: float) -> str:
        if psi >= 0.7:
            return "CRYSTAL"
        if psi >= 0.3:
            return "LIQUID"
        return "GAS"

    def _check_stale_crystal(self, state: AgentState, slope: float) -> bool:
        """Stale crystal: Psi high but quality_score declining."""
        psi = getattr(state, "psi", 0.5)
        return psi >= 0.7 and slope < -0.015

    def _gas_health(self, state: AgentState) -> str:
        """healthy vs pathological gas."""
        quality_score = getattr(state, "quality_score", 0.5)
        return "healthy" if quality_score > 0.4 else "pathological"

    def _state_full_update(self, state: AgentState, observation: dict) -> dict:
        """Full 3x3 state update for [load, quality, coherence]."""
        x = list(getattr(state, "state_x", [0.5, 1.0, 1.0]))
        P_flat = list(getattr(state, "state_P_full", [1, 0, 0, 0, 1, 0, 0, 0, 1]))
        Q = [0.01, 0, 0, 0, 0.01, 0, 0, 0, 0.01]
        R = getattr(state, "observation_noise", 0.2)
        P_pred = [P_flat[i] + Q[i] for i in range(9)]
        z = [
            observation.get("cognitive_load", x[0]),
            observation.get("context_quality", x[1]),
            observation.get("coherence", x[2]),
        ]
        y = [z[i] - x[i] for i in range(3)]
        K_diag = [P_pred[i * 3 + i] / (P_pred[i * 3 + i] + R) for i in range(3)]
        x_new = [x[i] + K_diag[i] * y[i] for i in range(3)]
        P_new = list(P_pred)
        for i in range(3):
            P_new[i * 3 + i] = (1 - K_diag[i]) * P_pred[i * 3 + i]
        return {
            "x": x_new,
            "P_full": P_new,
            "innovation": y,
            "update_magnitude": math.sqrt(sum(yi**2 for yi in y)),
        }

    def assess(self, state: AgentState, observation: dict[str, Any]) -> dict[str, Any]:
        """Run the quality-check stage and persist state outputs."""
        if "quality_score" in observation and isinstance(observation["quality_score"], int | float):
            state.quality_score = float(observation["quality_score"])
        state.slope_window.append(float(state.quality_score))
        if len(state.slope_window) > 64:
            state.slope_window = state.slope_window[-64:]

        slope = self._compute_slope(state)
        state.slope_quality = slope
        state.slope_alert = slope < -0.025

        state.psi = self._compute_psi(state)
        state.phase = self._get_phase(state.psi)
        state.psi_history.append(state.psi)
        if len(state.psi_history) > 64:
            state.psi_history = state.psi_history[-64:]
        state.stale_crystal = self._check_stale_crystal(state, slope)

        if state.phase == "GAS":
            state.state_counter += 1

        state.state_P_before = list(state.state_P_full)
        update = self._state_full_update(state, observation)
        state.state_x = list(update["x"])
        state.state_P_full = list(update["P_full"])
        state.update_magnitude = float(update["update_magnitude"])
        state.state_lifecycle = "updated"

        return {
            "slope_quality": slope,
            "slope_alert": bool(state.slope_alert),
            "psi": state.psi,
            "phase": state.phase,
            "stale_crystal": bool(state.stale_crystal),
            "gas_health": self._gas_health(state),
            "update": update,
        }

    def post_response(self, state: AgentState, result: dict[str, Any]) -> dict[str, Any]:
        """Post-response hook used by downstream phases."""
        if hasattr(self, "_behavior_sync_engine") and self._behavior_sync:
            self._behavior_sync.record_outcome(
                agent_id=getattr(state, "agent_id", "unknown"),
                outcome={
                    "quality_score": getattr(state, "quality_score", 0.5),
                    "psi": getattr(state, "psi", 0.5),
                    "decision": result.get("action", "unknown"),
                },
            )
        return result


class PipelineEngine:
    """Compact pipeline surface for phase-level integration hooks."""

    def __init__(self, config: dict | None = None):
        cfg = config or {}
        self._config = cfg
        self._phase2 = Phase2_ContextQualityAssessment(cfg)
        self._thompson_sampler = BanditSampler(cfg.get("bandit_sampler", {}))
        self._phases = [
            "phase2_assess",
            "phase3_pid",
            "phase7_injection",
            "phase9_iacs",
            "phase10_post_response",
        ]

    def _gas_health(self, state: AgentState) -> str:
        return self._phase2._gas_health(state)

    def _resolve_phase_slope(self, state: AgentState) -> float:
        """Resolve compression threshold based on phase + slope."""
        phase = getattr(state, "phase", "LIQUID")
        stale = getattr(state, "stale_crystal", False)
        slope_alert = getattr(state, "slope_alert", False)

        # Slope overrides crystal protection when stale.
        if slope_alert and stale:
            return 0.40  # STALE_CRYSTAL: compress like liquid

        thresholds = {
            "CRYSTAL": 0.65,  # healthy crystal: don't disturb
            "LIQUID": 0.40,  # standard
            "GAS_pathological": 0.30,  # aggressive compression
            "GAS_healthy": 0.55,  # don't disturb exploration
        }

        if phase == "CRYSTAL":
            return thresholds["CRYSTAL"]
        if phase == "GAS":
            gas_health = self._gas_health(state)
            return thresholds.get(f"GAS_{gas_health}", thresholds["GAS_pathological"])
        return thresholds["LIQUID"]

    def phase3_pid(self, state: AgentState) -> dict[str, Any]:
        """Controller snapshot with slope-first override signals."""
        slope_alert = bool(getattr(state, "slope_alert", False))

        # PRIMARY: slope detector.
        d_term = slope_alert  # True if slope < -0.025

        # SECONDARY: EWS tau for slow monotonic drift.
        ews_tau = float(getattr(state, "ews_tau", 0.0))
        slope_quality = float(getattr(state, "slope_quality", 0.0))
        slow_drift = abs(slope_quality) < 0.015 and ews_tau > 0.5

        return {
            "d_term": d_term,
            "ews_tau": ews_tau,
            "slow_drift": slow_drift,
            "compression_threshold": self._resolve_phase_slope(state),
        }

    def _get_injection_type(self, state: AgentState) -> str:
        phase = getattr(state, "phase", "LIQUID")
        stale = getattr(state, "stale_crystal", False)
        if phase == "CRYSTAL" and not stale:
            return "none"  # Hard NEVER: healthy crystal
        if phase == "CRYSTAL" and stale:
            return "thawing"  # Hard ALWAYS: stale crystal needs thawing
        if phase == "LIQUID":
            return "condensing"
        return "crystallizing"  # GAS

    def _compute_iv_proxy(self, state: AgentState, historical_delta: float, cost: float) -> float:
        """IV = historical_delta - cost + 0.15 × Tr(P_before - P_after)."""
        base_iv = float(historical_delta) - float(cost)

        # Update-driven uncertainty reduction.
        update_status = str(getattr(state, "state_lifecycle", "")).strip().lower()
        update_enabled = update_status in {"updated", "active", "enabled", "tracking"}
        if update_enabled:
            p_before = getattr(state, "state_P_before", [1, 0, 0, 0, 1, 0, 0, 0, 1])
            p_after = getattr(state, "state_P_full", [1, 0, 0, 0, 1, 0, 0, 0, 1])
            # Tr(P_before - P_after) = sum of diagonal differences.
            trace_delta = sum(
                float(p_before[i * 3 + i]) - float(p_after[i * 3 + i]) for i in range(3)
            )
            epistemic_value = 0.15 * trace_delta
            return base_iv + epistemic_value

        return base_iv

    def phase7_injection_decision(
        self,
        state: AgentState,
        *,
        agent_productive: bool = False,
        historical_delta: float = 0.0,
        cost: float = 0.0,
    ) -> InjectionResult:
        """Injection protocol with hard state-aware guards."""
        phase = getattr(state, "phase", "LIQUID")
        stale = getattr(state, "stale_crystal", False)

        # Hard NEVER: healthy crystal -> no injection.
        if phase == "CRYSTAL" and not stale:
            return InjectionResult(should_inject=False, reason="healthy_crystal_protected")

        # Hard ALWAYS: stale crystal -> thawing injection.
        if phase == "CRYSTAL" and stale:
            return InjectionResult(should_inject=True, injection_type="thawing")

        # Existing NEVER refined: productive agent in liquid phase.
        if agent_productive and phase == "LIQUID":
            return InjectionResult(should_inject=False, reason="productive_liquid")

        iv_proxy = self._compute_iv_proxy(state, historical_delta=historical_delta, cost=cost)
        return InjectionResult(
            should_inject=iv_proxy > 0.0,
            injection_type=self._get_injection_type(state),
            reason="adaptive",
            iv_proxy=iv_proxy,
        )

    def _weighted_bandit_update(self, state: AgentState, arm: str, reward: float) -> None:
        """Weighted Thompson Sampling update.

        weight = clamp(1.0 + update_magnitude_val, 0.5, 2.0)
        Larger prediction error = more informative observation = higher weight.
        """
        update_magnitude_val = float(getattr(state, "update_magnitude", 0.0))
        weight = max(0.5, min(2.0, 1.0 + update_magnitude_val))
        bounded_reward = max(0.0, min(1.0, float(reward)))

        # Weighted Beta distribution update.
        if bounded_reward > 0.5:
            # Success: add weight to alpha.
            self._thompson_sampler.update(
                arm=arm,
                task_type=getattr(state, "task_type", "unknown"),
                reward=max(0.0, min(1.0, bounded_reward * weight)),
            )
        else:
            # Failure: add weight to beta (failures).
            self._thompson_sampler.update(
                arm=arm,
                task_type=getattr(state, "task_type", "unknown"),
                reward=max(0.0, min(1.0, bounded_reward / weight)),
            )

    def post_response(self, state: AgentState, result: dict[str, Any]) -> dict[str, Any]:
        """Post-response updates: behavior-sync logging + weighted bandit."""
        out = self._phase2.post_response(state, result)
        arm = str(out.get("arm") or out.get("model") or "gpt-4o-mini")
        reward = float(out.get("reward", 0.5))
        self._weighted_bandit_update(state, arm=arm, reward=reward)
        return out
