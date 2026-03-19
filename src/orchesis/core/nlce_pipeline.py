"""NLCE core pipeline helpers."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from orchesis.discourse_coherence import compute_iacs_full
from orchesis.hgt_protocol import HGTProtocol
from orchesis.thompson_sampling import ThompsonSampler

ORCHESIS_FEATURES = {
    "hgt_transfer": False,  # activates at fleet >= 5
}


@dataclass
class NLCEPipelineState:
    """State carrier for NLCE pipeline phases."""

    iacs: float = 0.0
    iacs_breakdown: dict[str, Any] = field(default_factory=dict)


def phase9_iacs(messages: list[dict], state: NLCEPipelineState) -> dict[str, Any]:
    """Phase 9: discourse coherence (IACS) computation."""
    iacs_result = compute_iacs_full(messages)
    state.iacs = iacs_result["iacs"]
    state.iacs_breakdown = iacs_result
    return iacs_result


@dataclass
class AgentState:
    """State container used by NLCE Phase 2."""

    cognitive_load: float = 0.5
    context_quality: float = 1.0
    coherence: float = 1.0
    cqs: float = 0.5
    zipf_alpha: float = 1.672
    causal_fan_out_variance: float = 0.0
    kalman_x: list[float] = field(default_factory=lambda: [0.5, 1.0, 1.0])
    observation_noise: float = 0.2

    psi: float = 0.5
    phase: str = "LIQUID"
    psi_history: list[float] = field(default_factory=list)
    gas_counter: int = 0
    stale_psi_window: list[float] = field(default_factory=list)
    slope_cqs_window: list[float] = field(default_factory=list)
    kalman_P_full: list[float] = field(default_factory=lambda: [1, 0, 0, 0, 1, 0, 0, 0, 1])
    slope_alert: bool = False
    stale_crystal: bool = False


@dataclass
class InjectionResult:
    should_inject: bool
    injection_type: str = "none"
    reason: str = "adaptive"
    iv_proxy: float = 0.0


class Phase2_ContextQualityAssessment:
    """Phase 2 core signals: slope(CQS), crystallinity Psi, full 3x3 Kalman."""

    def __init__(self, config: dict | None = None):
        cfg = config or {}
        self._hgt = HGTProtocol(cfg.get("hgt_protocol", {}))

    def _compute_slope_cqs(self, state: AgentState, window: int = 8) -> float:
        """slope(CQS, w=8) - primary collapse detector."""
        history = getattr(state, "slope_cqs_window", [])
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
        """Context Crystallinity Psi in [0,1]."""
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

    def _check_stale_crystal(self, state: AgentState) -> bool:
        """Stale crystal: Psi high but CQS declining."""
        psi = getattr(state, "psi", 0.5)
        slope = self._compute_slope_cqs(state)
        return psi >= 0.7 and slope < -0.015

    def _gas_health(self, state: AgentState) -> str:
        """healthy vs pathological gas."""
        cqs = getattr(state, "cqs", 0.5)
        return "healthy" if cqs > 0.4 else "pathological"

    def _kalman_full_update(self, state: AgentState, observation: dict) -> dict:
        """Full 3x3 Kalman update for [cognitive_load, context_quality, coherence]."""
        x = list(getattr(state, "kalman_x", [0.5, 1.0, 1.0]))
        P_flat = list(getattr(state, "kalman_P_full", [1, 0, 0, 0, 1, 0, 0, 0, 1]))
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
            "innovation_norm": math.sqrt(sum(yi**2 for yi in y)),
        }

    def assess(self, state: AgentState, observation: dict[str, Any]) -> dict[str, Any]:
        """Run Phase 2 update and persist state outputs."""
        if "cqs" in observation and isinstance(observation["cqs"], int | float):
            state.cqs = float(observation["cqs"])
        state.slope_cqs_window.append(float(state.cqs))
        if len(state.slope_cqs_window) > 64:
            state.slope_cqs_window = state.slope_cqs_window[-64:]

        slope = self._compute_slope_cqs(state)
        state.slope_alert = slope < -0.025

        state.psi = self._compute_psi(state)
        state.phase = self._get_phase(state.psi)
        state.psi_history.append(state.psi)
        if len(state.psi_history) > 64:
            state.psi_history = state.psi_history[-64:]
        state.stale_crystal = self._check_stale_crystal(state)

        if state.phase == "GAS":
            state.gas_counter += 1

        kalman = self._kalman_full_update(state, observation)
        state.kalman_x = list(kalman["x"])
        state.kalman_P_full = list(kalman["P_full"])

        return {
            "slope_cqs": slope,
            "slope_alert": bool(state.slope_alert),
            "psi": state.psi,
            "phase": state.phase,
            "stale_crystal": bool(state.stale_crystal),
            "gas_health": self._gas_health(state),
            "kalman": kalman,
        }

    def post_response(self, state: AgentState, result: dict[str, Any]) -> dict[str, Any]:
        """Post-response hook used by downstream NLCE phases."""
        if hasattr(self, "_hgt") and self._hgt:
            self._hgt.record_outcome(
                agent_id=getattr(state, "agent_id", "unknown"),
                outcome={
                    "cqs": getattr(state, "cqs", 0.5),
                    "psi": getattr(state, "psi", 0.5),
                    "decision": result.get("action", "unknown"),
                },
            )
        return result


class NLCEPipeline:
    """Compact NLCE pipeline surface for phase-level integration hooks."""

    def __init__(self, config: dict | None = None):
        cfg = config or {}
        self._config = cfg
        self._phase2 = Phase2_ContextQualityAssessment(cfg)
        self._thompson_sampler = ThompsonSampler(cfg.get("thompson_sampling", {}))

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
        """Phase 3 PID snapshot with slope-first override signals."""
        slope_alert = bool(getattr(state, "slope_alert", False))

        # PRIMARY: slope detector.
        d_term = slope_alert  # True if slope < -0.025

        # SECONDARY: EWS tau for slow monotonic drift.
        ews_tau = float(getattr(state, "ews_tau", 0.0))
        slope_cqs = float(getattr(state, "slope_cqs", 0.0))
        slow_drift = abs(slope_cqs) < 0.015 and ews_tau > 0.5

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

        # Epistemic value from Kalman uncertainty reduction (H38 FEP).
        kalman_enabled = getattr(state, "kalman_state", False)
        if kalman_enabled:
            p_before = getattr(state, "kalman_P_before", [1, 0, 0, 0, 1, 0, 0, 0, 1])
            p_after = getattr(state, "kalman_P_full", [1, 0, 0, 0, 1, 0, 0, 0, 1])
            # Tr(P_before - P_after) = sum of diagonal differences.
            trace_delta = sum(float(p_before[i * 3 + i]) - float(p_after[i * 3 + i]) for i in range(3))
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
        """Phase 7 injection protocol with hard phase-aware guards."""
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

        weight = clamp(1.0 + innovation_norm, 0.5, 2.0)
        Larger prediction error = more informative observation = higher weight.
        """
        innovation_norm = float(getattr(state, "kalman_innovation_norm", 0.0))
        weight = max(0.5, min(2.0, 1.0 + innovation_norm))
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
        """Phase 10 post-response updates: HGT logging + weighted bandit."""
        out = self._phase2.post_response(state, result)
        arm = str(out.get("arm") or out.get("model") or "gpt-4o-mini")
        reward = float(out.get("reward", 0.5))
        self._weighted_bandit_update(state, arm=arm, reward=reward)
        return out
