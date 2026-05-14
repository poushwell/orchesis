"""Aggregated state monitoring for request streams.

Aggregates calibrated hazard signals into a per-session state estimate
using Noisy-OR composition, runs three parallel EWMAs over the event
stream, exposes the chain-length-aware threshold lookup, and emits
three independent detection alerts:

  Alert 1 — functional-ceiling threshold. Medium-window estimate
            compared against τ(L).
  Alert 2 — EWMA local-spike. Current event > μ_recent + k·s_recent.
  Alert 3 — CUSUM baseline drift. Bi-directional CUSUM detects
            sustained shifts in the average estimate.

Numerical constants are documented defaults — pending empirical
calibration on synthetic chains + first production batch. The
ThresholdResolver path is preserved by exposing each parameter as a
keyword arg or attribute (callers can hot-reload).
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Iterable


# ---------------------------------------------------------------------------
# Public reliability profile + chain length thresholds
# ---------------------------------------------------------------------------


ReliabilityProfile = str  # one of "permissive" / "balanced" / "strict" / "paranoid"


# Precomputed τ(L) lookup table per SPEC §1.5.4. Built with s = 0.08.
# Indexed: TAU_TABLE[profile][L] → threshold. Profile values are sparse
# anchors; intermediate L values use linear interpolation in the lookup.
TAU_TABLE: dict[ReliabilityProfile, dict[int, float]] = {
    "permissive": {1: 1.000, 3: 0.870, 5: 0.847, 10: 0.806, 20: 0.766,
                   50: 0.717, 100: 0.683, 200: 0.652},
    "balanced":   {1: 1.000, 3: 0.812, 5: 0.781, 10: 0.731, 20: 0.683,
                   50: 0.624, 100: 0.583, 200: 0.546},
    "strict":     {1: 1.000, 3: 0.755, 5: 0.717, 10: 0.658, 20: 0.602,
                   50: 0.532, 100: 0.486, 200: 0.443},
    "paranoid":   {1: 1.000, 3: 0.706, 5: 0.661, 10: 0.595, 20: 0.530,
                   50: 0.451, 100: 0.398, 200: 0.349},
}

# Floor: even at very long chains τ(L) doesn't drop below this.
TAU_FLOOR = 0.24


def tau_for_length(profile: ReliabilityProfile, chain_length: int) -> float:
    """Look up τ(L) for the given profile + chain length.

    Linear interpolation between table anchors; clamps below TAU_FLOOR for
    safety.
    """
    table = TAU_TABLE.get(profile)
    if table is None:
        raise ValueError(f"unknown reliability profile {profile!r}")
    if chain_length <= 1:
        return table[1]
    anchors = sorted(table)
    if chain_length >= anchors[-1]:
        return max(TAU_FLOOR, table[anchors[-1]])
    # Find the bracket and linearly interpolate.
    for lo, hi in zip(anchors, anchors[1:]):
        if lo <= chain_length <= hi:
            t_lo, t_hi = table[lo], table[hi]
            frac = (chain_length - lo) / (hi - lo)
            return max(TAU_FLOOR, t_lo + frac * (t_hi - t_lo))
    return max(TAU_FLOOR, table[anchors[-1]])


# ---------------------------------------------------------------------------
# Noisy-OR aggregation (§1.5.2)
# ---------------------------------------------------------------------------


def compute_sigma_step(hazards: Iterable[float]) -> float:
    """Aggregate per-signal calibrated hazards via Noisy-OR.

    Hazards are assumed already on the probability scale [0, 1]. The
    aggregation sees all contributed h_i — no per-signal threshold gating
    happens before this point (SPEC §1.5.2 architectural requirement).
    """
    product = 1.0
    for h in hazards:
        h_clipped = max(0.0, min(1.0, float(h)))
        product *= (1.0 - h_clipped)
    return 1.0 - product


def sigma_event(hazards: list[float]) -> float:
    """σ_event = max(σ_step, max(h_i)).

    The max backstop ensures a single screaming signal trips the
    aggregate even when the rest are quiet — defends against attempts
    to fragment one threat into many sub-threshold signals.
    """
    step = compute_sigma_step(hazards)
    return max(step, max(hazards) if hazards else 0.0)


# ---------------------------------------------------------------------------
# Per-session EWMA + CUSUM state (§1.5.3, §1.5.5)
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class SigmaState:
    session_id: str

    sigma_short: float = 0.0   # α = 0.3   (effective window ~5 steps)
    sigma_medium: float = 0.0  # α = 0.08  (~20 steps)
    sigma_long: float = 0.0    # α = 0.015 (~70 steps)

    mu_recent: float = 0.0     # EWMA of σ_event for local-spike baseline
    var_recent: float = 0.0    # EWMA of (σ - μ)² for local-spike deviation

    cusum_pos: float = 0.0     # bi-directional CUSUM accumulators
    cusum_neg: float = 0.0

    recent_steps: deque[float] = field(default_factory=lambda: deque(maxlen=1000))
    n_steps_observed: int = 0
    n_blocks: int = 0
    last_update_at: float = 0.0


@dataclass(frozen=True, slots=True)
class LayerAlerts:
    """Snapshot of which detection layers fired on the latest observation."""
    layer1_tau_exceeded: bool = False
    layer2_local_spike: bool = False
    layer3_cusum_drift: bool = False
    sigma_step: float = 0.0
    sigma_event: float = 0.0
    tau_value: float = 0.0


# ---------------------------------------------------------------------------
# SigmaMonitor — threadsafe, session-scoped state
# ---------------------------------------------------------------------------


class SigmaMonitor:
    """Tracks per-session σ across all active sessions.

    Memory cap: at most `max_sessions` retained; idle sessions older than
    `ttl_seconds` are evicted on demand. Thread-safe — every public method
    takes the internal lock.
    """

    ALPHA_SHORT = 0.3
    ALPHA_MEDIUM = 0.08
    ALPHA_LONG = 0.015

    # Alert 2: μ + k·s trigger
    ALPHA_RECENT = 0.3
    LAYER2_K = 2.5

    # Alert 3: CUSUM
    CUSUM_H = 5.0
    CUSUM_K = 0.5
    CUSUM_MU_TARGET = 0.5

    def __init__(self, max_sessions: int = 10_000, ttl_seconds: float = 1800.0) -> None:
        self._sessions: dict[str, SigmaState] = {}
        self._last_seen: dict[str, float] = {}
        self._lock = threading.Lock()
        self._max = int(max_sessions)
        self._ttl = float(ttl_seconds)

    # -- observation ------------------------------------------------------

    def observe_step(
        self,
        session_id: str,
        hazards: list[float],
        *,
        profile: ReliabilityProfile = "balanced",
        chain_length: int = 1,
    ) -> LayerAlerts:
        """Record one step's hazards + return which detection layers fired."""
        ev = sigma_event(hazards)
        step = compute_sigma_step(hazards)
        with self._lock:
            state = self._sessions.get(session_id)
            if state is None:
                self._evict_if_needed()
                state = SigmaState(session_id=session_id)
                self._sessions[session_id] = state
            state.sigma_short = self.ALPHA_SHORT * ev + (1 - self.ALPHA_SHORT) * state.sigma_short
            state.sigma_medium = self.ALPHA_MEDIUM * ev + (1 - self.ALPHA_MEDIUM) * state.sigma_medium
            state.sigma_long = self.ALPHA_LONG * ev + (1 - self.ALPHA_LONG) * state.sigma_long

            # Alert 2 spike check uses the PRIOR baseline so the current
            # event can stand out against it; update after.
            prior_mu = state.mu_recent
            prior_s = state.var_recent ** 0.5
            l2_candidate = (
                state.n_steps_observed > 3
                and ev > prior_mu + self.LAYER2_K * prior_s
            )

            # Now update the baseline EWMA + variance with the new event.
            delta = ev - state.mu_recent
            state.mu_recent = state.mu_recent + self.ALPHA_RECENT * delta
            state.var_recent = (1 - self.ALPHA_RECENT) * (state.var_recent + self.ALPHA_RECENT * delta * delta)

            # Alert 3 CUSUM
            state.cusum_pos = max(0.0, state.cusum_pos + (ev - self.CUSUM_MU_TARGET) - self.CUSUM_K)
            state.cusum_neg = max(0.0, state.cusum_neg - (ev - self.CUSUM_MU_TARGET) - self.CUSUM_K)

            state.recent_steps.append(ev)
            state.n_steps_observed += 1
            state.last_update_at = time.time()
            self._last_seen[session_id] = state.last_update_at

            tau = tau_for_length(profile, chain_length)
            l1 = state.sigma_medium > tau
            l2 = l2_candidate
            l3 = max(state.cusum_pos, state.cusum_neg) > self.CUSUM_H

            return LayerAlerts(
                layer1_tau_exceeded=l1,
                layer2_local_spike=l2,
                layer3_cusum_drift=l3,
                sigma_step=step,
                sigma_event=ev,
                tau_value=tau,
            )

    def reset_cusum(self, session_id: str) -> None:
        """Reset the CUSUM accumulators — call after intervention action
        or operator reset."""
        with self._lock:
            state = self._sessions.get(session_id)
            if state is not None:
                state.cusum_pos = 0.0
                state.cusum_neg = 0.0

    # -- introspection ----------------------------------------------------

    def current(self, session_id: str, layer: str = "short") -> float:
        with self._lock:
            state = self._sessions.get(session_id)
            if state is None:
                return 0.0
            try:
                return float(getattr(state, f"sigma_{layer}"))
            except AttributeError:
                raise ValueError(f"unknown σ layer {layer!r}")

    def snapshot(self, session_id: str) -> SigmaState | None:
        with self._lock:
            state = self._sessions.get(session_id)
            if state is None:
                return None
            # Return a copy so callers can read without lock.
            return SigmaState(
                session_id=state.session_id,
                sigma_short=state.sigma_short,
                sigma_medium=state.sigma_medium,
                sigma_long=state.sigma_long,
                mu_recent=state.mu_recent,
                var_recent=state.var_recent,
                cusum_pos=state.cusum_pos,
                cusum_neg=state.cusum_neg,
                recent_steps=deque(state.recent_steps, maxlen=state.recent_steps.maxlen),
                n_steps_observed=state.n_steps_observed,
                n_blocks=state.n_blocks,
                last_update_at=state.last_update_at,
            )

    def session_count(self) -> int:
        with self._lock:
            return len(self._sessions)

    def record_block(self, session_id: str) -> None:
        with self._lock:
            state = self._sessions.get(session_id)
            if state is not None:
                state.n_blocks += 1

    # -- maintenance ------------------------------------------------------

    def _evict_if_needed(self) -> None:
        """Caller holds the lock. Drop oldest idle sessions when full."""
        now = time.time()
        # First sweep: TTL-expired sessions.
        stale = [
            sid for sid, ts in self._last_seen.items()
            if now - ts > self._ttl
        ]
        for sid in stale:
            self._sessions.pop(sid, None)
            self._last_seen.pop(sid, None)
        if len(self._sessions) < self._max:
            return
        # Hard cap: drop the N oldest until under cap.
        ordered = sorted(self._last_seen.items(), key=lambda kv: kv[1])
        drop_count = len(self._sessions) - self._max + 1
        for sid, _ in ordered[:drop_count]:
            self._sessions.pop(sid, None)
            self._last_seen.pop(sid, None)
