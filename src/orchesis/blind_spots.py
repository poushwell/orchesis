"""Missing-uncertainty detector.

Cross-cutting mechanism that fires on patterns where an agent appears
confident but the surrounding evidence suggests it should not be. The
detector is *additive* to the rolling state aggregation: a fired
pattern emits a deviation event that feeds back into the state
estimator, so confident-but-degraded chains see their state estimate
rise organically. The intervention manager then decides what to do
(annotate, retry, halt) per the active reliability profile.

Four patterns implemented in v1:
  A — confidence + state-estimate divergence.
  B — incompleteness under confidence (schema-based).
  C — cross-component-consistency disagreement not acknowledged
      within N steps.
  D — sustained certainty in long chains.

Each pattern returns a hit object with severity ∈ [0, 1] or None.
Severities aggregate via Noisy-OR weighted by per-pattern reliability.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Mapping


# ---------------------------------------------------------------------------
# Confidence extraction (lexical, MVP per §1.7.1)
# ---------------------------------------------------------------------------


_CONFIDENT_PHRASES = frozenset({
    "definitely", "certainly", "obviously", "without doubt", "clearly",
    "i am sure", "i'm sure", "no question", "of course",
})

_HEDGING_PHRASES = frozenset({
    "might", "could be", "i think", "possibly", "maybe", "perhaps",
    "i believe", "i suspect", "i'm not sure", "potentially",
})


def extract_confidence(text: str) -> float:
    """Return a lexical confidence score ∈ [0, 1].

    Counts confident vs hedging phrase occurrences in the first 200 tokens.
    Sigmoid-normalized so totals saturate gracefully. 0.5 is the neutral
    midpoint when neither category dominates.
    """
    if not text:
        return 0.5
    head = " ".join(text.lower().split()[:200])
    confident_hits = sum(1 for p in _CONFIDENT_PHRASES if p in head)
    hedging_hits = sum(1 for p in _HEDGING_PHRASES if p in head)
    raw = confident_hits - hedging_hits  # positive → confident
    # Sigmoid with steepness 0.6 → ~0.85 at raw=2, ~0.95 at raw=4.
    import math
    return 1.0 / (1.0 + math.exp(-0.6 * raw))


# ---------------------------------------------------------------------------
# Pattern hits
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PatternHit:
    name: str
    severity: float          # [0, 1]
    weight: float            # reliability weight, [0, 1]
    details: Mapping[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Pattern detectors
# ---------------------------------------------------------------------------


def pattern_a_confidence_sigma_divergence(
    *,
    confidence_score: float,
    sigma_short: float,
    confidence_threshold: float = 0.7,
    sigma_threshold: float = 0.7,
) -> PatternHit | None:
    if confidence_score < confidence_threshold:
        return None
    if sigma_short < sigma_threshold:
        return None
    # Severity scales with how far above both thresholds we are.
    a = (confidence_score - confidence_threshold) / max(1e-9, 1.0 - confidence_threshold)
    b = (sigma_short - sigma_threshold) / max(1e-9, 1.0 - sigma_threshold)
    severity = max(0.0, min(1.0, a * b))
    return PatternHit(
        name="confidence_sigma_divergence",
        severity=severity,
        weight=0.7,  # lexical confidence is noisy
        details={
            "confidence": confidence_score,
            "sigma_short": sigma_short,
            "X_A": confidence_threshold,
            "Y_A": sigma_threshold,
        },
    )


def pattern_b_incompleteness_under_confidence(
    *,
    confidence_score: float,
    is_incomplete: bool,
    confidence_threshold: float = 0.65,
) -> PatternHit | None:
    if not is_incomplete:
        return None
    if confidence_score < confidence_threshold:
        return None
    return PatternHit(
        name="confident_incomplete",
        severity=confidence_score,
        weight=0.9,  # schema-based incompleteness is reliable
        details={
            "confidence": confidence_score,
            "incomplete": True,
            "X_B": confidence_threshold,
        },
    )


def pattern_c_consistency_disagreement_ignored(
    *,
    consistency_radius_at_step: float | None,
    acknowledged_within_steps: int | None,
    ack_window: int = 2,
) -> PatternHit | None:
    if consistency_radius_at_step is None or consistency_radius_at_step <= 0:
        return None
    if acknowledged_within_steps is not None and acknowledged_within_steps <= ack_window:
        return None
    severity = max(0.0, min(1.0, consistency_radius_at_step))
    return PatternHit(
        name="consistency_ignored",
        severity=severity,
        weight=0.8,
        details={
            "radius": consistency_radius_at_step,
            "ack_window": ack_window,
            "acknowledged_within": acknowledged_within_steps,
        },
    )


def pattern_d_sustained_certainty(
    *,
    chain_length: int,
    uncertainty_rate_recent: float,
    chain_threshold: int = 8,
    window_size: int = 5,
    uncertainty_threshold: float = 0.2,
) -> PatternHit | None:
    if chain_length < chain_threshold:
        return None
    if uncertainty_rate_recent >= uncertainty_threshold:
        return None
    severity = 1.0 - uncertainty_rate_recent
    return PatternHit(
        name="missing_humility",
        severity=max(0.0, min(1.0, severity)),
        weight=0.5,  # most prone to false positives
        details={
            "chain_length": chain_length,
            "uncertainty_rate": uncertainty_rate_recent,
            "N_D": chain_threshold,
            "M_D": window_size,
        },
    )


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


def aggregate_severity(hits: list[PatternHit]) -> float:
    """Noisy-OR over weighted per-pattern severities."""
    product = 1.0
    for h in hits:
        contribution = max(0.0, min(1.0, h.severity * h.weight))
        product *= (1.0 - contribution)
    return 1.0 - product


# ---------------------------------------------------------------------------
# Intervention ladder per reliability_profile (§1.7.3)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class InterventionLadder:
    log_below: float
    annotate_below: float
    consistency_check_below: float
    retry_below: float
    # severity ≥ retry_below routes to "halt".


_LADDERS: dict[str, InterventionLadder] = {
    "permissive": InterventionLadder(
        log_below=0.50, annotate_below=0.85, consistency_check_below=1.01, retry_below=1.01,
    ),
    "balanced": InterventionLadder(
        log_below=0.40, annotate_below=0.60, consistency_check_below=0.80, retry_below=1.01,
    ),
    "strict": InterventionLadder(
        log_below=0.25, annotate_below=0.40, consistency_check_below=0.65, retry_below=0.85,
    ),
    "paranoid": InterventionLadder(
        log_below=0.15, annotate_below=0.25, consistency_check_below=0.50, retry_below=0.75,
    ),
}


def decide_intervention(severity: float, profile: str) -> str:
    """Return one of: 'log', 'annotate', 'consistency_check', 'retry', 'halt'."""
    ladder = _LADDERS.get(profile)
    if ladder is None:
        raise ValueError(f"unknown reliability profile {profile!r}")
    if severity < ladder.log_below:
        return "log"
    if severity < ladder.annotate_below:
        return "annotate"
    if severity < ladder.consistency_check_below:
        return "consistency_check"
    if severity < ladder.retry_below:
        return "retry"
    return "halt"


# ---------------------------------------------------------------------------
# Top-level detector — wraps everything for proxy / engine consumption
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BlindSpotInputs:
    """Bundle of signals the detector needs each step."""
    confidence_score: float = 0.5
    sigma_short: float = 0.0
    sigma_medium: float = 0.0
    is_incomplete: bool = False
    consistency_radius_at_step: float | None = None
    acknowledged_within_steps: int | None = None
    chain_length: int = 0
    uncertainty_rate_recent: float = 1.0


@dataclass(frozen=True, slots=True)
class BlindSpotReport:
    aggregate_severity: float
    hits: tuple[PatternHit, ...]
    decision: str  # one of 'log' / 'annotate' / 'consistency_check' / 'retry' / 'halt'


class BlindSpotDetector:
    def __init__(self) -> None:
        pass

    def assess(
        self,
        inputs: BlindSpotInputs,
        profile: str = "balanced",
    ) -> BlindSpotReport:
        hits: list[PatternHit] = []
        a = pattern_a_confidence_sigma_divergence(
            confidence_score=inputs.confidence_score,
            sigma_short=inputs.sigma_short,
        )
        if a is not None:
            hits.append(a)
        b = pattern_b_incompleteness_under_confidence(
            confidence_score=inputs.confidence_score,
            is_incomplete=inputs.is_incomplete,
        )
        if b is not None:
            hits.append(b)
        c = pattern_c_consistency_disagreement_ignored(
            consistency_radius_at_step=inputs.consistency_radius_at_step,
            acknowledged_within_steps=inputs.acknowledged_within_steps,
        )
        if c is not None:
            hits.append(c)
        d = pattern_d_sustained_certainty(
            chain_length=inputs.chain_length,
            uncertainty_rate_recent=inputs.uncertainty_rate_recent,
        )
        if d is not None:
            hits.append(d)
        agg = aggregate_severity(hits)
        decision = decide_intervention(agg, profile)
        return BlindSpotReport(
            aggregate_severity=agg,
            hits=tuple(hits),
            decision=decision,
        )
