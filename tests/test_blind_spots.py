"""Tests for L7 BlindSpotDetector (SPEC §1.7)."""

from __future__ import annotations

import pytest

from orchesis.blind_spots import (
    BlindSpotDetector,
    BlindSpotInputs,
    aggregate_severity,
    decide_intervention,
    extract_confidence,
    pattern_a_confidence_sigma_divergence,
    pattern_b_incompleteness_under_confidence,
    pattern_c_consistency_disagreement_ignored,
    pattern_d_sustained_certainty,
)


# ---------------------------------------------------------------------------
# Confidence extraction
# ---------------------------------------------------------------------------


class TestConfidenceExtraction:
    def test_empty_returns_midpoint(self):
        assert extract_confidence("") == 0.5

    def test_confident_phrases_push_up(self):
        v = extract_confidence("I am sure this is correct. Definitely yes, obviously.")
        assert v > 0.7

    def test_hedging_phrases_push_down(self):
        v = extract_confidence("Maybe this works. I think it could be right but I'm not sure.")
        assert v < 0.3

    def test_balanced_stays_near_midpoint(self):
        # One confident + one hedging — net zero.
        v = extract_confidence("I am sure this might work.")
        assert 0.4 < v < 0.6


# ---------------------------------------------------------------------------
# Pattern A
# ---------------------------------------------------------------------------


class TestPatternA:
    def test_below_both_thresholds(self):
        assert pattern_a_confidence_sigma_divergence(
            confidence_score=0.4, sigma_short=0.3
        ) is None

    def test_only_confidence_above(self):
        assert pattern_a_confidence_sigma_divergence(
            confidence_score=0.9, sigma_short=0.3
        ) is None

    def test_only_sigma_above(self):
        assert pattern_a_confidence_sigma_divergence(
            confidence_score=0.4, sigma_short=0.9
        ) is None

    def test_both_above_fires(self):
        hit = pattern_a_confidence_sigma_divergence(
            confidence_score=0.9, sigma_short=0.9
        )
        assert hit is not None
        assert hit.severity > 0.0

    def test_severity_scales_with_extremity(self):
        mild = pattern_a_confidence_sigma_divergence(
            confidence_score=0.71, sigma_short=0.71
        )
        extreme = pattern_a_confidence_sigma_divergence(
            confidence_score=0.99, sigma_short=0.99
        )
        assert mild.severity < extreme.severity


# ---------------------------------------------------------------------------
# Pattern B
# ---------------------------------------------------------------------------


class TestPatternB:
    def test_no_hit_if_complete(self):
        assert pattern_b_incompleteness_under_confidence(
            confidence_score=0.95, is_incomplete=False
        ) is None

    def test_no_hit_if_low_confidence(self):
        assert pattern_b_incompleteness_under_confidence(
            confidence_score=0.4, is_incomplete=True
        ) is None

    def test_fires_on_incomplete_with_high_confidence(self):
        hit = pattern_b_incompleteness_under_confidence(
            confidence_score=0.85, is_incomplete=True
        )
        assert hit is not None
        assert hit.severity == 0.85


# ---------------------------------------------------------------------------
# Pattern C
# ---------------------------------------------------------------------------


class TestPatternC:
    def test_no_hit_when_no_consistency_radius(self):
        assert pattern_c_consistency_disagreement_ignored(
            consistency_radius_at_step=None, acknowledged_within_steps=None
        ) is None

    def test_no_hit_when_radius_zero(self):
        assert pattern_c_consistency_disagreement_ignored(
            consistency_radius_at_step=0.0, acknowledged_within_steps=None
        ) is None

    def test_no_hit_when_acknowledged_in_window(self):
        assert pattern_c_consistency_disagreement_ignored(
            consistency_radius_at_step=0.5, acknowledged_within_steps=1, ack_window=2
        ) is None

    def test_fires_when_ignored(self):
        hit = pattern_c_consistency_disagreement_ignored(
            consistency_radius_at_step=0.5, acknowledged_within_steps=None
        )
        assert hit is not None
        assert hit.severity == 0.5

    def test_fires_when_acknowledged_too_late(self):
        hit = pattern_c_consistency_disagreement_ignored(
            consistency_radius_at_step=0.3, acknowledged_within_steps=5, ack_window=2
        )
        assert hit is not None


# ---------------------------------------------------------------------------
# Pattern D
# ---------------------------------------------------------------------------


class TestPatternD:
    def test_no_hit_short_chain(self):
        assert pattern_d_sustained_certainty(
            chain_length=5, uncertainty_rate_recent=0.0
        ) is None

    def test_no_hit_high_uncertainty(self):
        assert pattern_d_sustained_certainty(
            chain_length=20, uncertainty_rate_recent=0.5
        ) is None

    def test_fires_long_chain_low_uncertainty(self):
        hit = pattern_d_sustained_certainty(
            chain_length=20, uncertainty_rate_recent=0.05
        )
        assert hit is not None
        assert hit.severity > 0.9


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


class TestAggregation:
    def test_empty_severity_zero(self):
        assert aggregate_severity([]) == 0.0

    def test_single_hit_weighted_severity(self):
        from orchesis.blind_spots import PatternHit
        hits = [PatternHit(name="a", severity=0.5, weight=0.7)]
        # 1 - (1 - 0.5*0.7) = 0.35
        assert aggregate_severity(hits) == pytest.approx(0.35)

    def test_multiple_hits_noisy_or(self):
        from orchesis.blind_spots import PatternHit
        hits = [
            PatternHit(name="a", severity=0.5, weight=1.0),
            PatternHit(name="b", severity=0.5, weight=1.0),
        ]
        # 1 - (1-0.5)*(1-0.5) = 0.75
        assert aggregate_severity(hits) == pytest.approx(0.75)


# ---------------------------------------------------------------------------
# Intervention ladder
# ---------------------------------------------------------------------------


class TestIntervention:
    def test_permissive_only_logs_below_50(self):
        assert decide_intervention(0.1, "permissive") == "log"
        assert decide_intervention(0.4, "permissive") == "log"
        assert decide_intervention(0.55, "permissive") == "annotate"
        assert decide_intervention(0.9, "permissive") == "consistency_check"

    def test_balanced_retry_at_high(self):
        # Per SPEC §1.7.3 balanced caps at retry; no halt rule.
        assert decide_intervention(0.85, "balanced") == "retry"
        assert decide_intervention(0.99, "balanced") == "retry"

    def test_strict_escalates_faster(self):
        assert decide_intervention(0.5, "strict") == "consistency_check"
        assert decide_intervention(0.7, "strict") == "retry"
        assert decide_intervention(0.9, "strict") == "halt"

    def test_paranoid_strictest(self):
        assert decide_intervention(0.3, "paranoid") == "consistency_check"
        assert decide_intervention(0.6, "paranoid") == "retry"
        assert decide_intervention(0.8, "paranoid") == "halt"

    def test_unknown_profile_raises(self):
        with pytest.raises(ValueError, match="unknown reliability profile"):
            decide_intervention(0.5, "nope")


# ---------------------------------------------------------------------------
# Detector facade
# ---------------------------------------------------------------------------


class TestDetectorFacade:
    def test_clean_inputs_log_only(self):
        d = BlindSpotDetector()
        report = d.assess(BlindSpotInputs(), profile="balanced")
        assert report.aggregate_severity == 0.0
        assert report.hits == ()
        assert report.decision == "log"

    def test_high_signal_combination_escalates(self):
        d = BlindSpotDetector()
        report = d.assess(
            BlindSpotInputs(
                confidence_score=0.95,
                sigma_short=0.85,
                is_incomplete=True,
                consistency_radius_at_step=0.4,
                chain_length=15,
                uncertainty_rate_recent=0.05,
            ),
            profile="strict",
        )
        assert report.aggregate_severity > 0.8
        assert len(report.hits) >= 2
        assert report.decision in ("retry", "halt")
