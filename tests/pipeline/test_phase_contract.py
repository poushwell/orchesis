"""Tests for Phase / PhaseResult / ScopedTracking / ContractViolation."""

from __future__ import annotations

import pytest

from orchesis.pipeline import (
    ContractViolation,
    Phase,
    PhaseResult,
    ScopedTracking,
    Tracking,
)
from tests.pipeline.conftest import make_phase


# ---------------------------------------------------------------------------
# PhaseResult
# ---------------------------------------------------------------------------


class TestPhaseResult:
    def test_pass_default(self):
        r = PhaseResult(status="pass")
        assert r.status == "pass"
        assert r.reason is None
        assert r.details == {}

    def test_block_with_reason(self):
        r = PhaseResult(status="block", reason="rate limited")
        assert r.status == "block"
        assert r.reason == "rate limited"

    def test_retry_with_modifications(self):
        r = PhaseResult(
            status="retry",
            retry_after_phase="context",
            retry_modifications={"max_tokens": 1024},
        )
        assert r.retry_after_phase == "context"
        assert r.retry_modifications == {"max_tokens": 1024}

    def test_phase_result_frozen(self):
        r = PhaseResult(status="pass")
        with pytest.raises(AttributeError):
            r.status = "block"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# ScopedTracking enforcement
# ---------------------------------------------------------------------------


class TestScopedTrackingDecisions:
    def test_emits_when_declared(self):
        phase = make_phase("p1", appends_tracking=("decisions",))
        t = Tracking()
        scoped = ScopedTracking(t, phase)
        scoped.add_decision("pass", reason="ok")
        assert len(t.decisions) == 1
        assert t.decisions[0].phase_name == "p1"
        assert t.decisions[0].verdict == "pass"

    def test_rejects_when_not_declared(self):
        phase = make_phase("p1")  # no appends_tracking
        t = Tracking()
        scoped = ScopedTracking(t, phase)
        with pytest.raises(ContractViolation, match="decisions"):
            scoped.add_decision("pass")


class TestScopedTrackingDeviations:
    def test_emits_declared_hazard(self):
        phase = make_phase(
            "p2",
            appends_tracking=("deviations",),
            produces_hazards=("custom_hazard",),
        )
        t = Tracking()
        scoped = ScopedTracking(t, phase)
        scoped.add_deviation("custom_hazard", 0.5)
        assert len(t.deviations) == 1
        assert t.deviations[0].event_type == "custom_hazard"
        assert t.deviations[0].severity == 0.5

    def test_undeclared_hazard_rejected(self):
        phase = make_phase(
            "p2",
            appends_tracking=("deviations",),
            produces_hazards=("known",),
        )
        scoped = ScopedTracking(Tracking(), phase)
        with pytest.raises(ContractViolation, match="not in PRODUCES_HAZARDS"):
            scoped.add_deviation("unknown", 0.5)

    def test_severity_out_of_range(self):
        phase = make_phase(
            "p2",
            appends_tracking=("deviations",),
            produces_hazards=("h",),
        )
        scoped = ScopedTracking(Tracking(), phase)
        with pytest.raises(ContractViolation, match="severity"):
            scoped.add_deviation("h", 1.5)
        with pytest.raises(ContractViolation, match="severity"):
            scoped.add_deviation("h", -0.1)

    def test_deviations_not_declared(self):
        phase = make_phase("p2", produces_hazards=("h",))
        scoped = ScopedTracking(Tracking(), phase)
        with pytest.raises(ContractViolation, match="deviations"):
            scoped.add_deviation("h", 0.5)


class TestScopedTrackingMetricsAndTimings:
    def test_metric_prefixed_with_phase_name(self):
        phase = make_phase("p3", appends_tracking=("metrics",))
        t = Tracking()
        scoped = ScopedTracking(t, phase)
        scoped.set_metric("latency", 12.3)
        assert "p3.latency" in t.metrics
        assert t.metrics["p3.latency"] == 12.3

    def test_metric_not_declared(self):
        phase = make_phase("p3")
        scoped = ScopedTracking(Tracking(), phase)
        with pytest.raises(ContractViolation, match="metrics"):
            scoped.set_metric("x", 1.0)

    def test_timing_emit(self):
        phase = make_phase("p3", appends_tracking=("timings",))
        t = Tracking()
        scoped = ScopedTracking(t, phase)
        scoped.add_timing(1.0, 2.0)
        assert len(t.timings) == 1

    def test_timing_not_declared(self):
        phase = make_phase("p3")
        scoped = ScopedTracking(Tracking(), phase)
        with pytest.raises(ContractViolation, match="timings"):
            scoped.add_timing(1.0, 2.0)


# ---------------------------------------------------------------------------
# Phase subclass validation
# ---------------------------------------------------------------------------


class TestPhaseSubclassValidation:
    def test_concrete_without_name_raises(self):
        with pytest.raises(TypeError, match="must set ClassVar 'name'"):
            class _Concrete(Phase):
                async def execute(self, ctx):  # type: ignore[override]
                    return PhaseResult(status="pass")

    def test_valid_name(self):
        class _Good(Phase):
            name = "valid_name_123"

            async def execute(self, ctx):  # type: ignore[override]
                return PhaseResult(status="pass")

        assert _Good.name == "valid_name_123"

    def test_invalid_appends_tracking_kind(self):
        with pytest.raises(TypeError, match="not in"):
            class _Bad(Phase):
                name = "bad"
                appends_tracking = frozenset({"junk"})

                async def execute(self, ctx):  # type: ignore[override]
                    return PhaseResult(status="pass")
