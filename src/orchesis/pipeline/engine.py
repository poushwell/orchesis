"""Pipeline engine.

Drives async phase execution + per-phase post-hooks:
  - aggregated state monitoring (`sigma`) — Noisy-OR over the
    deviations a phase emitted, plus the resulting layer alerts fed
    back into the same tracking journal so downstream phases see them.
  - missing-uncertainty detection (`blind_spots`) — assesses each phase
    boundary against four patterns; hits feed back as deviation events.
  - phase-id stamping for the signed tracking journal — every phase
    invocation wraps in `stamp_phase(name)` so journal.append(...) gets
    the right phase id even when called from inside the phase body.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from orchesis.pipeline.context import (
    PhaseTimings,
    RequestContext,
    Tracking,
)
from orchesis.pipeline.phase import (
    ContractViolation,
    Phase,
    PhaseResult,
    ScopedTracking,
)
from orchesis.pipeline.registry import PhaseRegistry


_PhaseTimings = PhaseTimings


class PipelineEngine:
    """Async pipeline driver with optional state + L7 hooks."""

    def __init__(
        self,
        registry: PhaseRegistry,
        *,
        sigma_monitor: Any | None = None,
        blind_spot_detector: Any | None = None,
        signed_journal: Any | None = None,
        default_profile: str = "balanced",
    ) -> None:
        self._registry = registry
        self._sigma = sigma_monitor
        self._blind = blind_spot_detector
        self._journal = signed_journal
        self._profile = default_profile

    async def process(self, ctx: RequestContext) -> list[PhaseResult]:
        graph = self._registry.acquire_for_request()
        results: list[PhaseResult] = []
        try:
            for phase in graph.phases:
                if phase.can_skip(ctx):
                    results.append(PhaseResult(status="skip", reason="phase opted out"))
                    continue
                result = await self._execute_with_hooks(phase, ctx)
                results.append(result)
                if result.status == "block":
                    break
        finally:
            self._registry.release(graph)
        return results

    async def process_one(self, phase_name: str, ctx: RequestContext) -> PhaseResult:
        """Run a single named phase from the current registry.

        Hybrid request path: the proxy invokes one migrated phase at a time
        while interleaving non-migrated legacy calls. Per-call refcount
        acquire/release ensures hot-reload correctness even across many
        process_one invocations within one request.
        """
        graph = self._registry.acquire_for_request()
        try:
            try:
                phase = graph.get(phase_name)
            except Exception as e:
                return PhaseResult(
                    status="block",
                    reason=f"unknown phase {phase_name!r}: {e}",
                )
            if phase.can_skip(ctx):
                return PhaseResult(status="skip", reason="phase opted out")
            return await self._execute_with_hooks(phase, ctx)
        finally:
            self._registry.release(graph)

    # ---- internal --------------------------------------------------------

    async def _execute_with_hooks(self, phase: Phase, ctx: RequestContext) -> PhaseResult:
        started_at = time.time()
        # Capture pre-phase tracking lengths so we can slice the deviations
        # this phase actually emitted.
        baseline_dev_count = len(ctx.tracking.deviations)
        try:
            result = await asyncio.wait_for(
                self._run_phase(phase, ctx),
                timeout=phase.timeout_seconds,
            )
        except asyncio.TimeoutError:
            result = PhaseResult(
                status="block",
                reason=f"phase {phase.name!r} timed out after {phase.timeout_seconds}s",
            )
        except ContractViolation as e:
            result = PhaseResult(
                status="block",
                reason=f"contract violation in phase {phase.name!r}: {e.detail}",
            )
        except Exception as e:
            result = PhaseResult(
                status="block",
                reason=f"phase {phase.name!r} raised {type(e).__name__}: {e}",
            )
        finished_at = time.time()
        if "timings" in phase.appends_tracking:
            ctx.tracking.add_timing(_PhaseTimings(
                phase_name=phase.name,
                started_at=started_at,
                finished_at=finished_at,
            ))
        # Run optional post-phase hooks. They may emit additional deviations.
        self._run_sigma_hook(phase, ctx, baseline_dev_count)
        self._run_blind_spot_hook(phase, ctx, result)
        return result

    async def _run_phase(self, phase: Phase, ctx: RequestContext) -> PhaseResult:
        original_tracking = ctx.tracking
        ctx.tracking = _TrackingProxy(  # type: ignore[assignment]
            original_tracking, ScopedTracking(original_tracking, phase)
        )
        # Stamp the current phase for signed-journal appends made inside.
        stamp = None
        if self._journal is not None:
            try:
                from orchesis.signed_journal import stamp_phase
                stamp = stamp_phase(phase.name)
                stamp.__enter__()
            except Exception:
                stamp = None
        try:
            return await phase.execute(ctx)
        finally:
            if stamp is not None:
                try:
                    stamp.__exit__(None, None, None)
                except Exception:
                    pass
            ctx.tracking = original_tracking  # type: ignore[assignment]

    def _run_sigma_hook(
        self,
        phase: Phase,
        ctx: RequestContext,
        baseline_dev_count: int,
    ) -> None:
        if self._sigma is None:
            return
        deviations = ctx.tracking.deviations
        new_devs = deviations[baseline_dev_count:]
        hazards = [d.severity for d in new_devs]
        if not hazards:
            return
        session_id = ctx.id.session_id or "default"
        chain_length = max(1, ctx.processed.chain_length or 1)
        profile = ctx.processed.params.get("reliability_profile") or self._profile
        try:
            alerts = self._sigma.observe_step(
                session_id, hazards,
                profile=profile,
                chain_length=chain_length,
            )
        except Exception:
            return
        # Stash the state estimate so L7 + downstream phases see it.
        ctx.processed.params["sigma_short"] = self._sigma.current(session_id, "short")
        ctx.processed.params["sigma_medium"] = self._sigma.current(session_id, "medium")
        ctx.processed.params["sigma_long"] = self._sigma.current(session_id, "long")
        ctx.processed.params["sigma_event"] = alerts.sigma_event
        # If any alert fired, emit a feedback deviation so the next phase's
        # state estimate sees the alert.
        if alerts.layer1_tau_exceeded or alerts.layer2_local_spike or alerts.layer3_cusum_drift:
            kind = (
                "state_ceiling_exceeded" if alerts.layer1_tau_exceeded
                else "state_local_spike" if alerts.layer2_local_spike
                else "state_baseline_drift"
            )
            ctx.recording.append(
                "state_alert",
                {
                    "phase": phase.name,
                    "kind": kind,
                    "sigma_event": alerts.sigma_event,
                    "tau": alerts.tau_value,
                },
            )

    def _run_blind_spot_hook(
        self,
        phase: Phase,
        ctx: RequestContext,
        result: PhaseResult,
    ) -> None:
        if self._blind is None:
            return
        # Build inputs from currently-known signals. Engine cannot extract
        # confidence from prose without a phase populating it; phases that
        # produce response content set `ctx.processed.params["confidence"]`.
        try:
            from orchesis.blind_spots import BlindSpotInputs
            sigma_short = float(ctx.processed.params.get("sigma_short", 0.0))
            sigma_medium = float(ctx.processed.params.get("sigma_medium", 0.0))
            confidence = float(ctx.processed.params.get("confidence", 0.5))
            inputs = BlindSpotInputs(
                confidence_score=confidence,
                sigma_short=sigma_short,
                sigma_medium=sigma_medium,
                is_incomplete=bool(ctx.processed.params.get("is_incomplete", False)),
                consistency_radius_at_step=ctx.processed.params.get(
                    "consistency_radius_at_step"
                ),
                acknowledged_within_steps=ctx.processed.params.get(
                    "acknowledged_within_steps"
                ),
                chain_length=ctx.processed.chain_length,
                uncertainty_rate_recent=float(
                    ctx.processed.params.get("uncertainty_rate_recent", 1.0)
                ),
            )
            profile = ctx.processed.params.get("reliability_profile") or self._profile
            report = self._blind.assess(inputs, profile=profile)
        except Exception:
            return
        if not report.hits:
            return
        ctx.processed.params["blind_spot_severity"] = report.aggregate_severity
        ctx.processed.params["blind_spot_decision"] = report.decision
        ctx.recording.append("blind_spot", {
            "phase": phase.name,
            "severity": report.aggregate_severity,
            "decision": report.decision,
            "hits": [h.name for h in report.hits],
        })


class _TrackingProxy:
    """Read-through proxy that adds scoped add_* methods used by phases.

    Phases that call `ctx.tracking.add_decision(...)` go through the scoped
    enforcement. Phases that read `ctx.tracking.deviations` etc. read the
    underlying journal directly.
    """

    __slots__ = ("_t", "_scoped")

    def __init__(self, tracking: Tracking, scoped: ScopedTracking):
        object.__setattr__(self, "_t", tracking)
        object.__setattr__(self, "_scoped", scoped)

    def add_decision(self, *args: Any, **kwargs: Any) -> None:
        self._scoped.add_decision(*args, **kwargs)

    def add_deviation(self, *args: Any, **kwargs: Any) -> None:
        self._scoped.add_deviation(*args, **kwargs)

    def add_timing(self, started_at: float, finished_at: float) -> None:
        self._scoped.add_timing(started_at, finished_at)

    def set_metric(self, name: str, value: float) -> None:
        self._scoped.set_metric(name, value)

    def __getattr__(self, item: str) -> Any:
        return getattr(self._t, item)
