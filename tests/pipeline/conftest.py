"""Shared fixtures for pipeline tests."""

from __future__ import annotations

from typing import Any

import pytest

from orchesis.pipeline import (
    Identity,
    InputSnapshot,
    Phase,
    PhaseResult,
    Processed,
    RecordingHandle,
    RequestContext,
    Tracking,
)


def make_phase(
    name: str,
    *,
    after: tuple[str, ...] = (),
    before: tuple[str, ...] = (),
    appends_tracking: tuple[str, ...] = (),
    produces_hazards: tuple[str, ...] = (),
    execute_fn=None,
    can_skip_fn=None,
    timeout_seconds: float = 5.0,
) -> Phase:
    """Build a Phase subclass instance with the given declarative metadata."""

    async def _execute(self, ctx: RequestContext) -> PhaseResult:
        if execute_fn is not None:
            return await _maybe_await(execute_fn(self, ctx))
        return PhaseResult(status="pass")

    namespace: dict[str, Any] = {
        "name": name,
        "after": frozenset(after),
        "before": frozenset(before),
        "appends_tracking": frozenset(appends_tracking),
        "PRODUCES_HAZARDS": frozenset(produces_hazards),
        "timeout_seconds": timeout_seconds,
        "execute": _execute,
    }
    if can_skip_fn is not None:
        def _can_skip(self, ctx: RequestContext) -> bool:
            return can_skip_fn(self, ctx)
        namespace["can_skip"] = _can_skip

    cls = type(f"Phase_{name}", (Phase,), namespace)
    return cls()


async def _maybe_await(v: Any) -> Any:
    if hasattr(v, "__await__"):
        return await v
    return v


@pytest.fixture
def make_ctx():
    """Factory: build a minimal RequestContext for phase tests."""

    def _build(**overrides: Any) -> RequestContext:
        identity = Identity(
            request_id=overrides.pop("request_id", "r1"),
            session_id=overrides.pop("session_id", "s1"),
            agent_id=overrides.pop("agent_id", "a1"),
            customer_id=overrides.pop("customer_id", "c1"),
            tier=overrides.pop("tier", "lite"),
        )
        input_snap = InputSnapshot(
            raw_body=b"{}",
            original_messages=(),
            original_tools=(),
            requested_model=overrides.pop("model", "test-model"),
            requested_params={},
            provider_hint=None,
            headers={},
        )
        return RequestContext(
            id=identity,
            input=input_snap,
            processed=Processed(),
            tracking=Tracking(),
            recording=RecordingHandle(),
        )

    return _build
