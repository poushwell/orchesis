"""Checkpoint 4 runtime integration tests.

Verifies that SigmaMonitor / BlindSpotDetector / ProviderAdapter / compression
+ canonicalize phases are actually invoked from the engine + proxy, not just
present as standalone modules.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from orchesis.phases import (
    CanonicalizePhase,
    CompressionDecodePhase,
    make_legacy_phase,
)
from orchesis.pipeline import (
    Identity,
    InputSnapshot,
    PhaseRegistry,
    PipelineEngine,
    Processed,
    RecordingHandle,
    RequestContext,
    Tracking,
)
from orchesis.sigma import SigmaMonitor
from orchesis.blind_spots import BlindSpotDetector
from orchesis.signed_journal import SignedJournal


def _ctx(**proc_params) -> RequestContext:
    proc = Processed()
    if proc_params:
        proc.params.update(proc_params)
    return RequestContext(
        id=Identity("r", "sess-cp4", "a", "c", "lite"),
        input=InputSnapshot(b"", (), (), "m", {}, None, {}),
        processed=proc,
        tracking=Tracking(),
        recording=RecordingHandle(),
    )


# ---------------------------------------------------------------------------
# Sigma monitor hooked into engine
# ---------------------------------------------------------------------------


class TestEngineSigmaHook:
    def test_sigma_observes_emitted_deviations(self):
        def emit_dev(self, ctx):
            ctx.tracking.add_deviation("tool_failure", 0.7)
            from orchesis.pipeline import PhaseResult
            return PhaseResult(status="pass")

        r = PhaseRegistry()
        phase = make_legacy_phase(
            "noisy",
            lambda c: True,
            appends_tracking=("timings", "deviations"),
        )
        # The factory doesn't accept produces_hazards yet; declare on the
        # class via a fresh subclass.
        type(phase).PRODUCES_HAZARDS = frozenset({"tool_failure"})
        # Override execute to emit a deviation.
        async def exe(self, ctx):
            ctx.tracking.add_deviation("tool_failure", 0.7)
            from orchesis.pipeline import PhaseResult
            return PhaseResult(status="pass")
        type(phase).execute = exe
        r.register(phase)
        r.reload()

        sm = SigmaMonitor()
        engine = PipelineEngine(r, sigma_monitor=sm)
        ctx = _ctx()
        asyncio.run(engine.process_one("noisy", ctx))
        # State estimate appears in processed.params after the hook ran.
        assert "sigma_short" in ctx.processed.params
        assert ctx.processed.params["sigma_short"] > 0.0

    def test_no_hook_no_sigma(self):
        # Engine without sigma_monitor doesn't populate sigma_short.
        r = PhaseRegistry()
        r.register(make_legacy_phase("p", lambda c: True))
        r.reload()
        engine = PipelineEngine(r)
        ctx = _ctx(_legacy_ctx=object())
        asyncio.run(engine.process_one("p", ctx))
        assert "sigma_short" not in ctx.processed.params


# ---------------------------------------------------------------------------
# Blind-spot detector hooked into engine
# ---------------------------------------------------------------------------


class TestEngineBlindSpotHook:
    def test_blind_spot_decision_stored(self):
        r = PhaseRegistry()
        r.register(make_legacy_phase("p", lambda c: True))
        r.reload()
        bd = BlindSpotDetector()
        engine = PipelineEngine(r, blind_spot_detector=bd)
        ctx = _ctx(
            _legacy_ctx=object(),
            confidence=0.95,
            sigma_short=0.85,
            is_incomplete=True,
        )
        ctx.processed.chain_length = 20
        ctx.processed.params["uncertainty_rate_recent"] = 0.05
        asyncio.run(engine.process_one("p", ctx))
        # At least one blind-spot pattern should fire.
        assert "blind_spot_severity" in ctx.processed.params
        assert ctx.processed.params["blind_spot_severity"] > 0.0
        assert "blind_spot_decision" in ctx.processed.params

    def test_no_hits_no_decision(self):
        r = PhaseRegistry()
        r.register(make_legacy_phase("p", lambda c: True))
        r.reload()
        bd = BlindSpotDetector()
        engine = PipelineEngine(r, blind_spot_detector=bd)
        ctx = _ctx(_legacy_ctx=object())
        asyncio.run(engine.process_one("p", ctx))
        assert "blind_spot_decision" not in ctx.processed.params


# ---------------------------------------------------------------------------
# Signed journal stamp_phase wired via engine
# ---------------------------------------------------------------------------


class TestEngineSignedJournalStamp:
    def test_phase_name_stamped_during_execute(self):
        from orchesis.signed_journal import CURRENT_PHASE
        seen_phases: list[str] = []

        async def exe(self, ctx):
            from orchesis.pipeline import PhaseResult
            seen_phases.append(CURRENT_PHASE.get() or "none")
            return PhaseResult(status="pass")

        r = PhaseRegistry()
        phase = make_legacy_phase("p_stamp", lambda c: True)
        type(phase).execute = exe
        r.register(phase)
        r.reload()

        j = SignedJournal()
        engine = PipelineEngine(r, signed_journal=j)
        ctx = _ctx()
        asyncio.run(engine.process_one("p_stamp", ctx))
        assert seen_phases == ["p_stamp"]


# ---------------------------------------------------------------------------
# Compression + canonicalize phases active in proxy
# ---------------------------------------------------------------------------


@pytest.fixture
def proxy_instance():
    from orchesis.proxy import HTTPProxyConfig, LLMHTTPProxy
    return LLMHTTPProxy(config=HTTPProxyConfig(host="127.0.0.1", port=0))


class TestCP4ProxyWiring:
    def test_sigma_monitor_present(self, proxy_instance):
        assert proxy_instance._sigma_monitor is not None

    def test_blind_spot_detector_present(self, proxy_instance):
        assert proxy_instance._blind_spot_detector is not None

    def test_signed_journal_disabled_by_default(self, proxy_instance):
        assert proxy_instance._signed_journal is None

    def test_compression_and_canonicalize_registered(self, proxy_instance):
        names = proxy_instance._phase_registry.current_graph.names
        assert "compression_decode" in names
        assert "canonicalize" in names

    def test_signed_journal_enabled_via_policy(self, tmp_path):
        from orchesis.proxy import HTTPProxyConfig, LLMHTTPProxy
        policy_path = tmp_path / "policy.yaml"
        policy_path.write_text(
            "signed_journal:\n"
            "  enabled: true\n"
            "  hmac_key: super-secret\n"
        )
        proxy = LLMHTTPProxy(
            config=HTTPProxyConfig(host="127.0.0.1", port=0),
            policy_path=str(policy_path),
        )
        assert proxy._signed_journal is not None
        assert proxy._signed_journal._hmac_key == b"super-secret"


# ---------------------------------------------------------------------------
# Provider adapter dispatch tag landed in proc_result
# ---------------------------------------------------------------------------


class TestProviderAdapterDispatch:
    def test_anthropic_model_tagged(self, proxy_instance):
        from orchesis.proxy import _RequestContext
        from unittest.mock import MagicMock
        legacy = _RequestContext(handler=MagicMock())
        legacy.body = {"model": "claude-3-5-sonnet"}
        legacy.parsed_req = type("P", (), {
            "content_text": None,
            "tool_calls": [],
            "model": "claude-3-5-sonnet",
            "provider": "anthropic",
        })()
        proxy_instance._phase_model_router(legacy)
        assert legacy.proc_result.get("provider_adapter") == "anthropic"

    def test_openai_model_tagged(self, proxy_instance):
        from orchesis.proxy import _RequestContext
        from unittest.mock import MagicMock
        legacy = _RequestContext(handler=MagicMock())
        legacy.body = {"model": "gpt-4o"}
        legacy.parsed_req = type("P", (), {
            "content_text": None,
            "tool_calls": [],
            "model": "gpt-4o",
            "provider": "openai",
        })()
        proxy_instance._phase_model_router(legacy)
        assert legacy.proc_result.get("provider_adapter") == "openai"

    def test_unknown_model_no_tag(self, proxy_instance):
        from orchesis.proxy import _RequestContext
        from unittest.mock import MagicMock
        legacy = _RequestContext(handler=MagicMock())
        legacy.body = {"model": "unknown-xyz"}
        legacy.parsed_req = type("P", (), {
            "content_text": None,
            "tool_calls": [],
            "model": "unknown-xyz",
            "provider": "",
        })()
        proxy_instance._phase_model_router(legacy)
        assert "provider_adapter" not in legacy.proc_result
