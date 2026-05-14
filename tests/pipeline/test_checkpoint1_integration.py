"""Checkpoint 1 integration: proxy.py wired to PhaseRegistry + PipelineEngine.

Verifies SPEC §2.1 acceptance criteria:
  - OrchesisProxy boots with a populated PhaseRegistry containing
    the migrated FlowXrayRecordPhase.
  - _phase_flow_xray_record now delegates to the engine and continues
    to populate ctx.flow_node_id.
  - POST /api/v1/pipeline/reload swaps the registry snapshot atomically
    and reports the new version.
"""

from __future__ import annotations

import http.client
import json
import socket
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def proxy_instance(tmp_path: Path):
    """Construct an LLMHTTPProxy with no HTTP server started."""
    from orchesis.proxy import HTTPProxyConfig, LLMHTTPProxy

    cfg = HTTPProxyConfig(host="127.0.0.1", port=_free_port())
    proxy = LLMHTTPProxy(config=cfg)
    return proxy


class TestProxyRegistryWiring:
    def test_registry_instantiated(self, proxy_instance):
        assert proxy_instance._phase_registry is not None
        graph = proxy_instance._phase_registry.current_graph
        # FlowXrayRecordPhase was registered + reload was called.
        assert "flow_xray_record" in graph

    def test_engine_instantiated(self, proxy_instance):
        assert proxy_instance._pipeline_engine is not None

    def test_initial_version_advanced(self, proxy_instance):
        # __init__ calls reload() once, so version should be > 0.
        assert proxy_instance._phase_registry.current_version >= 1


class TestFlowXrayPhaseViaEngine:
    def test_records_node_id_when_analyzer_enabled(self, proxy_instance):
        from orchesis.flow_xray import FlowAnalyzer, FlowXRayConfig
        from orchesis.phases import FlowXrayRecordPhase
        from orchesis.proxy import _RequestContext

        # Default policy doesn't enable flow tracker. Inject one and re-register
        # the phase so the engine sees it.
        proxy_instance._flow_analyzer = FlowAnalyzer(FlowXRayConfig(enabled=True))
        proxy_instance._phase_registry.unregister("flow_xray_record")
        proxy_instance._phase_registry.register(
            FlowXrayRecordPhase(proxy_instance._flow_analyzer)
        )
        proxy_instance._phase_registry.reload()

        legacy = _RequestContext(handler=MagicMock())
        legacy.body = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "hi"}],
            "tools": [{"name": "search"}, "fetch"],
        }
        legacy.session_id = "sess-xyz"
        legacy.original_model = "gpt-4o"
        legacy.behavior_agent_id = "agent-1"

        result = proxy_instance._phase_flow_xray_record(legacy)
        assert result is True
        assert legacy.flow_node_id != ""

    def test_skipped_when_analyzer_none(self, proxy_instance):
        from orchesis.proxy import _RequestContext

        legacy = _RequestContext(handler=MagicMock())
        legacy.body = {"model": "x"}
        legacy.session_id = "s"

        # Disable analyzer at runtime.
        saved = proxy_instance._flow_analyzer
        proxy_instance._flow_analyzer = None
        try:
            assert proxy_instance._phase_flow_xray_record(legacy) is True
            assert legacy.flow_node_id == ""
        finally:
            proxy_instance._flow_analyzer = saved


class TestPipelineReloadHotSwap:
    def test_reload_increments_version(self, proxy_instance):
        before = proxy_instance._phase_registry.current_version
        new_v = proxy_instance._phase_registry.reload()
        assert new_v > before

    def test_reload_preserves_phases(self, proxy_instance):
        proxy_instance._phase_registry.reload()
        names = proxy_instance._phase_registry.current_graph.names
        assert "flow_xray_record" in names

    def test_reload_handler_returns_status(self, proxy_instance):
        # Capture _send_json output to verify response shape.
        handler = MagicMock()
        captured: dict = {}

        def fake_send_json(h, status, payload):
            captured["status"] = status
            captured["payload"] = payload

        proxy_instance._send_json = fake_send_json  # type: ignore[method-assign]
        proxy_instance._handle_pipeline_reload(handler)
        assert captured["status"] == 200
        assert captured["payload"]["status"] == "reloaded"
        assert captured["payload"]["phase_count"] >= 1
        assert "version" in captured["payload"]
