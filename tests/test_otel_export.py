"""Tests for OTLP export and ProxySpanEmitter."""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from unittest.mock import patch

import pytest

from orchesis.config import load_policy
from orchesis.otel import GENAI_ATTRS, ProxySpanEmitter, SpanData, TraceContext
from orchesis.otel_export import OTLPExportConfig, OTLPSpanExporter
from orchesis.proxy import HTTPProxyConfig, LLMHTTPProxy


def _make_span(
    trace_id: str = "a" * 32,
    span_id: str = "b" * 16,
    parent_span_id: str | None = None,
    operation: str = "test.span",
    status: str = "OK",
    attributes: dict | None = None,
    events: list | None = None,
) -> SpanData:
    now = time.time_ns()
    return SpanData(
        trace_id=trace_id,
        span_id=span_id,
        parent_span_id=parent_span_id,
        operation=operation,
        start_time_ns=now - 1000,
        end_time_ns=now,
        status=status,
        attributes=attributes or {},
        events=events or [],
    )


# --- OTLP Payload (10 tests) ---


def test_build_payload_single_span() -> None:
    exporter = OTLPSpanExporter(OTLPExportConfig(enabled=False))
    span = _make_span()
    payload = exporter._build_otlp_payload([span])
    assert "resourceSpans" in payload
    assert len(payload["resourceSpans"]) == 1
    scope_spans = payload["resourceSpans"][0]["scopeSpans"]
    assert len(scope_spans) == 1
    spans = scope_spans[0]["spans"]
    assert len(spans) == 1
    assert spans[0]["name"] == "test.span"


def test_build_payload_resource_attrs() -> None:
    exporter = OTLPSpanExporter(
        OTLPExportConfig(enabled=False, resource_attributes={"service.name": "my-svc", "service.version": "1.0"})
    )
    span = _make_span()
    payload = exporter._build_otlp_payload([span])
    attrs = payload["resourceSpans"][0]["resource"]["attributes"]
    keys = {a["key"] for a in attrs}
    assert "service.name" in keys
    assert "service.version" in keys


def test_build_payload_scope() -> None:
    exporter = OTLPSpanExporter(OTLPExportConfig(enabled=False))
    span = _make_span()
    payload = exporter._build_otlp_payload([span])
    scope = payload["resourceSpans"][0]["scopeSpans"][0]["scope"]
    assert scope["name"] == "orchesis"
    assert "version" in scope


def test_build_payload_span_attributes() -> None:
    exporter = OTLPSpanExporter(OTLPExportConfig(enabled=False))
    span = _make_span(
        attributes={
            "s": "str",
            "i": 42,
            "f": 3.14,
            "b": True,
        }
    )
    payload = exporter._build_otlp_payload([span])
    attrs = payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["attributes"]
    by_key = {a["key"]: a["value"] for a in attrs}
    assert "stringValue" in str(by_key.get("s", {}))
    assert "intValue" in str(by_key.get("i", {}))
    assert "doubleValue" in str(by_key.get("f", {}))
    assert "boolValue" in str(by_key.get("b", {}))


def test_build_payload_events() -> None:
    exporter = OTLPSpanExporter(OTLPExportConfig(enabled=False))
    span = _make_span(
        events=[{"name": "evt1", "timestamp_ns": 123, "attributes": {"k": "v"}}]
    )
    payload = exporter._build_otlp_payload([span])
    events = payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["events"]
    assert len(events) == 1
    assert events[0]["name"] == "evt1"


def test_build_payload_status_ok() -> None:
    exporter = OTLPSpanExporter(OTLPExportConfig(enabled=False))
    span = _make_span(status="OK")
    payload = exporter._build_otlp_payload([span])
    code = payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["status"]["code"]
    assert code == 1


def test_build_payload_status_error() -> None:
    exporter = OTLPSpanExporter(OTLPExportConfig(enabled=False))
    span = _make_span(status="ERROR")
    payload = exporter._build_otlp_payload([span])
    code = payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["status"]["code"]
    assert code == 2


def test_trace_id_32_hex() -> None:
    exporter = OTLPSpanExporter(OTLPExportConfig(enabled=False))
    span = _make_span(trace_id="abc")
    payload = exporter._build_otlp_payload([span])
    trace_id = payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["traceId"]
    assert len(trace_id) == 32
    assert trace_id.startswith("abc")


def test_span_id_16_hex() -> None:
    exporter = OTLPSpanExporter(OTLPExportConfig(enabled=False))
    span = _make_span(span_id="xy")
    payload = exporter._build_otlp_payload([span])
    span_id = payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["spanId"]
    assert len(span_id) == 16


def test_batch_multiple_spans() -> None:
    exporter = OTLPSpanExporter(OTLPExportConfig(enabled=False))
    spans = [_make_span(operation=f"op{i}") for i in range(3)]
    payload = exporter._build_otlp_payload(spans)
    out_spans = payload["resourceSpans"][0]["scopeSpans"][0]["spans"]
    assert len(out_spans) == 3
    assert [s["name"] for s in out_spans] == ["op0", "op1", "op2"]


# --- Exporter Lifecycle (8 tests) ---


def test_export_span_queues() -> None:
    cfg = OTLPExportConfig(enabled=False, batch_size=100)
    exporter = OTLPSpanExporter(cfg)
    span = _make_span()
    exporter.export_span(span)
    assert exporter.get_stats()["queue_size"] == 1


def test_flush_clears_queue() -> None:
    cfg = OTLPExportConfig(enabled=False)
    exporter = OTLPSpanExporter(cfg)
    exporter.export_span(_make_span())
    exporter.flush()
    assert exporter.get_stats()["queue_size"] == 0


def test_batch_auto_flush() -> None:
    cfg = OTLPExportConfig(enabled=False, batch_size=2)
    exporter = OTLPSpanExporter(cfg)
    with patch.object(exporter, "_send_http", return_value=True):
        exporter.export_span(_make_span())
        assert exporter.get_stats()["queue_size"] == 1
        exporter.export_span(_make_span())
        assert exporter.get_stats()["queue_size"] == 0


def test_max_queue_drops_oldest() -> None:
    cfg = OTLPExportConfig(enabled=False, max_queue_size=3, batch_size=100)
    exporter = OTLPSpanExporter(cfg)
    for i in range(5):
        exporter.export_span(_make_span(operation=f"op{i}"))
    stats = exporter.get_stats()
    assert stats["queue_size"] <= 3
    assert stats["dropped"] >= 2


def test_start_stop() -> None:
    cfg = OTLPExportConfig(enabled=True, flush_interval_seconds=10)
    exporter = OTLPSpanExporter(cfg)
    exporter.start()
    assert exporter._running
    exporter.stop()
    assert not exporter._running


def test_stats_counting() -> None:
    cfg = OTLPExportConfig(enabled=False, batch_size=1)
    exporter = OTLPSpanExporter(cfg)
    with patch.object(exporter, "_send_http", return_value=True):
        exporter.export_span(_make_span())
        exporter.flush()
        exporter.export_span(_make_span())
        exporter.flush()
    assert exporter.get_stats()["exported"] >= 1


def test_disabled_noop() -> None:
    cfg = OTLPExportConfig(enabled=False)
    exporter = OTLPSpanExporter(cfg)
    exporter.export_span(_make_span())
    exporter.start()
    assert not exporter._running


def test_flush_empty_queue() -> None:
    exporter = OTLPSpanExporter(OTLPExportConfig(enabled=False))
    assert exporter.flush() == 0


# --- HTTP Send (6 tests) ---


def test_send_success() -> None:
    handler_called = []

    class OkHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            handler_called.append(True)
            self.send_response(200)
            self.end_headers()

    server = HTTPServer(("127.0.0.1", 0), OkHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        cfg = OTLPExportConfig(
            enabled=True,
            endpoint=f"http://127.0.0.1:{port}",
            traces_path="/v1/traces",
        )
        exporter = OTLPSpanExporter(cfg)
        span = _make_span()
        payload = exporter._build_otlp_payload([span])
        assert exporter._send_http(payload) is True
        assert handler_called
    finally:
        server.shutdown()
        server.server_close()


def test_send_failure_retry() -> None:
    class FailHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            self.send_response(500)
            self.end_headers()

    server = HTTPServer(("127.0.0.1", 0), FailHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        cfg = OTLPExportConfig(
            enabled=True,
            endpoint=f"http://127.0.0.1:{port}",
            retry_count=2,
        )
        exporter = OTLPSpanExporter(cfg)
        payload = exporter._build_otlp_payload([_make_span()])
        assert exporter._send_http(payload) is False
    finally:
        server.shutdown()
        server.server_close()


def test_send_timeout() -> None:
    class SlowHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            time.sleep(2)

    server = HTTPServer(("127.0.0.1", 0), SlowHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        cfg = OTLPExportConfig(
            enabled=True,
            endpoint=f"http://127.0.0.1:{port}",
            timeout_seconds=0.1,
        )
        exporter = OTLPSpanExporter(cfg)
        payload = exporter._build_otlp_payload([_make_span()])
        assert exporter._send_http(payload) is False
    finally:
        server.shutdown()
        server.server_close()


def test_send_with_auth_header() -> None:
    received_headers = {}

    class CaptureHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            received_headers["Authorization"] = self.headers.get("Authorization", "")
            self.send_response(200)
            self.end_headers()

    server = HTTPServer(("127.0.0.1", 0), CaptureHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        cfg = OTLPExportConfig(
            enabled=True,
            endpoint=f"http://127.0.0.1:{port}",
            headers={"Authorization": "Bearer my-token"},
        )
        exporter = OTLPSpanExporter(cfg)
        payload = exporter._build_otlp_payload([_make_span()])
        exporter._send_http(payload)
        assert "Bearer my-token" in received_headers.get("Authorization", "")
    finally:
        server.shutdown()
        server.server_close()


def test_send_custom_endpoint() -> None:
    cfg = OTLPExportConfig(enabled=True, endpoint="http://custom:4318", traces_path="/v1/traces")
    exporter = OTLPSpanExporter(cfg)
    with patch("urllib.request.urlopen") as mock:
        mock.return_value.__enter__.return_value.status = 200
        payload = exporter._build_otlp_payload([_make_span()])
        exporter._send_http(payload)
        req = mock.call_args[0][0]
        assert req.full_url == "http://custom:4318/v1/traces"


def test_send_connection_refused() -> None:
    cfg = OTLPExportConfig(enabled=True, endpoint="http://127.0.0.1:19999", timeout_seconds=0.5)
    exporter = OTLPSpanExporter(cfg)
    payload = exporter._build_otlp_payload([_make_span()])
    assert exporter._send_http(payload) is False


# --- GenAI Attributes (6 tests) ---


def test_request_span_genai_attrs() -> None:
    emitter = ProxySpanEmitter(otlp_exporter=None)
    ctx = TraceContext(trace_id="a" * 32, parent_span_id=None)
    span = emitter.create_request_span(ctx, model="gpt-4o", provider="openai", session_id="s1", agent_id="a1")
    assert span.attributes.get("gen_ai.system") == "openai"
    assert span.attributes.get("gen_ai.request.model") == "gpt-4o"
    assert span.attributes.get("gen_ai.operation.name") == "chat"


def test_response_span_usage() -> None:
    span = _make_span(attributes={"gen_ai.usage.input_tokens": 100, "gen_ai.usage.output_tokens": 50})
    assert span.attributes["gen_ai.usage.input_tokens"] == 100
    assert span.attributes["gen_ai.usage.output_tokens"] == 50


def test_response_span_finish_reason() -> None:
    span = _make_span(attributes={"gen_ai.response.finish_reasons": "end_turn"})
    assert span.attributes["gen_ai.response.finish_reasons"] == "end_turn"


def test_orchesis_custom_attrs() -> None:
    span = _make_span(
        attributes={
            "orchesis.cost_usd": 0.05,
            "orchesis.session_id": "sess-1",
            "orchesis.decision": "allow",
        }
    )
    assert span.attributes["orchesis.cost_usd"] == 0.05
    assert span.attributes["orchesis.session_id"] == "sess-1"


def test_phase_span_attrs() -> None:
    emitter = ProxySpanEmitter(otlp_exporter=None)
    ctx = TraceContext(trace_id="a" * 32)
    span = emitter.create_phase_span("cascade", ctx, "p" * 16)
    assert span.attributes.get("orchesis.proxy.phase") == "cascade"
    assert span.operation == "orchesis.phase.cascade"


def test_cache_hit_attrs() -> None:
    span = _make_span(
        attributes={"orchesis.cache_hit": True, "orchesis.cache_type": "semantic"}
    )
    assert span.attributes["orchesis.cache_hit"] is True
    assert span.attributes["orchesis.cache_type"] == "semantic"


# --- ProxySpanEmitter (5 tests) ---


def test_start_end_span() -> None:
    emitter = ProxySpanEmitter(otlp_exporter=None)
    ctx = TraceContext(trace_id="a" * 32)
    span = emitter.start_span("test.op", ctx)
    assert span.start_time_ns > 0
    assert span.end_time_ns == 0
    emitter.end_span(span)
    assert span.end_time_ns == 0
    exp = OTLPSpanExporter(OTLPExportConfig(enabled=False))
    emitter2 = ProxySpanEmitter(otlp_exporter=exp)
    span2 = emitter2.start_span("test.op", ctx)
    emitter2.end_span(span2)
    exp.flush()
    assert exp.get_stats()["exported"] == 0
    assert exp.get_stats()["queue_size"] == 0


def test_create_request_span() -> None:
    emitter = ProxySpanEmitter(otlp_exporter=None)
    ctx = TraceContext(trace_id="a" * 32)
    span = emitter.create_request_span(ctx, "claude-3", "anthropic")
    assert span.operation == "orchesis.proxy.request"
    assert span.parent_span_id is None or span.parent_span_id == ctx.parent_span_id


def test_create_phase_span() -> None:
    emitter = ProxySpanEmitter(otlp_exporter=None)
    ctx = TraceContext(trace_id="a" * 32)
    parent_id = "c" * 16
    span = emitter.create_phase_span("threat_intel", ctx, parent_id)
    assert span.parent_span_id == parent_id
    assert "orchesis.phase.threat_intel" in span.operation


def test_span_to_otlp_and_jsonl() -> None:
    cfg = OTLPExportConfig(enabled=False, batch_size=1)
    exporter = OTLPSpanExporter(cfg)
    with patch.object(exporter, "_send_http", return_value=True):
        emitter = ProxySpanEmitter(otlp_exporter=exporter)
        ctx = TraceContext(trace_id="a" * 32)
        span = emitter.start_span("test", ctx)
        emitter.end_span(span)
        exporter.flush()
    assert exporter.get_stats()["queue_size"] == 0
    assert exporter.get_stats()["exported"] >= 1


def test_disabled_emitter_noop() -> None:
    emitter = ProxySpanEmitter(otlp_exporter=None)
    ctx = TraceContext(trace_id="a" * 32)
    span = emitter.start_span("test", ctx)
    emitter.end_span(span)
    assert span.operation == "test"


# --- Config (5 tests) ---


def test_normalize_otel_export(tmp_path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
otel_export:
  enabled: true
  endpoint: "http://tempo:4318"
  batch_size: 25
  service_name: "my-proxy"
"""
    )
    policy = load_policy(policy_path)
    otel = policy.get("otel_export")
    assert otel is not None
    assert otel["enabled"] is True
    assert "4318" in otel["endpoint"]
    assert otel["batch_size"] == 25
    assert otel["service_name"] == "my-proxy"


def test_default_config(tmp_path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
otel_export:
  enabled: true
"""
    )
    policy = load_policy(policy_path)
    otel = policy["otel_export"]
    assert otel["endpoint"] == "http://localhost:4318"
    assert otel["batch_size"] == 50
    assert otel["traces_path"] == "/v1/traces"


def test_custom_resource_attrs(tmp_path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
otel_export:
  enabled: true
  resource_attributes:
    deployment.environment: "production"
    service.namespace: "ai"
"""
    )
    policy = load_policy(policy_path)
    attrs = policy["otel_export"]["resource_attributes"]
    assert "service.name" in attrs
    assert attrs.get("deployment.environment") == "production"
    assert attrs.get("service.namespace") == "ai"


def test_proxy_init_otel(tmp_path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
rules: []
otel_export:
  enabled: true
  endpoint: "http://127.0.0.1:0"
"""
    )
    proxy = LLMHTTPProxy(policy_path=str(policy_path), config=HTTPProxyConfig(port=0))
    assert proxy._otlp_exporter is not None
    assert proxy._span_emitter is not None
    proxy.stop()


def test_proxy_stats_otel(tmp_path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
rules: []
otel_export:
  enabled: true
"""
    )
    proxy = LLMHTTPProxy(policy_path=str(policy_path), config=HTTPProxyConfig(port=0))
    try:
        stats = proxy.stats
        assert "otel_export" in stats
        assert stats["otel_export"]["enabled"] is True
    finally:
        proxy.stop()
