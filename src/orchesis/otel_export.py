"""OTLP HTTP/JSON span and metrics exporter using stdlib only."""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from orchesis.otel import SpanData


@dataclass
class OTLPExportConfig:
    """Configuration for OTLP export."""

    enabled: bool = False
    endpoint: str = "http://localhost:4318"
    traces_path: str = "/v1/traces"
    metrics_path: str = "/v1/metrics"
    headers: dict[str, str] = field(default_factory=dict)
    timeout_seconds: float = 10.0
    batch_size: int = 50
    flush_interval_seconds: float = 5.0
    max_queue_size: int = 2000
    retry_count: int = 2
    resource_attributes: dict[str, str] = field(
        default_factory=lambda: {
            "service.name": "orchesis-proxy",
            "service.version": "0.8.0",
        }
    )


class OTLPSpanExporter:
    """
    Batched OTLP HTTP/JSON span exporter.

    Sends spans to any OpenTelemetry-compatible backend:
    Grafana Tempo, Jaeger, Datadog, Honeycomb, etc.

    Uses stdlib urllib — no opentelemetry-sdk dependency.
    Thread-safe with background flush.
    """

    def __init__(self, config: OTLPExportConfig | None = None) -> None:
        self._config = config or OTLPExportConfig()
        self._lock = threading.Lock()
        self._queue: deque[SpanData] = deque(maxlen=self._config.max_queue_size)
        self._flush_thread: threading.Thread | None = None
        self._running = False
        self._exported: int = 0
        self._failed: int = 0
        self._dropped: int = 0

    def start(self) -> None:
        """Start background flush thread."""
        if self._running or not self._config.enabled:
            return
        self._running = True
        self._flush_thread = threading.Thread(
            target=self._flush_loop, daemon=True, name="orchesis-otlp-flush"
        )
        self._flush_thread.start()

    def stop(self) -> None:
        """Stop background flush and export remaining spans."""
        self._running = False
        if self._flush_thread and self._flush_thread.is_alive():
            self._flush_thread.join(timeout=self._config.timeout_seconds)
        self.flush()

    def export_span(self, span: SpanData) -> None:
        """Add span to export queue. Non-blocking."""
        with self._lock:
            if len(self._queue) >= self._config.max_queue_size:
                self._dropped += 1
            self._queue.append(span)
            if len(self._queue) >= self._config.batch_size:
                self._flush_batch()

    def flush(self) -> int:
        """Export all queued spans. Returns count exported."""
        with self._lock:
            return self._flush_batch()

    def _flush_loop(self) -> None:
        """Background thread: flush periodically."""
        while self._running:
            time.sleep(self._config.flush_interval_seconds)
            with self._lock:
                if self._queue:
                    self._flush_batch()

    def _flush_batch(self) -> int:
        """Export current queue as OTLP batch. Must hold lock."""
        if not self._queue:
            return 0
        batch = list(self._queue)
        self._queue.clear()
        payload = self._build_otlp_payload(batch)
        success = self._send_http(payload)
        if success:
            self._exported += len(batch)
        else:
            self._failed += len(batch)
        return len(batch)

    def _build_otlp_payload(self, spans: list[SpanData]) -> dict[str, Any]:
        """
        Build OTLP JSON payload following the spec:
        https://opentelemetry.io/docs/specs/otlp/#otlphttp
        """
        resource_attrs = [
            {"key": k, "value": {"stringValue": str(v)}}
            for k, v in self._config.resource_attributes.items()
        ]
        otlp_spans = []
        for span in spans:
            otlp_attrs = []
            for key, value in span.attributes.items():
                if isinstance(value, bool):
                    otlp_attrs.append({"key": key, "value": {"boolValue": value}})
                elif isinstance(value, int):
                    otlp_attrs.append({"key": key, "value": {"intValue": str(value)}})
                elif isinstance(value, float):
                    otlp_attrs.append({"key": key, "value": {"doubleValue": value}})
                else:
                    otlp_attrs.append({"key": key, "value": {"stringValue": str(value)}})
            otlp_events = []
            for evt in span.events:
                evt_attrs = []
                for ek, ev in (evt.get("attributes") or {}).items():
                    if isinstance(ev, bool):
                        evt_attrs.append({"key": ek, "value": {"boolValue": ev}})
                    elif isinstance(ev, int):
                        evt_attrs.append({"key": ek, "value": {"intValue": str(ev)}})
                    else:
                        evt_attrs.append({"key": ek, "value": {"stringValue": str(ev)}})
                otlp_events.append({
                    "name": evt.get("name", ""),
                    "timeUnixNano": str(evt.get("timestamp_ns", 0)),
                    "attributes": evt_attrs,
                })
            status_code = 1 if span.status == "OK" else 2
            trace_id = span.trace_id.ljust(32, "0")[:32]
            span_id = span.span_id.ljust(16, "0")[:16]
            parent_span_id = (
                (span.parent_span_id or "").ljust(16, "0")[:16]
                if span.parent_span_id
                else ""
            )
            otlp_spans.append({
                "traceId": trace_id,
                "spanId": span_id,
                "parentSpanId": parent_span_id,
                "name": span.operation,
                "kind": 2,
                "startTimeUnixNano": str(span.start_time_ns),
                "endTimeUnixNano": str(span.end_time_ns),
                "attributes": otlp_attrs,
                "events": otlp_events,
                "status": {"code": status_code, "message": span.status},
            })
        return {
            "resourceSpans": [{
                "resource": {"attributes": resource_attrs},
                "scopeSpans": [{
                    "scope": {
                        "name": "orchesis",
                        "version": self._config.resource_attributes.get("service.version", "0.8.0"),
                    },
                    "spans": otlp_spans,
                }],
            }]
        }

    def _send_http(self, payload: dict[str, Any]) -> bool:
        """Send OTLP payload via HTTP POST. Returns success."""
        url = f"{self._config.endpoint.rstrip('/')}{self._config.traces_path}"
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            **self._config.headers,
        }
        for attempt in range(max(1, self._config.retry_count)):
            try:
                req = urllib.request.Request(url, data=body, headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=self._config.timeout_seconds) as resp:
                    if resp.status < 300:
                        return True
            except (urllib.error.URLError, urllib.error.HTTPError, OSError, TimeoutError):
                if attempt < self._config.retry_count - 1:
                    time.sleep(0.5 * (attempt + 1))
                continue
        return False

    def get_stats(self) -> dict[str, Any]:
        """Return exporter statistics."""
        with self._lock:
            return {
                "enabled": self._config.enabled,
                "endpoint": self._config.endpoint,
                "queue_size": len(self._queue),
                "exported": self._exported,
                "failed": self._failed,
                "dropped": self._dropped,
            }
