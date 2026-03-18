"""OpenTelemetry bridge without SDK dependency."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any
from urllib.request import Request, urlopen


class OpenTelemetryBridge:
    """Exports Orchesis metrics in OpenTelemetry format.

    Stdlib only - generates OTLP-compatible JSON without SDK.
    Enables integration with Jaeger, Grafana, Datadog via OTLP.
    """

    METRIC_NAMES = {
        "requests_total": "orchesis.proxy.requests.total",
        "blocked_total": "orchesis.proxy.blocked.total",
        "cost_usd": "orchesis.proxy.cost.usd",
        "latency_ms": "orchesis.proxy.latency.ms",
        "cache_hits": "orchesis.proxy.cache.hits",
        "token_yield": "orchesis.nlce.token_yield",
        "context_quality": "orchesis.nlce.context_quality",
    }

    def __init__(self, config: dict | None = None):
        cfg = config if isinstance(config, dict) else {}
        self.endpoint = str(cfg.get("endpoint", "http://localhost:4318/v1/metrics"))
        self.service_name = str(cfg.get("service_name", "orchesis-proxy"))
        self.enabled = bool(cfg.get("enabled", False))
        self._buffer: list[dict[str, Any]] = []
        self._exported = 0
        self._last_export_at = ""
        self._lock = threading.Lock()

    def record(self, metric: str, value: float, labels: dict | None = None) -> None:
        """Record a metric data point."""
        metric_key = str(metric or "").strip()
        if not metric_key:
            return
        metric_name = self.METRIC_NAMES.get(metric_key, metric_key)
        attrs = labels if isinstance(labels, dict) else {}
        point = {
            "metric": metric_name,
            "value": float(value),
            "labels": dict(attrs),
            "timestamp_unix_nano": int(time.time() * 1_000_000_000),
        }
        with self._lock:
            self._buffer.append(point)
            if len(self._buffer) > 50_000:
                self._buffer = self._buffer[-50_000:]

    def export_otlp_json(self) -> dict:
        """Export buffered metrics as OTLP JSON payload."""
        with self._lock:
            points = list(self._buffer)
        by_metric: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for item in points:
            by_metric[str(item.get("metric", "orchesis.unknown"))].append(item)

        metrics: list[dict[str, Any]] = []
        for metric_name, rows in by_metric.items():
            data_points: list[dict[str, Any]] = []
            for row in rows:
                attrs = []
                labels = row.get("labels", {})
                if isinstance(labels, dict):
                    for key, value in labels.items():
                        attrs.append(
                            {
                                "key": str(key),
                                "value": {"stringValue": str(value)},
                            }
                        )
                data_points.append(
                    {
                        "asDouble": float(row.get("value", 0.0) or 0.0),
                        "timeUnixNano": str(int(row.get("timestamp_unix_nano", 0) or 0)),
                        "attributes": attrs,
                    }
                )
            metrics.append(
                {
                    "name": metric_name,
                    "gauge": {"dataPoints": data_points},
                }
            )

        return {
            "resourceMetrics": [
                {
                    "resource": {
                        "attributes": [
                            {"key": "service.name", "value": {"stringValue": self.service_name}},
                        ]
                    },
                    "scopeMetrics": [
                        {
                            "scope": {"name": "orchesis.otel_bridge"},
                            "metrics": metrics,
                        }
                    ],
                }
            ]
        }

    def flush(self) -> int:
        """Send buffered metrics to endpoint. Returns count sent."""
        with self._lock:
            count = len(self._buffer)
            if count == 0:
                return 0
            points = list(self._buffer)
            self._buffer = []
            self._last_export_at = datetime.now(timezone.utc).isoformat()

        by_metric: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for item in points:
            by_metric[str(item.get("metric", "orchesis.unknown"))].append(item)
        metrics: list[dict[str, Any]] = []
        for metric_name, rows in by_metric.items():
            data_points: list[dict[str, Any]] = []
            for row in rows:
                attrs = []
                labels = row.get("labels", {})
                if isinstance(labels, dict):
                    for key, value in labels.items():
                        attrs.append({"key": str(key), "value": {"stringValue": str(value)}})
                data_points.append(
                    {
                        "asDouble": float(row.get("value", 0.0) or 0.0),
                        "timeUnixNano": str(int(row.get("timestamp_unix_nano", 0) or 0)),
                        "attributes": attrs,
                    }
                )
            metrics.append({"name": metric_name, "gauge": {"dataPoints": data_points}})
        payload = {
            "resourceMetrics": [
                {
                    "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": self.service_name}}]},
                    "scopeMetrics": [{"scope": {"name": "orchesis.otel_bridge"}, "metrics": metrics}],
                }
            ]
        }

        if self.enabled:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            req = Request(self.endpoint, data=body, method="POST", headers={"Content-Type": "application/json"})
            try:
                with urlopen(req, timeout=2):
                    pass
            except Exception:
                # Export failures should not break control-plane operations.
                pass

        with self._lock:
            self._exported += int(count)
        return int(count)

    def generate_trace(self, request: dict, decision: dict) -> dict:
        """Generate OTLP trace span for a request."""
        req = request if isinstance(request, dict) else {}
        dec = decision if isinstance(decision, dict) else {}
        request_id = str(req.get("request_id", req.get("id", "")) or "")
        seed = f"{request_id}:{time.time_ns()}".encode("utf-8")
        trace_id = hashlib.sha256(seed).hexdigest()[:32]
        span_id = hashlib.sha256(seed + b":span").hexdigest()[:16]
        attrs = [
            {"key": "orchesis.request.id", "value": {"stringValue": request_id or "unknown"}},
            {"key": "orchesis.decision.final", "value": {"stringValue": str(dec.get("decision", dec.get("final_decision", "UNKNOWN")))}},
        ]
        return {
            "resourceSpans": [
                {
                    "resource": {
                        "attributes": [
                            {"key": "service.name", "value": {"stringValue": self.service_name}},
                        ]
                    },
                    "scopeSpans": [
                        {
                            "scope": {"name": "orchesis.otel_bridge"},
                            "spans": [
                                {
                                    "traceId": trace_id,
                                    "spanId": span_id,
                                    "name": "orchesis.request",
                                    "kind": 1,
                                    "startTimeUnixNano": str(int(time.time() * 1_000_000_000)),
                                    "endTimeUnixNano": str(int(time.time() * 1_000_000_000)),
                                    "attributes": attrs,
                                }
                            ],
                        }
                    ],
                }
            ]
        }

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "buffered": len(self._buffer),
                "exported": int(self._exported),
                "endpoint": self.endpoint,
                "enabled": bool(self.enabled),
            }
