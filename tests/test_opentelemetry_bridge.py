from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.otel_bridge import OpenTelemetryBridge


def test_metric_recorded() -> None:
    bridge = OpenTelemetryBridge()
    bridge.record("requests_total", 1.0)
    stats = bridge.get_stats()
    assert stats["buffered"] == 1


def test_otlp_json_format_valid() -> None:
    bridge = OpenTelemetryBridge({"service_name": "svc-a"})
    bridge.record("requests_total", 3.0, {"env": "test"})
    bridge.record("latency_ms", 120.0, {"route": "/evaluate"})
    payload = bridge.export_otlp_json()
    assert "resourceMetrics" in payload
    resource = payload["resourceMetrics"][0]
    assert "scopeMetrics" in resource
    assert isinstance(resource["scopeMetrics"][0]["metrics"], list)


def test_trace_generated() -> None:
    bridge = OpenTelemetryBridge()
    trace = bridge.generate_trace(
        {"request_id": "req-1", "path": "/api/v1/evaluate"},
        {"decision": "ALLOW"},
    )
    spans = trace["resourceSpans"][0]["scopeSpans"][0]["spans"]
    assert len(spans) == 1
    assert spans[0]["name"] == "orchesis.request"
    assert len(spans[0]["traceId"]) == 32
    assert len(spans[0]["spanId"]) == 16


def test_flush_clears_buffer() -> None:
    bridge = OpenTelemetryBridge()
    bridge.record("requests_total", 1.0)
    bridge.record("blocked_total", 0.0)
    sent = bridge.flush()
    stats = bridge.get_stats()
    assert sent == 2
    assert stats["buffered"] == 0
    assert stats["exported"] >= 2


def test_labels_included() -> None:
    bridge = OpenTelemetryBridge()
    bridge.record("cost_usd", 0.42, {"agent_id": "a-1", "team": "red"})
    payload = bridge.export_otlp_json()
    metrics = payload["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
    cost_metric = [item for item in metrics if item["name"] == "orchesis.proxy.cost.usd"][0]
    attrs = cost_metric["gauge"]["dataPoints"][0]["attributes"]
    keys = {item["key"] for item in attrs}
    assert "agent_id" in keys
    assert "team" in keys


def test_metric_names_correct() -> None:
    bridge = OpenTelemetryBridge()
    assert bridge.METRIC_NAMES["requests_total"] == "orchesis.proxy.requests.total"
    assert bridge.METRIC_NAMES["context_quality"] == "orchesis.nlce.context_quality"


def test_api_metrics_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    app.state.otel_bridge.record("requests_total", 5.0, {"agent": "agent-1"})
    client = TestClient(app)
    response = client.get("/api/v1/otel/metrics", headers={"Authorization": "Bearer test-token"})
    assert response.status_code == 200
    payload = response.json()
    assert "resourceMetrics" in payload


def test_api_flush_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    app.state.otel_bridge.record("blocked_total", 1.0)
    client = TestClient(app)
    response = client.post("/api/v1/otel/flush", headers={"Authorization": "Bearer test-token"})
    assert response.status_code == 200
    assert response.json()["flushed"] == 1
