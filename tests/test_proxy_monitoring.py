from __future__ import annotations

from fastapi.testclient import TestClient

from orchesis.demo_backend import app as backend_app
from orchesis.proxy import create_proxy_app


def test_health_endpoint() -> None:
    proxy_app = create_proxy_app(
        policy={"rules": [{"name": "budget_limit", "max_cost_per_call": 1.0}]},
        backend_app=backend_app,
    )
    client = TestClient(proxy_app)
    response = client.get("/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "healthy"
    assert payload["version"] == "0.6.0"
    assert "policy_version" in payload
    assert "uptime_seconds" in payload
    assert "total_decisions" in payload


def test_metrics_endpoint() -> None:
    proxy_app = create_proxy_app(
        policy={"rules": [{"name": "budget_limit", "max_cost_per_call": 1.0}]},
        backend_app=backend_app,
    )
    client = TestClient(proxy_app)
    _ = client.get("/data", headers={"x-cost": "0.1"})
    _ = client.get("/data", headers={"x-cost": "0.1"})
    metrics = client.get("/metrics")
    assert metrics.status_code == 200
    assert "orchesis_decisions_total" in metrics.text
    assert 'orchesis_decisions_total{decision="ALLOW"}' in metrics.text
