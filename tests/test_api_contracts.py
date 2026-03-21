"""
API contract tests - verify endpoint existence, methods, and response shapes.
Auto-generated from app.routes to catch regressions.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app


def _build_app(tmp_path: Path):
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    return create_api_app(
        policy_path=str(policy),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )


def _api_paths(app) -> list[str]:
    return [route.path for route in app.routes if hasattr(route, "path") and str(route.path).startswith("/api/")]


def _method_path_signatures(app) -> list[str]:
    signatures: list[str] = []
    for route in app.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None)
        if not path or not methods or not str(path).startswith("/api/"):
            continue
        for method in sorted(methods):
            signatures.append(f"{method}:{path}")
    return signatures


def test_all_routes_have_unique_paths(tmp_path: Path) -> None:
    """No duplicate URL path+method signatures in the app."""
    app = _build_app(tmp_path)
    sigs = _method_path_signatures(app)
    counts = Counter(sigs)
    duplicates = sorted([item for item, count in counts.items() if count > 1])
    assert not duplicates, f"Duplicate routes: {duplicates}"


def test_core_routes_exist(tmp_path: Path) -> None:
    """Core routes are registered."""
    app = _build_app(tmp_path)
    paths = set(_api_paths(app))
    for expected in ["/api/v1/status", "/api/v1/policy"]:
        assert expected in paths, f"Missing core route: {expected}"


def test_ecosystem_routes_exist(tmp_path: Path) -> None:
    """Ecosystem routes are registered."""
    app = _build_app(tmp_path)
    paths = set(_api_paths(app))
    expected_prefixes = ["/api/v1/casura", "/api/v1/aabb", "/api/v1/are", "/api/v1/channels"]
    for prefix in expected_prefixes:
        assert any(path.startswith(prefix) for path in paths), f"Missing ecosystem prefix: {prefix}"


def test_security_routes_exist(tmp_path: Path) -> None:
    """Security routes are registered."""
    app = _build_app(tmp_path)
    paths = set(_api_paths(app))
    expected_prefixes = ["/api/v1/persona", "/api/v1/threat-patterns", "/api/v1/signatures", "/api/v1/alert-rules"]
    for prefix in expected_prefixes:
        assert any(path.startswith(prefix) for path in paths), f"Missing security prefix: {prefix}"


def test_health_endpoint_returns_200(tmp_path: Path) -> None:
    """GET /health returns 200."""
    client = TestClient(_build_app(tmp_path))
    resp = client.get("/health")
    assert resp.status_code == 200


def test_stats_endpoint_returns_200(tmp_path: Path) -> None:
    """GET /api/v1/status returns 200."""
    client = TestClient(_build_app(tmp_path))
    resp = client.get("/api/v1/status")
    assert resp.status_code == 200


def test_paginated_endpoint_shape(tmp_path: Path) -> None:
    """Paginated endpoint returns {items, total, limit, offset, has_more}."""
    client = TestClient(_build_app(tmp_path))
    for idx in range(7):
        created = client.post(
            "/api/v1/casura/incidents",
            headers={"Authorization": "Bearer test-token"},
            json={"title": f"inc-{idx}", "severity": 5.0, "category": "prompt_injection"},
        )
        assert created.status_code == 200
    resp = client.get(
        "/api/v1/casura/incidents?paginated=true&limit=5&offset=0",
        headers={"Authorization": "Bearer test-token"},
    )
    assert resp.status_code == 200
    payload = resp.json()
    for key in ("items", "total", "limit", "offset", "has_more"):
        assert key in payload


def test_route_count_sanity(tmp_path: Path) -> None:
    """App has reasonable number of routes (between 50 and 500)."""
    app = _build_app(tmp_path)
    routes = _api_paths(app)
    assert 50 <= len(routes) <= 500
