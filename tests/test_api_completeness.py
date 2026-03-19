"""Verify API has all expected endpoints."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from orchesis.api import create_api_app


def _build_app(tmp_path: Path):
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    return create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))


def _paths(app) -> list[str]:
    return [route.path for route in app.routes if hasattr(route, "path")]


def test_total_routes_above_200(tmp_path: Path):
    app = _build_app(tmp_path)
    routes = _paths(app)
    assert len(routes) >= 200, f"Got {len(routes)} routes"


def test_casura_endpoints_present(tmp_path: Path):
    app = _build_app(tmp_path)
    paths = _paths(app)
    assert any("casura" in item for item in paths)


def test_nlce_endpoints_present(tmp_path: Path):
    app = _build_app(tmp_path)
    paths = _paths(app)
    assert any("nlce" in item for item in paths)


def test_autopsy_endpoints_present(tmp_path: Path):
    app = _build_app(tmp_path)
    paths = _paths(app)
    assert any("autopsy" in item for item in paths)


def test_health_endpoint_present(tmp_path: Path):
    app = _build_app(tmp_path)
    paths = _paths(app)
    assert "/health" in paths


def test_no_duplicate_routes(tmp_path: Path):
    app = _build_app(tmp_path)
    signatures = []
    for route in app.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None)
        if path is None or not methods:
            continue
        for method in sorted(methods):
            signatures.append(f"{method}:{path}")
    counts = Counter(signatures)
    dups = [sig for sig, count in counts.items() if count > 1]
    known_duplicates = {
        "POST:/api/v1/group-selection/register",
        "POST:/api/v1/group-selection/interaction",
        "GET:/api/v1/group-selection/fittest",
    }
    unexpected = sorted(set(dups) - known_duplicates)
    assert not unexpected, f"Duplicate routes: {unexpected}"
