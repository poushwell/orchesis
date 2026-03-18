from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from orchesis.api import create_api_app
from orchesis.geo_intel import GeoIntel


def _policy_yaml() -> str:
    return """
api:
  token: "orch_sk_test"
rules: []
"""


def _auth() -> dict[str, str]:
    return {"Authorization": "Bearer orch_sk_test"}


async def _client(app):
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


def _make_app(tmp_path: Path):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    return create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )


def test_private_ip_classified() -> None:
    payload = GeoIntel().classify_ip("10.0.0.1")
    assert payload["type"] == "private"
    assert payload["is_private"] is True
    assert payload["risk_hint"] == "internal"


def test_public_ip_classified() -> None:
    payload = GeoIntel().classify_ip("8.8.8.8")
    assert payload["type"] == "public"
    assert payload["is_private"] is False
    assert payload["risk_hint"] == "external"


def test_loopback_classified() -> None:
    payload = GeoIntel().classify_ip("127.0.0.1")
    assert payload["type"] == "loopback"
    assert payload["is_private"] is True
    assert payload["risk_hint"] == "internal"


def test_ssrf_detected_private_range() -> None:
    payload = GeoIntel().scan_for_ssrf("fetch http://169.254.169.254/latest/meta-data")
    assert payload["ssrf_detected"] is True
    assert "169.254.169.254" in payload["target_ips"]
    assert payload["severity"] in {"high", "critical", "medium"}


def test_ip_extraction_from_text() -> None:
    ips = GeoIntel().extract_ips("targets 10.0.0.5, 8.8.8.8 and invalid 300.1.1.1")
    assert "10.0.0.5" in ips
    assert "8.8.8.8" in ips
    assert "300.1.1.1" not in ips


@pytest.mark.asyncio
async def test_api_classify_endpoint(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    async with await _client(app) as client:
        res = await client.get("/api/v1/geo/classify", params={"ip": "10.0.0.1"}, headers=_auth())
    assert res.status_code == 200
    payload = res.json()
    assert payload["ip"] == "10.0.0.1"
    assert payload["type"] == "private"
