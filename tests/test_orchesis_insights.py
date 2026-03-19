from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from orchesis.api import create_api_app
from orchesis.insights import OrchesisInsights


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


def test_insights_generated() -> None:
    data = OrchesisInsights().generate()
    assert "generated_at" in data
    assert "headline_metrics" in data


def test_cost_framework_present() -> None:
    data = OrchesisInsights().generate()
    assert "cost_framework" in data
    assert {"C", "O", "S", "T"}.issubset(set(data["cost_framework"].keys()))


def test_impossibility_theorems_present() -> None:
    data = OrchesisInsights().generate()
    assert "impossibility_theorems" in data
    assert {"T1", "T2", "T3"}.issubset(set(data["impossibility_theorems"].keys()))


def test_one_liner_contains_key_stats() -> None:
    line = OrchesisInsights().get_one_liner()
    assert "3.52" in line
    assert "22.73%" in line
    assert "Zero code changes" in line


def test_elevator_pitch_generated() -> None:
    pitch = OrchesisInsights().get_elevator_pitch()
    assert "proxy" in pitch.lower()
    assert len(pitch) > 100


def test_headline_metrics_correct() -> None:
    metrics = OrchesisInsights().generate()["headline_metrics"]
    assert metrics["n_star"] == 16
    assert metrics["zipf_alpha"] == 1.672
    assert metrics["proxy_overhead"] == "0.8%"


@pytest.mark.asyncio
async def test_api_insights_endpoint(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    async with await _client(app) as client:
        res = await client.get("/api/v1/insights", headers=_auth())
    assert res.status_code == 200
    payload = res.json()
    assert "headline_metrics" in payload


@pytest.mark.asyncio
async def test_api_one_liner_endpoint(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    async with await _client(app) as client:
        res = await client.get("/api/v1/insights/one-liner", headers=_auth())
    assert res.status_code == 200
    payload = res.json()
    assert "one_liner" in payload
    assert "3.52" in payload["one_liner"]
