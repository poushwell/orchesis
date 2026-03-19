from __future__ import annotations

import httpx
import pytest

from orchesis.api import create_api_app
from orchesis.red_queen import RedQueenMonitor


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


def test_attack_recorded() -> None:
    monitor = RedQueenMonitor()
    monitor.record_attack({"type": "prompt_injection", "novel": True})
    stats = monitor.get_stats()
    assert stats["attacks_recorded"] == 1


def test_detection_recorded() -> None:
    monitor = RedQueenMonitor()
    monitor.record_detection({"type": "prompt_injection"})
    stats = monitor.get_stats()
    assert stats["detections_recorded"] == 1


def test_ari_computed() -> None:
    monitor = RedQueenMonitor()
    monitor.record_attack({"type": "jailbreak", "novel": True})
    monitor.record_attack({"type": "jailbreak", "novel": False})
    monitor.record_detection({"type": "jailbreak"})
    row = monitor.compute_arms_race_index()
    assert "ari" in row
    assert row["n_attacks"] == 2
    assert row["n_detections"] == 1


def test_arms_race_status() -> None:
    monitor = RedQueenMonitor()
    monitor.record_attack({"type": "a", "novel": True})
    monitor.record_attack({"type": "b", "novel": True})
    row = monitor.compute_arms_race_index()
    assert row["status"] == "arms_race"


def test_stable_status_high_detection() -> None:
    monitor = RedQueenMonitor()
    for idx in range(4):
        monitor.record_attack({"type": f"a-{idx}", "novel": False})
        monitor.record_detection({"type": f"a-{idx}"})
    row = monitor.compute_arms_race_index()
    assert row["status"] == "stable"


def test_emerging_patterns_returned() -> None:
    monitor = RedQueenMonitor()
    monitor.record_attack({"type": "novel-1", "novel": True})
    monitor.record_attack({"type": "known-1", "novel": False})
    rows = monitor.get_emerging_patterns()
    assert len(rows) == 1
    assert rows[0]["type"] == "novel-1"


def test_novel_attack_mutation_rate() -> None:
    monitor = RedQueenMonitor()
    monitor.record_attack({"type": "a", "novel": True})
    monitor.record_attack({"type": "b", "novel": False})
    monitor.record_detection({"type": "a"})
    row = monitor.compute_arms_race_index()
    assert row["attack_mutation_rate"] == 0.5


@pytest.mark.asyncio
async def test_api_ari_endpoint(tmp_path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    async with await _client(app) as client:
        attack_response = await client.post(
            "/api/v1/red-queen/attack",
            headers=_auth(),
            json={"type": "prompt_injection", "novel": True},
        )
        assert attack_response.status_code == 200
        detection_response = await client.post(
            "/api/v1/red-queen/detection",
            headers=_auth(),
            json={"type": "prompt_injection"},
        )
        assert detection_response.status_code == 200
        ari_response = await client.get("/api/v1/red-queen/ari", headers=_auth())
    assert ari_response.status_code == 200
    payload = ari_response.json()
    assert "ari" in payload
    assert payload["n_attacks"] == 1
    assert payload["n_detections"] == 1
