from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from orchesis.api import create_api_app
from orchesis.data_flywheel import DataFlywheel


def _policy_yaml() -> str:
    return """
api:
  token: "orch_sk_test"
data_flywheel:
  levels: [L1, L2, L3, L4]
rules: []
"""


def _auth() -> dict[str, str]:
    return {"Authorization": "Bearer orch_sk_test"}


async def _client(app):
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


def test_signal_collected() -> None:
    fw = DataFlywheel({"levels": ["L1", "L2"]})
    fw.collect_signal({"agent_id": "a1", "model": "gpt-4o-mini", "task_type": "coding"})
    stats = fw.get_flywheel_stats()
    assert int(stats["signals_collected"]) == 1


def test_patterns_extracted() -> None:
    fw = DataFlywheel({"levels": ["L1", "L2"]})
    fw.collect_signal({"model": "gpt-4o-mini", "task_type": "coding"})
    fw.collect_signal({"model": "gpt-4o-mini", "task_type": "research"})
    out = fw.extract_patterns()
    assert int(out["signals_used"]) == 2
    assert int(out["patterns"]["model:gpt-4o-mini"]) == 2


def test_leaderboard_returned() -> None:
    fw = DataFlywheel({"levels": ["L1", "L4"]})
    fw.collect_signal({"model": "gpt-4o-mini", "task_type": "coding", "quality": 0.9, "cost": 0.02})
    fw.collect_signal({"model": "gpt-4o-mini", "task_type": "coding", "quality": 0.7, "cost": 0.01})
    board = fw.get_leaderboard()
    assert len(board) == 1
    assert board[0]["model"] == "gpt-4o-mini"
    assert board[0]["sample_count"] == 2


def test_calibration_result() -> None:
    fw = DataFlywheel({"levels": ["L3"]})
    res = fw.calibrate_signatures(
        [{"signature": "a", "false_positive_rate": 0.10, "threshold": 0.8}, {"signature": "b", "false_positive_rate": 0.05}]
    )
    assert int(res["signatures_updated"]) == 2
    assert int(res["thresholds_adjusted"]) == 1
    assert float(res["false_positive_reduction"]) >= 0.0


def test_anonymization_verified() -> None:
    fw = DataFlywheel({"levels": ["L1"]})
    fw.collect_signal({"agent_id": "secret-agent", "session_id": "sess-1", "model": "gpt-4o-mini"})
    assert fw._signals  # noqa: SLF001
    row = fw._signals[0]  # noqa: SLF001
    assert "agent_id" not in row
    assert "session_id" not in row
    assert "agent_id_anon" in row
    assert "session_id_anon" in row


def test_flywheel_stats() -> None:
    fw = DataFlywheel({"levels": ["L1", "L2", "L4"]})
    fw.collect_signal({"model": "m1", "task_type": "coding", "quality": 0.8, "cost": 0.01})
    fw.extract_patterns()
    stats = fw.get_flywheel_stats()
    assert int(stats["signals_collected"]) == 1
    assert int(stats["patterns_extracted"]) >= 1
    assert int(stats["leaderboard_entries"]) == 1


@pytest.mark.asyncio
async def test_api_leaderboard_endpoint(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    app.state.data_flywheel.collect_signal(
        {"model": "gpt-4o-mini", "task_type": "research", "quality": 0.95, "cost": 0.03}
    )
    async with await _client(app) as client:
        response = await client.get("/api/v1/flywheel/leaderboard", headers=_auth())
    assert response.status_code == 200
    payload = response.json()
    assert int(payload["count"]) >= 1
    assert payload["leaderboard"][0]["model"] == "gpt-4o-mini"


@pytest.mark.asyncio
async def test_api_signal_endpoint(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    async with await _client(app) as client:
        response = await client.post(
            "/api/v1/flywheel/signal",
            headers=_auth(),
            json={"agent_id": "agent-x", "model": "gpt-4o-mini", "task_type": "planning", "quality": 0.8},
        )
    assert response.status_code == 200
    assert response.json()["status"] == "accepted"
    assert int(app.state.data_flywheel.get_flywheel_stats()["signals_collected"]) == 1
