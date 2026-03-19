from __future__ import annotations

import httpx
import pytest

from orchesis.api import create_api_app
from orchesis.double_loop_learning import DoubleLoopLearner


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


def test_error_recorded() -> None:
    learner = DoubleLoopLearner()
    learner.record_error("timeout", 0.4, {"session": "s1"})
    stats = learner.get_learning_stats()
    assert stats["errors_recorded"] == 1


def test_single_loop_determined_below_threshold() -> None:
    learner = DoubleLoopLearner({"single_threshold": 0.3, "double_threshold": 0.6})
    assert learner.determine_loop(0.4) == "single"


def test_double_loop_determined_above_threshold() -> None:
    learner = DoubleLoopLearner({"single_threshold": 0.3, "double_threshold": 0.6})
    assert learner.determine_loop(0.7) == "double"


def test_single_loop_adapts_parameter() -> None:
    learner = DoubleLoopLearner()
    row = learner.single_loop_adapt("compression_aggressiveness", 0.1)
    assert row["loop"] == "single"
    assert row["new_value"] > row["old_value"]


def test_double_loop_resets_strategy() -> None:
    learner = DoubleLoopLearner()
    learner.single_loop_adapt("injection_frequency", 0.2)
    row = learner.double_loop_adapt("new strategy", "too many compounding failures")
    assert row["loop"] == "double"
    stats = learner.get_learning_stats()
    assert all(abs(float(v) - 0.5) < 1e-9 for v in stats["governing_rules"].values())


def test_governing_rules_bounded() -> None:
    learner = DoubleLoopLearner()
    upper = learner.single_loop_adapt("compression_aggressiveness", 10.0)
    lower = learner.single_loop_adapt("compression_aggressiveness", -10.0)
    assert upper["new_value"] <= 1.0
    assert lower["new_value"] >= 0.0


def test_stats_tracked() -> None:
    learner = DoubleLoopLearner()
    learner.record_error("drift", 0.9, {})
    learner.single_loop_adapt("cache_threshold", -0.1)
    learner.double_loop_adapt("switch strategy", "persistent drift")
    stats = learner.get_learning_stats()
    assert stats["errors_recorded"] == 1
    assert stats["single_loop_adaptations"] == 1
    assert stats["double_loop_adaptations"] == 1


@pytest.mark.asyncio
async def test_api_adapt_endpoint(tmp_path) -> None:
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
            "/api/v1/double-loop/adapt",
            headers=_auth(),
            json={"error_rate": 0.45, "rule": "compression_aggressiveness", "delta": 0.05},
        )
    assert response.status_code == 200
    payload = response.json()
    assert payload["loop"] == "single"
    assert payload["adaptation"]["rule"] == "compression_aggressiveness"
