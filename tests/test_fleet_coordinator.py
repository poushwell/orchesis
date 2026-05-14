from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.fleet_coordinator import FleetCoordinator


def test_register_agent() -> None:
    fleet = FleetCoordinator()
    result = fleet.register_agent("agent-a", ["search", "reason"])
    assert result["registered"] is True
    assert result["agent_id"] == "agent-a"
    assert "search" in result["capabilities"]


def test_task_assigned_to_best_agent() -> None:
    fleet = FleetCoordinator()
    fleet.register_agent("agent-a", ["search"])
    fleet.register_agent("agent-b", ["search", "code"])
    first = fleet.assign_task({"required_capabilities": ["search"]})
    second = fleet.assign_task({"required_capabilities": ["search", "code"]})
    assert first in {"agent-a", "agent-b"}
    assert second == "agent-b"


def test_context_shared_between_agents() -> None:
    fleet = FleetCoordinator()
    fleet.register_agent("agent-a", ["planner"])
    fleet.register_agent("agent-b", ["executor"])
    assigned = fleet.assign_task(
        {
            "required_capabilities": ["planner"],
            "context_key": "plan",
            "context_value": "step-1, step-2",
        }
    )
    assert assigned == "agent-a"
    ok = fleet.share_context("agent-a", "agent-b", "plan")
    assert ok is True


def test_fleet_status_returned() -> None:
    fleet = FleetCoordinator()
    fleet.register_agent("a", ["general"])
    fleet.register_agent("b", ["general"])
    _ = fleet.assign_task({"required_capabilities": ["general"]})
    status = fleet.get_fleet_status()
    assert status["total_agents"] == 2
    assert status["tasks_routed"] >= 1


def test_load_distribution_computed() -> None:
    fleet = FleetCoordinator()
    fleet.register_agent("a", ["general"])
    fleet.register_agent("b", ["general"])
    _ = fleet.assign_task({"required_capabilities": ["general"]})
    _ = fleet.assign_task({"required_capabilities": ["general"]})
    dist = fleet.get_load_distribution()
    assert "distribution" in dist
    assert set(dist["distribution"].keys()) == {"a", "b"}
    assert dist["total_tasks"] >= 2


def test_rebalance_called() -> None:
    fleet = FleetCoordinator()
    fleet.register_agent("a", ["general"])
    fleet.register_agent("b", ["general"])
    fleet._agents["a"]["tasks"] = 5
    fleet._agents["a"]["status"] = "active"
    fleet._agents["b"]["tasks"] = 0
    rebalance = fleet.rebalance()
    assert "rebalanced" in rebalance
    assert "moved_tasks" in rebalance


def test_api_fleet_status(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    app.state.fleet_coordinator.register_agent("agent-a", ["general"])
    client = TestClient(app)
    response = client.get("/api/v1/fleet/status", headers={"Authorization": "Bearer test-token"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["total_agents"] >= 1


def test_api_assign_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    app.state.fleet_coordinator.register_agent("agent-a", ["search", "code"])
    client = TestClient(app)
    response = client.post(
        "/api/v1/fleet/assign",
        json={"task": {"required_capabilities": ["search"]}},
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["assigned_agent"] == "agent-a"
