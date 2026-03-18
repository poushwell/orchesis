from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.vickrey_allocator import VickreyBudgetAllocator


def _allocator(total_budget: int = 1000) -> VickreyBudgetAllocator:
    return VickreyBudgetAllocator({"total_budget": total_budget})


def test_bid_submitted() -> None:
    allocator = _allocator()
    row = allocator.submit_bid("agent-a", 300, "high")
    assert row["agent_id"] == "agent-a"
    assert row["bid_tokens"] == 300
    assert row["task_priority"] == "high"
    assert row["bid_id"].startswith("bid-")


def test_auction_allocates_budget() -> None:
    allocator = _allocator(1000)
    allocator.submit_bid("agent-a", 400, "high")
    allocator.submit_bid("agent-b", 300, "medium")
    result = allocator.run_auction()
    assert result["allocations"]["agent-a"] == 400
    assert result["allocations"]["agent-b"] == 300
    assert result["total_allocated"] == 700


def test_second_price_mechanism() -> None:
    allocator = _allocator(500)
    allocator.submit_bid("winner", 300, "high")
    allocator.submit_bid("runner_up", 200, "medium")
    result = allocator.run_auction()
    assert result["prices"]["winner"] == 200


def test_high_priority_wins_tie() -> None:
    allocator = _allocator(100)
    allocator.submit_bid("low", 100, "low")
    allocator.submit_bid("high", 100, "high")
    result = allocator.run_auction()
    assert result["allocations"]["high"] >= result["allocations"]["low"]


def test_total_not_exceeded() -> None:
    allocator = _allocator(250)
    allocator.submit_bid("a", 200, "high")
    allocator.submit_bid("b", 200, "high")
    allocator.submit_bid("c", 200, "high")
    result = allocator.run_auction()
    assert result["total_allocated"] <= 250


def test_allocation_retrieved() -> None:
    allocator = _allocator(300)
    allocator.submit_bid("a", 150, "medium")
    allocator.run_auction()
    assert allocator.get_allocation("a") == 150


def test_api_bid_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)
    response = client.post(
        "/api/v1/vickrey/bid",
        json={"agent_id": "agent-x", "bid_tokens": 120, "task_priority": "high"},
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["agent_id"] == "agent-x"


def test_api_auction_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)
    headers = {"Authorization": "Bearer test-token"}
    client.post("/api/v1/vickrey/bid", json={"agent_id": "a", "bid_tokens": 90, "task_priority": "high"}, headers=headers)
    client.post("/api/v1/vickrey/bid", json={"agent_id": "b", "bid_tokens": 80, "task_priority": "medium"}, headers=headers)
    response = client.post("/api/v1/vickrey/auction", headers=headers)
    assert response.status_code == 200
    payload = response.json()
    assert "allocations" in payload
    assert payload["total_allocated"] >= 0
