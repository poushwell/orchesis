from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.immune_memory import ImmuneMemory


def test_primary_response_first_exposure() -> None:
    memory = ImmuneMemory()
    out = memory.expose("prompt injection attack", 0.8)
    assert out["primary_response"] is True
    assert out["memory_response"] is False
    assert out["exposures"] == 1


def test_memory_response_repeat_exposure() -> None:
    memory = ImmuneMemory()
    memory.expose("credential leak", 0.7)
    out = memory.expose("credential leak", 0.7)
    assert out["primary_response"] is False
    assert out["memory_response"] is True
    assert out["exposures"] == 2


def test_memory_strength_grows() -> None:
    memory = ImmuneMemory()
    s1 = memory.expose("tool abuse", 0.6)["memory_strength"]
    s2 = memory.expose("tool abuse", 0.6)["memory_strength"]
    assert s2 > s1


def test_recall_speed_accelerates() -> None:
    memory = ImmuneMemory({"recall_boost": 2.0})
    r1 = memory.expose("sqli", 0.9)["recall_speed"]
    r2 = memory.expose("sqli", 0.9)["recall_speed"]
    r3 = memory.expose("sqli", 0.9)["recall_speed"]
    assert r2 > r1
    assert r3 > r2


def test_recall_finds_pattern() -> None:
    memory = ImmuneMemory()
    memory.expose("ssrf pattern", 0.8)
    row = memory.recall("ssrf pattern")
    assert row is not None
    assert row["exposures"] == 1


def test_recall_miss_unknown() -> None:
    memory = ImmuneMemory()
    assert memory.recall("never-seen-threat") is None


def test_capacity_bounded() -> None:
    memory = ImmuneMemory({"capacity": 2})
    memory.expose("a", 0.1)
    memory.expose("b", 0.2)
    memory.expose("c", 0.3)
    stats = memory.get_memory_stats()
    assert stats["memory_cells"] == 2


def test_api_expose_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy_path), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)
    response = client.post(
        "/api/v1/immune/expose",
        json={"threat_pattern": "prompt injection", "severity": 0.9},
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["exposures"] == 1
    assert "pattern_hash" in payload

