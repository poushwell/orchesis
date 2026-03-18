from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.quorum_sensing import QuorumSensor


def test_quorum_forms_at_n_star() -> None:
    sensor = QuorumSensor({"n_star": 3, "similarity": 0.7})
    sensor.register_task("a1", "summarize quarterly report")
    sensor.register_task("a2", "summarize quarterly reports")
    sensor.register_task("a3", "summarize quarter report")
    rows = sensor.detect_quorum()
    assert len(rows) == 1
    assert len(rows[0]["agents"]) == 3


def test_quorum_not_formed_below_threshold() -> None:
    sensor = QuorumSensor({"n_star": 3, "similarity": 0.7})
    sensor.register_task("a1", "summarize quarterly report")
    sensor.register_task("a2", "summarize quarter report")
    assert sensor.detect_quorum() == []


def test_context_contributed_and_retrieved() -> None:
    sensor = QuorumSensor({"n_star": 3, "similarity": 0.7})
    for agent, fp in (
        ("a1", "write release notes v1"),
        ("a2", "write release note v2"),
        ("a3", "write release notes final"),
    ):
        sensor.register_task(agent, fp)
    quorum = sensor.detect_quorum()[0]
    ok = sensor.contribute_context(quorum["quorum_id"], "a1", {"hint": "include migration notes"})
    assert ok is True
    ctx = sensor.get_shared_context(quorum["quorum_id"])
    assert ctx is not None
    assert ctx["context"]["hint"] == "include migration notes"


def test_similar_tasks_grouped() -> None:
    sensor = QuorumSensor({"n_star": 3, "similarity": 0.75})
    for agent, fp in (
        ("r1", "research retrieval strategy"),
        ("r2", "research retrieval strategies"),
        ("r3", "research retrieval plan"),
        ("c1", "compile compliance checklist"),
        ("c2", "compile compliance checklists"),
        ("c3", "compile compliance list"),
    ):
        sensor.register_task(agent, fp)
    rows = sensor.detect_quorum()
    assert len(rows) == 2


def test_dissimilar_tasks_not_grouped() -> None:
    sensor = QuorumSensor({"n_star": 3, "similarity": 0.8})
    sensor.register_task("a1", "build dashboard widgets")
    sensor.register_task("a2", "rotate database backup keys")
    sensor.register_task("a3", "generate poetry in french")
    assert sensor.detect_quorum() == []


def test_quorum_stats_tracked() -> None:
    sensor = QuorumSensor({"n_star": 3, "similarity": 0.7})
    sensor.register_task("a1", "optimize cache policy")
    sensor.register_task("a2", "optimize cache policies")
    sensor.register_task("a3", "optimize cache strategy")
    stats = sensor.get_stats()
    assert stats["active_quorums"] == 1
    assert stats["total_agents"] == 3
    assert stats["agents_in_quorum"] == 3
    assert stats["n_star"] == 3


def test_api_quorum_status(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy_path), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)
    headers = {"Authorization": "Bearer test-token"}
    for i in range(16):
        resp = client.post(
            "/api/v1/quorum/register-task",
            json={"agent_id": f"agent-{i}", "task_fingerprint": f"summarize security report {i % 3}"},
            headers=headers,
        )
        assert resp.status_code == 200

    status = client.get("/api/v1/quorum/status", headers=headers)
    assert status.status_code == 200
    payload = status.json()
    assert payload["n_star"] == 16
    assert payload["active_quorums"] >= 1


def test_api_register_task(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy_path), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)
    response = client.post(
        "/api/v1/quorum/register-task",
        json={"agent_id": "a1", "task_fingerprint": "investigate incident timeline"},
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.status_code == 200
    assert response.json()["ok"] is True
