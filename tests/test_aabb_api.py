from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
from tests.cli_test_utils import CliRunner

from orchesis.aabb.benchmark import AABBBenchmark
from orchesis.api import create_api_app
from orchesis.cli import main


def _app_with_aabb(tmp_path: Path):
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    app.state.aabb_benchmark = AABBBenchmark()
    return app


def test_leaderboard_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    app = _app_with_aabb(tmp_path)
    client = TestClient(app)
    headers = {"Authorization": "Bearer test-token"}
    client.post("/api/v1/aabb/run/agent-a", headers=headers)
    client.post("/api/v1/aabb/run/agent-b", headers=headers)
    res = client.get("/api/v1/aabb/leaderboard", headers=headers)
    assert res.status_code == 200
    payload = res.json()
    assert payload["total"] >= 2


def test_run_benchmark_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    client = TestClient(_app_with_aabb(tmp_path))
    res = client.post("/api/v1/aabb/run/agent-x", headers={"Authorization": "Bearer test-token"})
    assert res.status_code == 200
    payload = res.json()
    assert payload["agent_id"] == "agent-x"
    assert "overall_score" in payload


def test_stats_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    app = _app_with_aabb(tmp_path)
    client = TestClient(app)
    headers = {"Authorization": "Bearer test-token"}
    client.post("/api/v1/aabb/run/agent-a", headers=headers)
    res = client.get("/api/v1/aabb/stats", headers=headers)
    assert res.status_code == 200
    assert res.json()["total_runs"] >= 1


def test_compare_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    app = _app_with_aabb(tmp_path)
    client = TestClient(app)
    headers = {"Authorization": "Bearer test-token"}
    client.post("/api/v1/aabb/run/agent-a", headers=headers)
    client.post("/api/v1/aabb/run/agent-b", headers=headers)
    res = client.get("/api/v1/aabb/compare/agent-a/agent-b", headers=headers)
    assert res.status_code == 200
    payload = res.json()
    assert "diff" in payload
    assert payload["winner"] in {"agent-a", "agent-b"}


def test_cli_aabb_leaderboard() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["aabb", "--leaderboard"])
    assert result.exit_code == 0
    assert "leaderboard" in result.output


def test_cli_aabb_run() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["aabb", "--run-agent", "agent-x"])
    assert result.exit_code == 0
    assert "\"agent_id\": \"agent-x\"" in result.output
