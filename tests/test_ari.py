from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
from tests.cli_test_utils import CliRunner

from orchesis.ari import AgentReadinessIndex
from orchesis.ars import ARSResult
from orchesis.api import create_api_app
from orchesis.cli import main


def _ars_result(
    *,
    score: float = 80.0,
    confidence: str = "high",
    components: dict[str, float] | None = None,
) -> ARSResult:
    return ARSResult(
        agent_id="agent-x",
        score=score,
        grade="B",
        components=components
        or {
            "security_compliance": 90.0,
            "cost_efficiency": 80.0,
            "task_completion": 85.0,
            "loop_freedom": 90.0,
            "latency_health": 80.0,
            "context_stability": 75.0,
        },
        sample_size=100,
        confidence=confidence,
        computed_at=0.0,
    )


def test_evaluate_all_pass() -> None:
    ari = AgentReadinessIndex()
    result = ari.evaluate("a", metrics={"security_score": 90, "cost_score": 90, "task_score": 90, "loop_score": 90, "latency_score": 90, "obs_score": 90})
    assert result.verdict == "READY"


def test_evaluate_blocking_fail() -> None:
    ari = AgentReadinessIndex()
    result = ari.evaluate("a", metrics={"security_score": 40, "cost_score": 90, "task_score": 90, "loop_score": 90, "latency_score": 90, "obs_score": 90})
    assert result.verdict == "NOT_READY"
    assert "security_posture" in result.blocking_failures


def test_evaluate_conditional() -> None:
    ari = AgentReadinessIndex()
    result = ari.evaluate("a", metrics={"security_score": 80, "cost_score": 60, "task_score": 75, "loop_score": 70, "latency_score": 70, "obs_score": 60})
    assert result.verdict == "CONDITIONAL"


def test_from_ars_result() -> None:
    ars = _ars_result(
        components={
            "security_compliance": 91.0,
            "cost_efficiency": 62.0,
            "task_completion": 77.0,
            "loop_freedom": 88.0,
            "latency_health": 71.0,
            "context_stability": 66.0,
        }
    )
    ari = AgentReadinessIndex()
    result = ari.evaluate("a", ars_result=ars)
    by_name = {d.name: d.score for d in result.dimensions}
    assert by_name["security_posture"] == 91.0
    assert by_name["observability"] == 66.0


def test_from_metrics_dict() -> None:
    ari = AgentReadinessIndex()
    result = ari.evaluate("a", metrics={"security_score": 81, "cost_score": 71, "task_score": 76, "loop_score": 86, "latency_score": 72, "obs_score": 61})
    assert result.verdict == "READY"


def test_blocking_failures_list() -> None:
    ari = AgentReadinessIndex()
    result = ari.evaluate("a", metrics={"security_score": 50, "cost_score": 49, "task_score": 54, "loop_score": 90, "latency_score": 90, "obs_score": 90})
    assert set(result.blocking_failures) == {"security_posture", "cost_predictability", "task_reliability"}


def test_recommendations_generated() -> None:
    ari = AgentReadinessIndex()
    result = ari.evaluate("a", metrics={"security_score": 40, "cost_score": 30, "task_score": 20, "loop_score": 65, "latency_score": 45, "obs_score": 35})
    assert "Reduce threat rate below 20%" in result.recommendations
    assert "Set budget ceiling" in result.recommendations
    assert "Enable loop detection" in result.recommendations


def test_recommendations_deduplicated(monkeypatch) -> None:
    monkeypatch.setattr(
        AgentReadinessIndex,
        "_recommendations_for",
        staticmethod(lambda _dimension, status: ["same"] if status != "pass" else []),
    )
    ari = AgentReadinessIndex()
    result = ari.evaluate("a", metrics={"security_score": 10, "cost_score": 10, "task_score": 10, "loop_score": 10, "latency_score": 10, "obs_score": 10})
    assert result.recommendations == ["same"]


def test_custom_weights() -> None:
    ari = AgentReadinessIndex(weights={"security_posture": 100, "cost_predictability": 0, "task_reliability": 0, "loop_safety": 0, "latency_profile": 0, "observability": 0})
    result = ari.evaluate("a", metrics={"security_score": 80, "cost_score": 10, "task_score": 10, "loop_score": 10, "latency_score": 10, "obs_score": 10})
    assert result.index == 80.0


def test_index_calculation() -> None:
    ari = AgentReadinessIndex()
    result = ari.evaluate("a", metrics={"security_score": 100, "cost_score": 0, "task_score": 0, "loop_score": 0, "latency_score": 0, "obs_score": 0})
    expected = round(100 * 25 / 100, 2)
    assert result.index == expected


def test_verdict_ready_threshold() -> None:
    ari = AgentReadinessIndex()
    result = ari.evaluate("a", metrics={"security_score": 75, "cost_score": 75, "task_score": 75, "loop_score": 75, "latency_score": 75, "obs_score": 75})
    assert result.index == 75.0
    assert result.verdict == "READY"


def test_verdict_not_ready_override() -> None:
    ari = AgentReadinessIndex()
    result = ari.evaluate("a", metrics={"security_score": 59, "cost_score": 100, "task_score": 100, "loop_score": 100, "latency_score": 100, "obs_score": 100})
    assert result.index > 75
    assert result.verdict == "NOT_READY"


def test_batch_evaluate() -> None:
    ari = AgentReadinessIndex()
    results = ari.batch_evaluate(
        [
            {"agent_id": "a", "metrics": {"security_score": 90, "cost_score": 90, "task_score": 90, "loop_score": 90, "latency_score": 90, "obs_score": 90}},
            {"agent_id": "b", "metrics": {"security_score": 30, "cost_score": 90, "task_score": 90, "loop_score": 90, "latency_score": 90, "obs_score": 90}},
        ]
    )
    assert len(results) == 2
    assert results[0].agent_id == "a"


def test_get_summary() -> None:
    ari = AgentReadinessIndex()
    results = [
        ari.evaluate("a", metrics={"security_score": 90, "cost_score": 90, "task_score": 90, "loop_score": 90, "latency_score": 90, "obs_score": 90}),
        ari.evaluate("b", metrics={"security_score": 70, "cost_score": 60, "task_score": 75, "loop_score": 70, "latency_score": 70, "obs_score": 60}),
        ari.evaluate("c", metrics={"security_score": 30, "cost_score": 90, "task_score": 90, "loop_score": 90, "latency_score": 90, "obs_score": 90}),
    ]
    summary = ari.get_summary(results)
    assert summary["total"] == 3
    assert summary["ready"] == 1
    assert summary["conditional"] == 1
    assert summary["not_ready"] == 1


def test_get_summary_top_blocking() -> None:
    ari = AgentReadinessIndex()
    results = [
        ari.evaluate("a", metrics={"security_score": 20, "cost_score": 90, "task_score": 90}),
        ari.evaluate("b", metrics={"security_score": 10, "cost_score": 90, "task_score": 90}),
        ari.evaluate("c", metrics={"security_score": 80, "cost_score": 10, "task_score": 90}),
    ]
    summary = ari.get_summary(results)
    assert summary["top_blocking_dimensions"][0] == "security_posture"


def test_confidence_from_ars() -> None:
    ari = AgentReadinessIndex()
    result = ari.evaluate("a", ars_result=_ars_result(confidence="medium"))
    assert result.confidence == "medium"


def test_confidence_no_data() -> None:
    ari = AgentReadinessIndex()
    result = ari.evaluate("a")
    assert result.confidence == "low"


def test_dimension_status_pass_warn_fail() -> None:
    ari = AgentReadinessIndex()
    result = ari.evaluate("a", metrics={"security_score": 80, "cost_score": 50, "task_score": 54, "loop_score": 90, "latency_score": 90, "obs_score": 90})
    by_name = {d.name: d.status for d in result.dimensions}
    assert by_name["security_posture"] == "pass"
    assert by_name["cost_predictability"] == "warn"
    assert by_name["task_reliability"] == "fail"


def test_all_dimensions_present() -> None:
    ari = AgentReadinessIndex()
    result = ari.evaluate("a")
    names = [d.name for d in result.dimensions]
    assert names == [
        "security_posture",
        "cost_predictability",
        "task_reliability",
        "loop_safety",
        "latency_profile",
        "observability",
    ]


def test_empty_metrics() -> None:
    ari = AgentReadinessIndex()
    result = ari.evaluate("a", metrics={})
    assert result.agent_id == "a"
    assert 0 <= result.index <= 100


def _policy_yaml() -> str:
    return """
api:
  token: "orch_sk_test"
agent_readiness:
  metrics:
    agent-x:
      security_score: 90
      cost_score: 78
      task_score: 85
      loop_score: 88
      latency_score: 76
      obs_score: 75
    low-agent:
      security_score: 40
      cost_score: 45
      task_score: 42
      loop_score: 50
      latency_score: 48
      obs_score: 35
rules: []
"""


def test_ari_api_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text(_policy_yaml(), encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)
    res = client.get("/api/v1/ari/agent-x", headers={"Authorization": "Bearer orch_sk_test"})
    assert res.status_code == 200
    payload = res.json()
    assert payload["agent_id"] == "agent-x"
    assert "score" in payload
    assert "status" in payload
    assert "dimensions" in payload
    assert "security" in payload["dimensions"]


def test_ari_report_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text(_policy_yaml(), encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)
    res = client.get("/api/v1/ari/agent-x/report", headers={"Authorization": "Bearer orch_sk_test"})
    assert res.status_code == 200
    payload = res.json()
    assert payload["agent_id"] == "agent-x"
    assert "report_generated_at" in payload
    assert isinstance(payload["blocking_gates"], list)


def test_ari_check_cli_passes(tmp_path: Path) -> None:
    cfg = tmp_path / "orchesis.yaml"
    cfg.write_text(_policy_yaml(), encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["ari-check", "--agent", "agent-x", "--min-score", "75", "--config", str(cfg)],
    )
    assert result.exit_code == 0
    assert "✓ ARI score:" in result.output


def test_ari_check_cli_fails_below_threshold(tmp_path: Path) -> None:
    cfg = tmp_path / "orchesis.yaml"
    cfg.write_text(_policy_yaml(), encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["ari-check", "--agent", "low-agent", "--min-score", "75", "--config", str(cfg)],
    )
    assert result.exit_code == 1
    assert "✗ ARI score:" in result.output


def test_ari_check_exit_codes(tmp_path: Path) -> None:
    cfg = tmp_path / "orchesis.yaml"
    cfg.write_text(_policy_yaml(), encoding="utf-8")
    runner = CliRunner()
    ok = runner.invoke(main, ["ari-check", "--agent", "agent-x", "--min-score", "50", "--config", str(cfg)])
    bad = runner.invoke(main, ["ari-check", "--agent", "low-agent", "--min-score", "90", "--config", str(cfg)])
    assert ok.exit_code == 0
    assert bad.exit_code == 1

