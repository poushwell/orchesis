from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

from orchesis.agent_health import AgentHealthScore
from orchesis.api import create_api_app


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


def _write_event(
    decisions_log: Path,
    *,
    agent_id: str,
    seconds_ago: float,
    decision: str = "ALLOW",
    cost: float = 0.0,
    reason: str = "",
    eval_us: int = 5000,
) -> None:
    ts = datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)
    row = {
        "event_id": f"evt-{agent_id}-{int(seconds_ago)}-{decision.lower()}",
        "timestamp": ts.isoformat(),
        "agent_id": agent_id,
        "tool": "shell.exec",
        "params_hash": "abc123",
        "cost": float(cost),
        "decision": decision,
        "reasons": [reason] if reason else ([] if decision == "ALLOW" else ["policy:blocked"]),
        "rules_checked": [],
        "rules_triggered": [],
        "evaluation_order": [],
        "evaluation_duration_us": int(eval_us),
        "policy_version": "v1",
        "state_snapshot": {"model": "gpt-4o"},
        "decision_reason": None,
        "credentials_injected": [],
        "signature": None,
    }
    decisions_log.parent.mkdir(parents=True, exist_ok=True)
    with decisions_log.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row) + "\n")


def _make_app(tmp_path: Path):
    policy_path = tmp_path / "policy.yaml"
    decisions_log = tmp_path / "decisions.jsonl"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(decisions_log),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    return app, decisions_log


def test_health_score_range_0_100() -> None:
    scorer = AgentHealthScore()
    result = scorer.compute(
        {
            "block_rate": 0.8,
            "threat_frequency": 0.1,
            "cost_budget_ratio": 0.5,
            "savings_rate": 0.3,
            "cache_hit_rate": 0.6,
            "loop_frequency": 0.1,
            "error_rate": 0.05,
            "latency_ms": 120,
        }
    )
    assert 0.0 <= result["score"] <= 100.0


def test_grade_assignment_correct() -> None:
    scorer = AgentHealthScore()
    low = scorer.compute(
        {
            "block_rate": 0.0,
            "threat_frequency": 0.9,
            "cost_budget_ratio": 1.0,
            "savings_rate": 0.0,
            "cache_hit_rate": 0.0,
            "loop_frequency": 1.0,
            "error_rate": 1.0,
            "latency_ms": 5000,
        }
    )
    high = scorer.compute(
        {
            "block_rate": 1.0,
            "threat_frequency": 0.0,
            "cost_budget_ratio": 0.0,
            "savings_rate": 1.0,
            "cache_hit_rate": 1.0,
            "loop_frequency": 0.0,
            "error_rate": 0.0,
            "latency_ms": 10,
        }
    )
    assert low["grade"] == "D"
    assert high["grade"] in {"A", "A+"}


def test_breakdown_sums_to_total() -> None:
    scorer = AgentHealthScore()
    result = scorer.compute(
        {
            "block_rate": 0.7,
            "threat_frequency": 0.2,
            "cost_budget_ratio": 0.4,
            "savings_rate": 0.2,
            "cache_hit_rate": 0.8,
            "loop_frequency": 0.1,
            "error_rate": 0.1,
            "latency_ms": 250,
        }
    )
    breakdown = result["breakdown"]
    expected = (
        breakdown["security"] * scorer.WEIGHTS["security"]
        + breakdown["cost_efficiency"] * scorer.WEIGHTS["cost_efficiency"]
        + breakdown["context_quality"] * scorer.WEIGHTS["context_quality"]
        + breakdown["reliability"] * scorer.WEIGHTS["reliability"]
    )
    assert result["score"] == pytest.approx(expected, abs=0.02)


def test_trend_detection() -> None:
    scorer = AgentHealthScore()
    improving = scorer.compute(
        {
            "block_rate": 1.0,
            "threat_frequency": 0.0,
            "cost_budget_ratio": 0.0,
            "savings_rate": 1.0,
            "cache_hit_rate": 1.0,
            "loop_frequency": 0.0,
            "error_rate": 0.0,
            "latency_ms": 10,
            "previous_score": 60.0,
        }
    )
    degrading = scorer.compute(
        {
            "block_rate": 0.0,
            "threat_frequency": 0.8,
            "cost_budget_ratio": 1.0,
            "savings_rate": 0.0,
            "cache_hit_rate": 0.0,
            "loop_frequency": 1.0,
            "error_rate": 1.0,
            "latency_ms": 3500,
            "previous_score": 80.0,
        }
    )
    assert improving["trend"] == "improving"
    assert degrading["trend"] == "degrading"


@pytest.mark.asyncio
async def test_health_endpoint_returns_valid(tmp_path: Path) -> None:
    app, decisions_log = _make_app(tmp_path)
    _write_event(decisions_log, agent_id="agent_health", seconds_ago=5, decision="ALLOW", cost=0.3, eval_us=3000)
    _write_event(
        decisions_log,
        agent_id="agent_health",
        seconds_ago=20,
        decision="DENY",
        reason="loop detected",
        cost=0.2,
        eval_us=12000,
    )

    async with await _client(app) as client:
        await client.post("/api/v1/overwatch/agent_health/budget", headers=_auth(), json={"daily_limit": 5.0})
        res = await client.get("/api/v1/agents/agent_health/health", headers=_auth())

    assert res.status_code == 200
    payload = res.json()
    assert payload["agent_id"] == "agent_health"
    assert 0.0 <= float(payload["score"]) <= 100.0
    assert payload["grade"] in {"A+", "A", "B+", "B", "C", "D"}
    assert payload["trend"] in {"improving", "stable", "degrading"}
    assert set(payload["breakdown"].keys()) == {
        "security",
        "cost_efficiency",
        "context_quality",
        "reliability",
    }
