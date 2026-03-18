from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

from orchesis.api import create_api_app
from orchesis.policy_optimizer import PolicyOptimizer


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


def _event(agent_id: str, cost: float, cache_hit_rate: float = 0.5) -> dict:
    return {
        "event_id": f"evt-{agent_id}-{cost}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent_id": agent_id,
        "tool": "chat",
        "params_hash": "abc",
        "cost": cost,
        "decision": "ALLOW",
        "reasons": [],
        "rules_checked": [],
        "rules_triggered": [],
        "evaluation_order": [],
        "evaluation_duration_us": 100,
        "policy_version": "v1",
        "state_snapshot": {"cache_hit_rate": cache_hit_rate},
    }


def _write_events(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(item, ensure_ascii=False) for item in rows) + "\n", encoding="utf-8")


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


def test_suggestions_generated() -> None:
    optimizer = PolicyOptimizer()
    rows = [_event("a", 0.1), _event("a", 0.2), _event("b", 1.2, 0.2)]
    out = optimizer.analyze(rows, {"rules": []})
    assert isinstance(out["suggested_changes"], list)
    assert len(out["suggested_changes"]) >= 1


def test_rate_limit_suggestion() -> None:
    optimizer = PolicyOptimizer()
    rows = [_event("agent-x", 0.01) for _ in range(20)]
    suggestion = optimizer.suggest_rate_limits(rows)
    assert suggestion["type"] == "rate_limit"
    assert suggestion["value"] >= 30


def test_cache_threshold_suggestion() -> None:
    optimizer = PolicyOptimizer()
    rows = [_event("a", 0.01, cache_hit_rate=0.1), _event("a", 0.01, cache_hit_rate=0.2)]
    suggestion = optimizer.suggest_cache_settings(rows)
    assert suggestion["type"] == "cache"
    assert isinstance(suggestion["value"], float)


def test_budget_suggestion() -> None:
    optimizer = PolicyOptimizer()
    rows = [_event("agent-a", 1.0), _event("agent-a", 2.0), _event("agent-b", 0.2)]
    suggestion = optimizer.suggest_budget_limits(rows)
    assert suggestion["type"] == "budget"
    assert suggestion["value"] >= 1.0


def test_impact_estimated() -> None:
    optimizer = PolicyOptimizer()
    impact = optimizer.estimate_impact({"type": "cache"}, [_event("a", 0.1)])
    assert "cost_change" in impact
    assert "security_change" in impact
    assert "performance_change" in impact


def test_apply_suggestions() -> None:
    optimizer = PolicyOptimizer()
    policy = {"rules": [], "semantic_cache": {"similarity_threshold": 0.85}}
    suggestions = [{"path": "semantic_cache.similarity_threshold", "value": 0.9}]
    out = optimizer.apply_suggestions(policy, suggestions)
    assert out["semantic_cache"]["similarity_threshold"] == 0.9


@pytest.mark.asyncio
async def test_api_optimize_endpoint(tmp_path: Path) -> None:
    app, decisions_log = _make_app(tmp_path)
    _write_events(decisions_log, [_event("a", 0.2), _event("a", 0.3), _event("b", 1.2, 0.1)])
    async with await _client(app) as client:
        res = await client.post("/api/v1/policy/optimize", json={}, headers=_auth())
    assert res.status_code == 200
    payload = res.json()
    assert "suggested_changes" in payload
    assert "expected_improvements" in payload
