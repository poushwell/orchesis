from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

from orchesis.api import create_api_app
from orchesis.cache_warmer import CacheWarmer
from orchesis.semantic_cache import SemanticCache


def _policy_yaml() -> str:
    return """
api:
  token: "orch_sk_test"
rules: []
semantic_cache:
  enabled: true
  min_content_length: 1
"""


def _auth() -> dict[str, str]:
    return {"Authorization": "Bearer orch_sk_test"}


async def _client(app):
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


def _event(
    query: str,
    *,
    timestamp: str | None = None,
    tokens: int = 100,
    cost: float = 0.1,
    model: str = "gpt-4o-mini",
) -> dict:
    return {
        "event_id": f"evt-{abs(hash((query, timestamp or 'now')))}",
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        "agent_id": "agent_cache",
        "tool": "chat.completions",
        "params_hash": "abc123",
        "decision": "ALLOW",
        "reasons": [],
        "rules_checked": [],
        "rules_triggered": [],
        "evaluation_order": [],
        "evaluation_duration_us": 100,
        "policy_version": "v1",
        "cost": cost,
        "state_snapshot": {
            "query": query,
            "prompt_tokens": tokens,
            "completion_tokens": max(1, tokens // 4),
            "model": model,
        },
        "decision_reason": None,
        "credentials_injected": [],
        "signature": None,
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


def test_analyze_finds_frequent_queries() -> None:
    cache = SemanticCache({"enabled": True, "min_content_length": 1})
    warmer = CacheWarmer(cache, {"min_frequency": 3, "max_entries": 20})
    rows = [_event("how to reset password?") for _ in range(4)] + [_event("other", tokens=50)]
    candidates = warmer.analyze_history(rows)
    assert len(candidates) == 1
    assert candidates[0]["query"] == "how to reset password?"
    assert candidates[0]["frequency"] == 4


def test_warm_populates_cache() -> None:
    cache = SemanticCache({"enabled": True, "min_content_length": 1})
    warmer = CacheWarmer(cache, {"min_frequency": 1, "max_entries": 10})
    candidates = [
        {"query": "frequent prompt", "frequency": 6, "avg_tokens": 120, "estimated_savings": 0.8, "model": "gpt-4o-mini"}
    ]
    report = warmer.warm(candidates)
    stats = cache.get_stats()
    assert report["warmed"] == 1
    assert stats["entries"] >= 1


def test_min_frequency_filter() -> None:
    cache = SemanticCache({"enabled": True, "min_content_length": 1})
    warmer = CacheWarmer(cache, {"min_frequency": 3})
    rows = [_event("alpha") for _ in range(2)] + [_event("beta") for _ in range(3)]
    candidates = warmer.analyze_history(rows)
    assert len(candidates) == 1
    assert candidates[0]["query"] == "beta"


def test_warming_report_generated() -> None:
    cache = SemanticCache({"enabled": True, "min_content_length": 1})
    warmer = CacheWarmer(cache, {"min_frequency": 1})
    _ = warmer.warm([{"query": "hello", "frequency": 1, "avg_tokens": 20, "estimated_savings": 0.2}])
    report = warmer.get_warming_report()
    assert "generated_at" in report
    assert "warmed" in report
    assert "estimated_savings_per_run" in report


@pytest.mark.asyncio
async def test_api_warm_endpoint(tmp_path: Path) -> None:
    app, decisions_log = _make_app(tmp_path)
    rows = [_event("common question", tokens=120) for _ in range(4)] + [_event("rare question", tokens=50)]
    _write_events(decisions_log, rows)
    async with await _client(app) as client:
        res = await client.post("/api/v1/cache/warm", json={"limit": 10}, headers=_auth())
    assert res.status_code == 200
    payload = res.json()
    assert payload["warmed"] >= 1
    assert "cache_stats" in payload
    assert payload["cache_stats"]["entries"] >= 1


@pytest.mark.asyncio
async def test_candidates_ranked_by_frequency(tmp_path: Path) -> None:
    app, decisions_log = _make_app(tmp_path)
    rows = []
    rows.extend([_event("q-high", tokens=100) for _ in range(6)])
    rows.extend([_event("q-mid", tokens=100) for _ in range(4)])
    rows.extend([_event("q-low", tokens=100) for _ in range(3)])
    _write_events(decisions_log, rows)
    async with await _client(app) as client:
        res = await client.get("/api/v1/cache/warm/candidates?limit=3", headers=_auth())
    assert res.status_code == 200
    payload = res.json()
    assert payload["total"] == 3
    candidates = payload["candidates"]
    assert candidates[0]["query"] == "q-high"
    assert candidates[1]["query"] == "q-mid"
