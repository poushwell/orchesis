from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from orchesis.api import create_api_app
from orchesis.relevance_theory import RelevanceScorer


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


def _make_app(tmp_path: Path):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    return create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )


def test_cognitive_effects_novel_content() -> None:
    scorer = RelevanceScorer({})
    context = [{"content": "existing baseline terms only"}]
    effects = scorer.compute_cognitive_effects({"content": "novel alpha beta insight"}, context)
    assert effects > 0.4


def test_processing_effort_long_message() -> None:
    scorer = RelevanceScorer({})
    message = {"content": "x" * 2200}
    effort = scorer.compute_processing_effort(message)
    assert effort >= 0.5


def test_relevance_score_computed() -> None:
    scorer = RelevanceScorer({})
    out = scorer.score({"content": "new actionable fix"}, [{"content": "old baseline"}])
    assert "relevance" in out
    assert 0.0 <= float(out["relevance"]) <= 1.0


def test_high_relevance_novel_short() -> None:
    scorer = RelevanceScorer({})
    out = scorer.score({"content": "zero day mitigation patch now"}, [{"content": "routine status update"}])
    assert out["keep"] is True
    assert float(out["relevance"]) > 0.3


def test_low_relevance_repetitive() -> None:
    scorer = RelevanceScorer({})
    repeated = "status status status status status " * 120
    context = [{"content": repeated}]
    out = scorer.score({"content": repeated}, context)
    assert out["keep"] is False
    assert float(out["relevance"]) <= 0.3


def test_rank_messages_by_relevance() -> None:
    scorer = RelevanceScorer({})
    messages = [
        {"role": "user", "content": "status ok"},
        {"role": "assistant", "content": "urgent exploit mitigation and containment guide"},
        {"role": "user", "content": "status ok status ok status ok"},
    ]
    ranked = scorer.rank_messages(messages)
    assert len(ranked) == 3
    assert float(ranked[0]["relevance"]) >= float(ranked[-1]["relevance"])


@pytest.mark.asyncio
async def test_api_score_endpoint(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    async with await _client(app) as client:
        res = await client.post(
            "/api/v1/relevance/score",
            headers=_auth(),
            json={
                "message": {"role": "user", "content": "novel policy anomaly signal"},
                "context": [{"content": "routine update"}],
            },
        )
    assert res.status_code == 200
    payload = res.json()
    assert "relevance" in payload
    assert "keep" in payload


@pytest.mark.asyncio
async def test_stats_tracked(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    async with await _client(app) as client:
        await client.post(
            "/api/v1/relevance/score",
            headers=_auth(),
            json={
                "message": {"role": "user", "content": "novel attack pattern"},
                "context": [{"content": "known baseline"}],
            },
        )
        res = await client.get("/api/v1/relevance/stats", headers=_auth())
    assert res.status_code == 200
    payload = res.json()
    assert payload["scored"] >= 1
