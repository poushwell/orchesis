from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from orchesis.api import create_api_app
from orchesis.session_forensics import SessionForensics


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


def _event(session_id: str, *, tokens: int, decision: str = "ALLOW", phase: str = "LIQUID") -> dict:
    return {
        "timestamp": "2026-03-19T00:00:00Z",
        "decision": decision,
        "reasons": [],
        "tokens": tokens,
        "state_snapshot": {"session_id": session_id, "phase": phase},
        "session_id": session_id,
    }


def _write_events(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n",
        encoding="utf-8",
    )


def test_analysis_performed() -> None:
    engine = SessionForensics()
    result = engine.analyze("sess-1", [_event("sess-1", tokens=100), _event("sess-1", tokens=120)])
    assert result["session_id"] == "sess-1"
    assert result["duration_requests"] == 2


def test_token_growth_detected() -> None:
    engine = SessionForensics()
    result = engine.analyze("sess-1", [_event("sess-1", tokens=100), _event("sess-1", tokens=250)])
    assert result["token_growth"]["growth_factor"] == 2.5


def test_context_collapse_anomaly() -> None:
    engine = SessionForensics()
    result = engine.analyze("sess-1", [_event("sess-1", tokens=100), _event("sess-1", tokens=401)])
    assert "context_collapse" in result["anomalies"]


def test_decision_pattern_computed() -> None:
    engine = SessionForensics()
    result = engine.analyze(
        "sess-1",
        [
            _event("sess-1", tokens=100, decision="ALLOW"),
            _event("sess-1", tokens=120, decision="DENY"),
        ],
    )
    assert result["decision_pattern"]["total"] == 2
    assert result["decision_pattern"]["deny"] == 1


def test_phase_transitions_tracked() -> None:
    engine = SessionForensics()
    result = engine.analyze(
        "sess-1",
        [
            _event("sess-1", tokens=100, phase="LIQUID"),
            _event("sess-1", tokens=120, phase="LIQUID"),
            _event("sess-1", tokens=140, phase="CRYSTAL"),
        ],
    )
    assert result["phase_transitions"] == ["LIQUID", "CRYSTAL"]


def test_health_score_computed() -> None:
    engine = SessionForensics()
    result = engine.analyze(
        "sess-1",
        [
            _event("sess-1", tokens=100, decision="DENY"),
            _event("sess-1", tokens=450, decision="DENY"),
        ],
    )
    assert 0.0 <= float(result["health_score"]) <= 1.0


@pytest.mark.asyncio
async def test_api_analyze_endpoint(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    decisions_path = tmp_path / "decisions.jsonl"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    _write_events(decisions_path, [_event("sess-1", tokens=100), _event("sess-1", tokens=150)])
    app = create_api_app(
        policy_path=str(policy_path),
        decisions_log=str(decisions_path),
        state_persist=str(tmp_path / "state.jsonl"),
        history_path=str(tmp_path / "history.jsonl"),
    )
    async with await _client(app) as client:
        res = await client.post("/api/v1/forensics/session/sess-1/analyze", headers=_auth())
    assert res.status_code == 200
    assert res.json()["session_id"] == "sess-1"


@pytest.mark.asyncio
async def test_api_get_endpoint(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    decisions_path = tmp_path / "decisions.jsonl"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    _write_events(decisions_path, [_event("sess-1", tokens=100), _event("sess-1", tokens=150)])
    app = create_api_app(
        policy_path=str(policy_path),
        decisions_log=str(decisions_path),
        state_persist=str(tmp_path / "state.jsonl"),
        history_path=str(tmp_path / "history.jsonl"),
    )
    async with await _client(app) as client:
        await client.post("/api/v1/forensics/session/sess-1/analyze", headers=_auth())
        res = await client.get("/api/v1/forensics/session/sess-1", headers=_auth())
    assert res.status_code == 200
    assert res.json()["session_id"] == "sess-1"
