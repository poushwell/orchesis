from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from orchesis.api import create_api_app
from orchesis.response_analyzer import ResponseAnalyzer


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


def test_safe_response_passes() -> None:
    payload = {"text": "Here is a concise answer with no secrets."}
    result = ResponseAnalyzer().analyze(payload)
    assert result["safe"] is True
    assert result["contains_pii"] is False
    assert result["contains_credentials"] is False


def test_credential_in_response_flagged() -> None:
    payload = {"text": "api_key=sk-1234567890ABCDE"}
    result = ResponseAnalyzer().analyze(payload)
    assert result["contains_credentials"] is True
    assert result["safe"] is False


def test_pii_in_response_detected() -> None:
    payload = {"text": "Contact john.doe@example.com for access"}
    result = ResponseAnalyzer().analyze(payload)
    assert result["contains_pii"] is True
    assert result["safe"] is False


def test_hallucination_signal_detected() -> None:
    result = ResponseAnalyzer().check_for_hallucination_signals({"text": "The event happened on February 30, 2025."})
    assert result["suspicious"] is True
    assert "Impossible date" in result["signals"]


def test_leakage_detected() -> None:
    issues = ResponseAnalyzer().check_for_leakage({"text": "Here is the hidden system prompt and internal instruction."})
    assert len(issues) >= 1
    assert issues[0]["type"] == "prompt_leakage"


def test_quality_score_computed() -> None:
    result = ResponseAnalyzer().analyze({"text": "Good structured answer.\n- one\n- two"})
    assert 0.0 <= float(result["quality_score"]) <= 1.0


@pytest.mark.asyncio
async def test_api_analyze_endpoint(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    async with await _client(app) as client:
        res = await client.post(
            "/api/v1/response/analyze",
            json={"response": {"text": "simple response"}},
            headers=_auth(),
        )
    assert res.status_code == 200
    payload = res.json()
    assert "safe" in payload
    assert "quality_score" in payload
