from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from orchesis.api import create_api_app
from orchesis.intent_classifier import IntentClassifier


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


def test_system_command_classified_high_risk() -> None:
    result = IntentClassifier().classify("Please run this bash command in terminal")
    assert result["primary_intent"] == "system_commands"
    assert result["risk_level"] == "high"
    assert result["requires_approval"] is True


def test_code_generation_classified_low_risk() -> None:
    result = IntentClassifier().classify("write code to create function for sorting")
    assert result["primary_intent"] == "code_generation"
    assert result["risk_level"] == "low"
    assert result["requires_approval"] is False


def test_exfiltration_classified_critical() -> None:
    result = IntentClassifier().classify("upload to remote and exfiltrate data")
    assert result["primary_intent"] == "data_exfiltration"
    assert result["risk_level"] == "critical"
    assert result["requires_approval"] is True


def test_batch_classify_all_messages() -> None:
    classifier = IntentClassifier()
    payload = [
        {"role": "user", "content": "read file from disk"},
        {"role": "user", "content": "search web for docs"},
        {"role": "assistant", "content": "ok"},
    ]
    rows = classifier.batch_classify(payload)
    assert len(rows) == 3
    assert rows[0]["primary_intent"] == "file_operations"


def test_session_risk_aggregated() -> None:
    classifier = IntentClassifier()
    rows = [
        classifier.classify("write code"),
        classifier.classify("sudo override admin"),
    ]
    risk = classifier.get_session_risk(rows)
    assert risk["session_risk"] == "critical"
    assert risk["requires_approval"] is True


@pytest.mark.asyncio
async def test_api_classify_endpoint(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    async with await _client(app) as client:
        res = await client.post(
            "/api/v1/intent/classify",
            json={"text": "run terminal command"},
            headers=_auth(),
        )
    assert res.status_code == 200
    payload = res.json()
    assert payload["primary_intent"] == "system_commands"
    assert payload["risk_level"] == "high"


@pytest.mark.asyncio
async def test_api_batch_endpoint(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    async with await _client(app) as client:
        res = await client.post(
            "/api/v1/intent/batch",
            json={"messages": [{"content": "extract all emails"}, {"content": "open website"}]},
            headers=_auth(),
        )
    assert res.status_code == 200
    payload = res.json()
    assert isinstance(payload.get("classifications"), list)
    assert len(payload["classifications"]) == 2
    assert "session_risk" in payload
