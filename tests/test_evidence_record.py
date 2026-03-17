from __future__ import annotations

import hashlib
import json
from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.evidence_record import EvidenceRecord
from orchesis.telemetry import DecisionEvent


def _sample_decision(session_id: str = "sess-1", decision: str = "ALLOW", cost: float = 0.1) -> DecisionEvent:
    return DecisionEvent(
        event_id="evt-1",
        timestamp="2026-03-17T00:00:00Z",
        agent_id="agent-1",
        tool="web_search",
        params_hash="abc",
        cost=cost,
        decision=decision,
        reasons=[] if decision == "ALLOW" else ["blocked"],
        rules_checked=["budget_limit"],
        rules_triggered=[],
        evaluation_order=["budget_limit"],
        evaluation_duration_us=1234,
        policy_version="v1",
        state_snapshot={"session_id": session_id},
    )


def _hash_without_integrity(record: dict) -> str:
    payload = dict(record)
    payload["integrity"] = dict(payload.get("integrity", {}))
    payload["integrity"]["record_hash"] = ""
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def test_record_has_required_fields() -> None:
    record = EvidenceRecord().build("sess-1", [_sample_decision("sess-1")])
    assert "record_id" in record
    assert record["session_id"] == "sess-1"
    assert "generated_at" in record
    assert "decisions" in record
    assert "summary" in record
    assert "integrity" in record


def test_record_integrity_hash_correct() -> None:
    record = EvidenceRecord().build("sess-1", [_sample_decision("sess-1", "DENY", 0.2)])
    assert record["integrity"]["record_hash"] == _hash_without_integrity(record)


def test_json_export_valid(tmp_path: Path) -> None:
    record = EvidenceRecord().build("sess-1", [_sample_decision("sess-1")])
    out = tmp_path / "evidence.json"
    saved = EvidenceRecord().export_json(record, str(out))
    assert Path(saved).exists()
    loaded = json.loads(Path(saved).read_text(encoding="utf-8"))
    assert loaded["session_id"] == "sess-1"


def test_text_export_readable() -> None:
    record = EvidenceRecord().build("sess-1", [_sample_decision("sess-1")])
    text = EvidenceRecord().export_text(record)
    assert "Orchesis Evidence Record" in text
    assert "Session ID: sess-1" in text
    assert "record_hash:" in text


def test_api_endpoint_returns_record(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    decisions_log = tmp_path / "decisions.jsonl"
    event = _sample_decision("sess-api", "ALLOW", 0.25)
    decisions_log.write_text(json.dumps(event.__dict__, ensure_ascii=False) + "\n", encoding="utf-8")

    app = create_api_app(policy_path=str(policy), decisions_log=str(decisions_log))
    client = TestClient(app)
    pythonresponse = client.get(
        "/api/v1/evidence/sess-api",
        headers={"Authorization": "Bearer test-token"},
    )
    assert pythonresponse.status_code == 200
    payload = pythonresponse.json()
    assert payload["session_id"] == "sess-api"
    assert payload["summary"]["total_requests"] == 1


def test_eu_ai_act_article_referenced() -> None:
    record = EvidenceRecord().build("sess-1", [_sample_decision("sess-1")])
    assert "Article 12" in record["eu_ai_act_article"]
