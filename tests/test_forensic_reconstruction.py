from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.forensic_reconstruction import ForensicReconstructor


def _decisions() -> list[dict]:
    return [
        {
            "request_id": "req-1",
            "timestamp": "2026-03-19T10:00:00Z",
            "agent_id": "agent-a",
            "decision": "ALLOW",
            "reasons": ["ok"],
            "message_count": 5,
            "tokens": 800,
            "state_snapshot": {"phase": "model_router", "psi": 0.42},
            "phases": ["guardrails", "model_router", "cost_optimizer"],
            "hash": "abc123",
        },
        {
            "request_id": "req-0",
            "timestamp": "2026-03-19T09:59:00Z",
            "agent_id": "agent-a",
            "decision": "DENY",
            "reasons": ["rate_limit"],
        },
    ]


def test_reconstruct_from_log() -> None:
    reconstructor = ForensicReconstructor()
    result = reconstructor.reconstruct("req-1", _decisions())
    assert result["request_id"] == "req-1"
    assert result["decision"] == "ALLOW"


def test_missing_request_returns_error() -> None:
    reconstructor = ForensicReconstructor()
    result = reconstructor.reconstruct("missing", _decisions())
    assert "error" in result


def test_causal_chain_found() -> None:
    reconstructor = ForensicReconstructor()
    chain = reconstructor.find_causal_chain("req-1", _decisions())
    assert len(chain) == 1
    assert chain[0]["request_id"] == "req-0"


def test_forensic_report_generated() -> None:
    reconstructor = ForensicReconstructor()
    report = reconstructor.generate_forensic_report("req-1", _decisions())
    assert report["request_id"] == "req-1"
    assert "reconstruction" in report
    assert report["chain_length"] == 1


def test_eu_ai_act_compliant_flag() -> None:
    reconstructor = ForensicReconstructor()
    result = reconstructor.reconstruct("req-1", _decisions())
    assert result["eu_ai_act_compliant"] is True


def test_context_snapshot_included() -> None:
    reconstructor = ForensicReconstructor()
    result = reconstructor.reconstruct("req-1", _decisions())
    snapshot = result["context_snapshot"]
    assert snapshot["messages_seen"] == 5
    assert snapshot["estimated_tokens"] == 800
    assert snapshot["phase"] == "model_router"


def test_api_reconstruct_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    decisions = tmp_path / "decisions.jsonl"
    event = {
        "event_id": "req-1",
        "timestamp": "2026-03-19T10:00:00Z",
        "agent_id": "agent-a",
        "tool": "read_file",
        "params_hash": "h",
        "cost": 0.1,
        "decision": "ALLOW",
        "reasons": ["ok"],
        "rules_checked": [],
        "rules_triggered": [],
        "evaluation_order": [],
        "evaluation_duration_us": 100,
        "policy_version": "v1",
        "state_snapshot": {"tool_counts": {}, "phase": "guard", "psi": 0.2},
    }
    decisions.write_text(json.dumps(event) + "\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(decisions))
    client = TestClient(app)
    response = client.post(
        "/api/v1/forensic/reconstruct",
        json={"request_id": "req-1"},
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["request_id"] == "req-1"
    assert payload["agent_id"] == "agent-a"


def test_stats_tracked() -> None:
    reconstructor = ForensicReconstructor()
    _ = reconstructor.reconstruct("req-1", _decisions())
    stats = reconstructor.get_stats()
    assert stats["cached_reconstructions"] == 1
    assert "log_path" in stats
