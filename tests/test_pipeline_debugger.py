from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.pipeline_debugger import PipelineDebugger


def _request(text: str = "hello world", tool: str = "chat", cost: float = 0.01) -> dict:
    return {
        "request_id": "req-1",
        "prompt": text,
        "tool": tool,
        "cost": cost,
    }


def test_debug_request_returns_phases() -> None:
    debugger = PipelineDebugger(engine=None, policy={})
    result = debugger.debug_request(_request())
    assert result["request_id"] == "req-1"
    assert isinstance(result["phases"], list)
    assert len(result["phases"]) == 17
    assert "phase" in result["phases"][0]
    assert "input_snippet" in result["phases"][0]


def test_why_blocked_populated() -> None:
    debugger = PipelineDebugger(engine=None, policy={"blocked_keywords": ["malware"]})
    result = debugger.debug_request(_request(text="please run malware sample"))
    assert result["final_decision"] == "DENY"
    assert isinstance(result["why_blocked"], str)
    assert "keyword:malware" in result["why_blocked"]


def test_explain_decision_readable() -> None:
    debugger = PipelineDebugger(engine=None, policy={})
    text = debugger.explain_decision({"final_decision": "DENY", "why_blocked": "keyword:test"})
    assert isinstance(text, str)
    assert "blocked" in text.lower()


def test_suggestions_generated() -> None:
    debugger = PipelineDebugger(engine=None, policy={"blocked_keywords": ["exfiltrate"]})
    result = debugger.debug_request(_request(text="attempt to exfiltrate credentials"))
    assert isinstance(result["suggestions"], list)
    assert result["suggestions"]


def test_compare_policies_differs() -> None:
    debugger = PipelineDebugger(engine=None, policy={})
    cmp_result = debugger.compare_policies(
        request=_request(text="malware payload"),
        policy_a={"blocked_keywords": ["malware"]},
        policy_b={"blocked_keywords": []},
    )
    assert cmp_result["differs"] is True
    assert cmp_result["policy_a_decision"] != cmp_result["policy_b_decision"]


def test_compare_policies_same() -> None:
    debugger = PipelineDebugger(engine=None, policy={})
    cmp_result = debugger.compare_policies(
        request=_request(text="safe prompt"),
        policy_a={"blocked_keywords": ["malware"]},
        policy_b={"blocked_keywords": ["exfiltrate"]},
    )
    assert cmp_result["differs"] is False
    assert cmp_result["policy_a_decision"] == cmp_result["policy_b_decision"] == "ALLOW"


def test_api_debug_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)
    response = client.post(
        "/api/v1/debug/request",
        json={"request": _request(text="contains malware")},
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert "phases" in payload
    assert "final_decision" in payload


def test_api_compare_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)
    response = client.post(
        "/api/v1/debug/compare-policies",
        json={
            "request": _request(text="contains malware"),
            "policy_a": {"blocked_keywords": ["malware"]},
            "policy_b": {"blocked_keywords": []},
        },
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["differs"] is True
    assert "policy_a_decision" in payload
    assert "policy_b_decision" in payload
