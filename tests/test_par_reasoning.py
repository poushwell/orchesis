from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.par_reasoning import PARReasoner


def test_abductive_mode_below_threshold() -> None:
    reasoner = PARReasoner({"abductive_threshold": 4})
    reasoner.observe({"event": "a"})
    out = reasoner.abduce({"reasons": ["quota_exceeded"]})
    assert out["mode"] == "abductive"


def test_causal_mode_above_threshold() -> None:
    reasoner = PARReasoner({"abductive_threshold": 2})
    reasoner.observe({"event": "a"})
    reasoner.observe({"event": "b"})
    out = reasoner.abduce({"reasons": ["policy_violation"]})
    assert out["mode"] == "causal"


def test_abduce_generates_hypothesis() -> None:
    reasoner = PARReasoner()
    out = reasoner.abduce({"reasons": ["blocked_by_rule"]})
    assert out["best_explanation"] is not None
    assert "Caused by:" in out["best_explanation"]["hypothesis"]


def test_confidence_grows_with_observations() -> None:
    reasoner = PARReasoner({"abductive_threshold": 8})
    low = reasoner._compute_confidence(1)
    high = reasoner._compute_confidence(20)
    assert high > low


def test_t5_applies_flag() -> None:
    reasoner = PARReasoner({"abductive_threshold": 3})
    reasoner.observe({"id": 1})
    out = reasoner.abduce({"reasons": ["deny"]})
    assert out["t5_applies"] is True


def test_causal_graph_returned() -> None:
    reasoner = PARReasoner({"abductive_threshold": 3})
    reasoner.observe({"id": 1})
    graph = reasoner.get_causal_graph()
    assert graph["nodes"] == 1
    assert "completeness" in graph
    assert graph["mode"] == "abductive"


def test_api_abduce_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy_path), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)
    headers = {"Authorization": "Bearer test-token"}

    client.post("/api/v1/par/observe", json={"agent_id": "a1", "event": "deny"}, headers=headers)
    response = client.post(
        "/api/v1/par/abduce",
        json={"reasons": ["quota_exceeded", "policy_block"]},
        headers=headers,
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["mode"] in {"abductive", "causal"}
    assert payload["best_explanation"] is not None


def test_api_causal_graph_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy_path), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)
    headers = {"Authorization": "Bearer test-token"}

    client.post("/api/v1/par/observe", json={"agent_id": "a1", "event": "deny"}, headers=headers)
    response = client.get("/api/v1/par/causal-graph", headers=headers)
    assert response.status_code == 200
    payload = response.json()
    assert payload["nodes"] >= 1
    assert "t5_limitation" in payload

