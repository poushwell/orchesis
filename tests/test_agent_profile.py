from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.agent_profile import AgentIntelligenceProfile
from orchesis.api import create_api_app
from orchesis.context_dna import ContextDNA
from orchesis.context_dna_store import ContextDNAStore
from orchesis.telemetry import DecisionEvent


def _decision_event(agent_id: str = "agent-1", tool: str = "web_search", decision: str = "ALLOW", cost: float = 0.1) -> DecisionEvent:
    return DecisionEvent(
        event_id=f"evt-{agent_id}-{tool}-{decision}",
        timestamp="2026-03-17T00:00:00Z",
        agent_id=agent_id,
        tool=tool,
        params_hash="abc",
        cost=cost,
        decision=decision,
        reasons=[] if decision == "ALLOW" else ["rate_limit: exceeded"],
        rules_checked=["budget_limit"],
        rules_triggered=[],
        evaluation_order=["budget_limit"],
        evaluation_duration_us=123,
        policy_version="v1",
        state_snapshot={"tool_counts": {tool: 1}},
    )


def test_profile_builds_correctly(tmp_path: Path) -> None:
    store = ContextDNAStore(str(tmp_path / "dna"))
    dna = ContextDNA("agent-1")
    dna.observe({"messages": [{"role": "user", "content": "hello"}], "tools": ["web_search"], "topic": "research"}, {"duration_ms": 120, "cache_hit": True, "decision": "ALLOW"})
    dna.compute_baseline()
    store.save(dna)
    decisions_log = tmp_path / "decisions.jsonl"
    event = _decision_event(agent_id="agent-1")
    decisions_log.write_text(json.dumps(event.__dict__, ensure_ascii=False) + "\n", encoding="utf-8")
    profile = AgentIntelligenceProfile().build("agent-1", store, {"score": 0.9}, str(decisions_log))
    assert profile["agent_id"] == "agent-1"
    assert "baseline_metrics" in profile
    assert isinstance(profile["reliability_history"], list)
    assert len(profile["reliability_history"]) == 7


def test_profile_cold_start_flag(tmp_path: Path) -> None:
    store = ContextDNAStore(str(tmp_path / "dna"))
    dna = ContextDNA("agent-2")
    dna.compute_baseline()
    store.save(dna)
    decisions_log = tmp_path / "decisions.jsonl"
    decisions_log.write_text("", encoding="utf-8")
    profile = AgentIntelligenceProfile().build("agent-2", store, {"score": 1.0}, str(decisions_log))
    assert profile["cold_start"] is True


def test_detected_patterns_populated(tmp_path: Path) -> None:
    store = ContextDNAStore(str(tmp_path / "dna"))
    decisions_log = tmp_path / "decisions.jsonl"
    events = [
        _decision_event(agent_id="agent-3", tool="web_search"),
        _decision_event(agent_id="agent-3", tool="web_search"),
        _decision_event(agent_id="agent-3", tool="web_search"),
    ]
    decisions_log.write_text(
        "\n".join(json.dumps(item.__dict__, ensure_ascii=False) for item in events) + "\n",
        encoding="utf-8",
    )
    profile = AgentIntelligenceProfile().build("agent-3", store, {"score": 0.8}, str(decisions_log))
    assert any("Uses web_search frequently" in item for item in profile["detected_patterns"])


def test_cost_optimizations_listed(tmp_path: Path) -> None:
    store = ContextDNAStore(str(tmp_path / "dna"))
    dna = ContextDNA("agent-4")
    for _ in range(3):
        dna.observe({"messages": [{"role": "user", "content": "hello world"}]}, {"duration_ms": 100, "cache_hit": True, "decision": "ALLOW"})
    dna.compute_baseline()
    store.save(dna)
    decisions_log = tmp_path / "decisions.jsonl"
    events = [_decision_event(agent_id="agent-4", cost=0.5), _decision_event(agent_id="agent-4", cost=0.4)]
    decisions_log.write_text(
        "\n".join(json.dumps(item.__dict__, ensure_ascii=False) for item in events) + "\n",
        encoding="utf-8",
    )
    profile = AgentIntelligenceProfile().build("agent-4", store, {"score": 0.95}, str(decisions_log))
    assert any("Saved $" in item for item in profile["cost_optimizations"])


def test_api_endpoint_returns_profile(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    decisions_log = tmp_path / "decisions.jsonl"
    event = _decision_event(agent_id="agent-api", tool="web_search", cost=0.25)
    decisions_log.write_text(json.dumps(event.__dict__, ensure_ascii=False) + "\n", encoding="utf-8")
    dna_store = ContextDNAStore(str(tmp_path / ".orchesis" / "dna"))
    dna = ContextDNA("agent-api")
    dna.observe({"messages": [{"role": "user", "content": "find docs"}], "tools": ["web_search"], "topic": "research"}, {"duration_ms": 100, "cache_hit": True, "decision": "ALLOW"})
    dna.compute_baseline()
    dna_store.save(dna)

    app = create_api_app(policy_path=str(policy), decisions_log=str(decisions_log))
    client = TestClient(app)
    response = client.get("/api/v1/agents/agent-api/profile", headers={"Authorization": "Bearer test-token"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["agent_id"] == "agent-api"
    assert "baseline_metrics" in payload
    assert "reliability_history" in payload

