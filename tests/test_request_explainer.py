from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.request_explainer import RequestExplainer


def test_allow_explained() -> None:
    explainer = RequestExplainer()
    out = explainer.explain({"decision": "ALLOW", "reasons": []})
    assert out["decision"] == "ALLOW"
    assert "allowed" in out["plain_english"].lower()


def test_deny_explained() -> None:
    explainer = RequestExplainer()
    out = explainer.explain({"decision": "DENY", "reasons": ["prompt_injection"]})
    assert out["decision"] == "DENY"
    assert "blocked" in out["plain_english"].lower()


def test_plain_english_generated() -> None:
    explainer = RequestExplainer()
    out = explainer.explain({"decision": "DENY", "reasons": ["content_blocked"]})
    assert isinstance(out["plain_english"], str)
    assert len(out["plain_english"]) > 10


def test_eu_ai_act_article_present() -> None:
    explainer = RequestExplainer()
    out = explainer.explain({"decision": "ALLOW"})
    assert "Article 13" in out["eu_ai_act_article"]


def test_appeal_possible_on_deny() -> None:
    explainer = RequestExplainer()
    deny = explainer.explain({"decision": "DENY", "reasons": ["rate_limited"]})
    allow = explainer.explain({"decision": "ALLOW", "reasons": []})
    assert deny["appeal_possible"] is True
    assert allow["appeal_possible"] is False


def test_session_explained() -> None:
    explainer = RequestExplainer()
    out = explainer.explain_session(
        [
            {"decision": "ALLOW", "reasons": []},
            {"decision": "DENY", "reasons": ["budget_exceeded"]},
            {"decision": "DENY", "reasons": ["rate_limited"]},
        ]
    )
    assert out["total_requests"] == 3
    assert out["denied"] == 2
    assert out["deny_rate"] == 0.6667


def test_top_reasons_extracted() -> None:
    explainer = RequestExplainer()
    top = explainer._top_reasons(
        [
            {"decision": "DENY", "reasons": ["budget_exceeded", "rate_limited"]},
            {"decision": "DENY", "reasons": ["budget_exceeded"]},
            {"decision": "DENY", "reasons": ["prompt_injection"]},
        ]
    )
    assert top[0] == "budget_exceeded"
    assert len(top) <= 3


def test_api_explain_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy_path), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)
    response = client.post(
        "/api/v1/explain/decision",
        json={"decision": "DENY", "reasons": ["prompt_injection"]},
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["decision"] == "DENY"
    assert "plain_english" in payload

