from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.knowledge_base import OrchesisKnowledgeBase


def test_search_returns_results() -> None:
    kb = OrchesisKnowledgeBase()
    rows = kb.search("orchesis")
    assert rows
    assert any("orchesis" in row["title"].lower() or "orchesis" in row["content"].lower() for row in rows)


def test_search_empty_returns_empty() -> None:
    kb = OrchesisKnowledgeBase()
    assert kb.search("") == []


def test_get_article_by_id() -> None:
    kb = OrchesisKnowledgeBase()
    article = kb.get_article("quick_start")
    assert article is not None
    assert article["title"] == "Quick Start Guide"


def test_list_by_tag() -> None:
    kb = OrchesisKnowledgeBase()
    rows = kb.list_by_tag("compliance")
    assert rows
    assert any(row["article_id"] == "eu_ai_act" for row in rows)


def test_suggest_for_error() -> None:
    kb = OrchesisKnowledgeBase()
    rows = kb.suggest_for_error("401 unauthorized token invalid")
    assert rows
    assert any(row["article_id"] == "quick_start" for row in rows)


def test_add_custom_article() -> None:
    kb = OrchesisKnowledgeBase()
    ok = kb.add_article(
        "custom_runbook",
        {
            "title": "Custom Runbook",
            "content": "How to run internal on-call playbooks.",
            "tags": ["ops", "runbook"],
        },
    )
    assert ok is True
    article = kb.get_article("custom_runbook")
    assert article is not None
    assert article["title"] == "Custom Runbook"


def test_api_search_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)
    response = client.get("/api/v1/kb/search?q=token", headers={"Authorization": "Bearer test-token"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] >= 1


def test_api_suggest_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)
    response = client.post(
        "/api/v1/kb/suggest-for-error",
        json={"error_message": "budget exceeded and token yield dropped"},
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] >= 1
    assert any(row["article_id"] == "token_yield" for row in payload["suggestions"])
