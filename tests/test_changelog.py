from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app


def test_changelog_returns_entries(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy))
    client = TestClient(app)
    response = client.get("/api/v1/changelog")
    assert response.status_code == 200
    payload = response.json()
    assert isinstance(payload.get("entries"), list)
    assert len(payload["entries"]) >= 1


def test_current_version_in_response(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy))
    client = TestClient(app)
    payload = client.get("/api/v1/changelog").json()
    assert payload.get("current_version") == "0.2.1"


def test_entries_have_required_fields(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy))
    client = TestClient(app)
    entries = client.get("/api/v1/changelog").json().get("entries", [])
    assert entries
    required = {"version", "date", "highlights", "changes"}
    for entry in entries:
        assert required.issubset(set(entry.keys()))
