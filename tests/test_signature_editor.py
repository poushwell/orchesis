from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.signature_editor import SignatureEditor


def _sample_signature(sig_id: str = "custom-001") -> dict:
    return {
        "id": sig_id,
        "name": "Prompt injection detector",
        "category": "prompt_injection",
        "severity": "high",
        "pattern": r"ignore\s+all\s+previous",
        "description": "Detect classic instruction override.",
        "enabled": True,
        "tags": ["prompt", "injection"],
    }


def test_create_signature_valid(tmp_path: Path) -> None:
    editor = SignatureEditor(str(tmp_path / "signatures.json"))
    created = editor.create(_sample_signature())
    assert created["id"] == "custom-001"
    assert created["severity"] == "high"
    assert created["created_at"]


def test_create_signature_invalid_pattern(tmp_path: Path) -> None:
    editor = SignatureEditor(str(tmp_path / "signatures.json"))
    bad = _sample_signature("custom-002")
    bad["pattern"] = r"([a-z"
    with pytest.raises(ValueError):
        editor.create(bad)


def test_update_signature(tmp_path: Path) -> None:
    editor = SignatureEditor(str(tmp_path / "signatures.json"))
    editor.create(_sample_signature())
    updated = editor.update("custom-001", {"severity": "critical", "enabled": False})
    assert updated["severity"] == "critical"
    assert updated["enabled"] is False


def test_delete_signature(tmp_path: Path) -> None:
    editor = SignatureEditor(str(tmp_path / "signatures.json"))
    editor.create(_sample_signature())
    assert editor.delete("custom-001") is True
    assert editor.delete("custom-001") is False


def test_list_by_category(tmp_path: Path) -> None:
    editor = SignatureEditor(str(tmp_path / "signatures.json"))
    one = _sample_signature("custom-001")
    two = _sample_signature("custom-002")
    two["category"] = "credential"
    editor.create(one)
    editor.create(two)
    rows = editor.list_all(category="credential")
    assert len(rows) == 1
    assert rows[0]["id"] == "custom-002"


def test_pattern_test_safe(tmp_path: Path) -> None:
    editor = SignatureEditor(str(tmp_path / "signatures.json"))
    result = editor.test_pattern(r"(a+)+$", "a" * 2000)
    assert result["safe"] is False


def test_pattern_test_matches(tmp_path: Path) -> None:
    editor = SignatureEditor(str(tmp_path / "signatures.json"))
    result = editor.test_pattern(r"token-[0-9]+", "ok token-123 and token-456")
    assert result["safe"] is True
    assert result["matched"] is True
    assert "token-123" in result["matches"]


def test_export_import_roundtrip(tmp_path: Path) -> None:
    src = SignatureEditor(str(tmp_path / "src.json"))
    src.create(_sample_signature())
    yaml_path = tmp_path / "sig.yaml"
    src.export_yaml(str(yaml_path))

    dst = SignatureEditor(str(tmp_path / "dst.json"))
    imported = dst.import_yaml(str(yaml_path))
    assert imported == 1
    rows = dst.list_all()
    assert len(rows) == 1
    assert rows[0]["id"] == "custom-001"


def test_api_crud_endpoints(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)
    headers = {"Authorization": "Bearer test-token"}

    create_resp = client.post("/api/v1/signatures", json=_sample_signature(), headers=headers)
    assert create_resp.status_code == 200
    assert create_resp.json()["id"] == "custom-001"

    get_resp = client.get("/api/v1/signatures/custom-001", headers=headers)
    assert get_resp.status_code == 200
    assert get_resp.json()["name"] == "Prompt injection detector"

    update_resp = client.put("/api/v1/signatures/custom-001", json={"severity": "critical"}, headers=headers)
    assert update_resp.status_code == 200
    assert update_resp.json()["severity"] == "critical"

    list_resp = client.get("/api/v1/signatures?category=prompt_injection", headers=headers)
    assert list_resp.status_code == 200
    assert len(list_resp.json()["signatures"]) == 1

    test_resp = client.post(
        "/api/v1/signatures/test-pattern",
        json={"pattern": r"token-[0-9]+", "test_text": "token-7"},
        headers=headers,
    )
    assert test_resp.status_code == 200
    assert test_resp.json()["matched"] is True

    delete_resp = client.delete("/api/v1/signatures/custom-001", headers=headers)
    assert delete_resp.status_code == 200
    assert delete_resp.json()["deleted"] is True
