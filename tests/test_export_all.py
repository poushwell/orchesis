from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.dashboard import get_dashboard_html


def _event(event_id: str) -> dict:
    return {
        "event_id": event_id,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "agent_id": "agent-export",
        "tool": "web_search",
        "params_hash": "abc",
        "cost": 0.1,
        "decision": "ALLOW",
        "reasons": [],
        "rules_checked": [],
        "rules_triggered": [],
        "evaluation_order": ["parse", "policy", "send"],
        "evaluation_duration_us": 1200,
        "policy_version": "v1",
        "state_snapshot": {"session_id": "sess-export", "model": "gpt-4o-mini"},
    }


def _make_app(tmp_path: Path):
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    decisions = tmp_path / "decisions.jsonl"
    decisions.write_text(json.dumps(_event("req-1"), ensure_ascii=False) + "\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(decisions))
    return app


def _get_zip(client: TestClient) -> zipfile.ZipFile:
    response = client.get("/api/v1/export/all", headers={"Authorization": "Bearer test-token"})
    assert response.status_code == 200
    assert response.headers.get("content-type", "").startswith("application/zip")
    return zipfile.ZipFile(io.BytesIO(response.content))


def test_export_returns_zip(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    client = TestClient(app)
    zf = _get_zip(client)
    assert len(zf.namelist()) >= 1


def test_zip_contains_manifest(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    client = TestClient(app)
    zf = _get_zip(client)
    assert "export_manifest.json" in zf.namelist()


def test_zip_contains_decisions(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    client = TestClient(app)
    zf = _get_zip(client)
    assert "decisions.jsonl" in zf.namelist()
    text = zf.read("decisions.jsonl").decode("utf-8")
    assert "req-1" in text


def test_manifest_has_metadata(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    client = TestClient(app)
    zf = _get_zip(client)
    manifest = json.loads(zf.read("export_manifest.json").decode("utf-8"))
    assert "exported_at" in manifest
    assert "files" in manifest
    assert "decisions_count" in manifest
    assert "agents_count" in manifest


def test_dashboard_export_button_present() -> None:
    html = get_dashboard_html()
    assert 'id="export-all-btn"' in html
    assert "onclick=\"exportAll()\"" in html
    assert "function exportAll()" in html
