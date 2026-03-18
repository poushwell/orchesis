from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.tenants import TenantManager


def test_create_tenant(tmp_path: Path) -> None:
    mgr = TenantManager(str(tmp_path / "tenants"))
    row = mgr.create_tenant("team-a", {"rules": [{"name": "a"}], "limits": {"daily": 10}})
    assert row["tenant_id"] == "team-a"
    assert row["policy"]["limits"]["daily"] == 10


def test_get_tenant_policy(tmp_path: Path) -> None:
    mgr = TenantManager(str(tmp_path / "tenants"))
    mgr.create_tenant("team-a", {"x": 1})
    policy = mgr.get_policy("team-a")
    assert policy == {"x": 1}


def test_update_tenant_policy(tmp_path: Path) -> None:
    mgr = TenantManager(str(tmp_path / "tenants"))
    mgr.create_tenant("team-a", {"x": 1})
    row = mgr.update_policy("team-a", {"x": 2, "y": 3})
    assert row["policy"]["x"] == 2
    assert row["policy"]["y"] == 3


def test_delete_tenant(tmp_path: Path) -> None:
    mgr = TenantManager(str(tmp_path / "tenants"))
    mgr.create_tenant("team-a", {"x": 1})
    assert mgr.delete_tenant("team-a") is True
    assert mgr.delete_tenant("team-a") is False


def test_list_tenants(tmp_path: Path) -> None:
    mgr = TenantManager(str(tmp_path / "tenants"))
    mgr.create_tenant("team-b", {"x": 1})
    mgr.create_tenant("team-a", {"x": 2})
    rows = mgr.list_tenants()
    ids = [item["tenant_id"] for item in rows]
    assert ids == ["team-a", "team-b"]


def test_resolve_merges_correctly(tmp_path: Path) -> None:
    mgr = TenantManager(str(tmp_path / "tenants"))
    mgr.create_tenant("team-a", {"limits": {"daily": 20}, "flags": {"a": True}})
    base = {"limits": {"daily": 5, "weekly": 50}, "flags": {"b": True}, "unchanged": 1}
    resolved = mgr.resolve_policy("team-a", base)
    assert resolved["limits"]["daily"] == 20
    assert resolved["limits"]["weekly"] == 50
    assert resolved["flags"]["a"] is True
    assert resolved["flags"]["b"] is True
    assert resolved["unchanged"] == 1


def test_api_tenant_endpoints(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)
    headers = {"Authorization": "Bearer test-token"}

    create_resp = client.post(
        "/api/v1/tenants",
        json={"tenant_id": "team-a", "policy": {"limits": {"daily": 10}}},
        headers=headers,
    )
    assert create_resp.status_code == 200
    assert create_resp.json()["tenant_id"] == "team-a"

    list_resp = client.get("/api/v1/tenants", headers=headers)
    assert list_resp.status_code == 200
    assert list_resp.json()["count"] == 1

    get_resp = client.get("/api/v1/tenants/team-a", headers=headers)
    assert get_resp.status_code == 200
    assert get_resp.json()["policy"]["limits"]["daily"] == 10

    update_resp = client.put(
        "/api/v1/tenants/team-a/policy",
        json={"policy": {"limits": {"daily": 22}}},
        headers=headers,
    )
    assert update_resp.status_code == 200
    assert update_resp.json()["policy"]["limits"]["daily"] == 22

    delete_resp = client.delete("/api/v1/tenants/team-a", headers=headers)
    assert delete_resp.status_code == 200
    assert delete_resp.json()["deleted"] is True
