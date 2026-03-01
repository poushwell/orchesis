from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

import httpx
import mcp.types as types
import pytest

from orchesis.api import create_api_app
from orchesis.mcp_proxy import McpToolInterceptor
from orchesis.sync import PolicySyncClient, PolicySyncServer, SyncStatus


def _auth() -> dict[str, str]:
    return {"Authorization": "Bearer orch_sk_test"}


def _policy_yaml(max_cost: float = 1.0) -> str:
    return f"""
api:
  token: "orch_sk_test"
rules:
  - name: budget_limit
    max_cost_per_call: {max_cost}
""".strip()


class _FakeResponse:
    def __init__(self, payload: dict[str, Any], status_code: int = 200):
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("error", request=None, response=None)

    def json(self) -> dict[str, Any]:
        return self._payload


def test_sync_client_detects_update(monkeypatch) -> None:  # noqa: ANN001
    client = PolicySyncClient("http://control", "token", node_id="node-a")
    client._current_version = "old-v"  # noqa: SLF001

    def _fake_get(*args, **kwargs):  # noqa: ANN002, ANN003
        _ = (args, kwargs)
        return _FakeResponse({"version_id": "new-v", "yaml_content": "rules: []"})

    monkeypatch.setattr("orchesis.sync.httpx.get", _fake_get)
    has_update, policy = client.check_for_update()
    assert has_update is True
    assert isinstance(policy, dict)


def test_sync_client_no_update(monkeypatch) -> None:  # noqa: ANN001
    client = PolicySyncClient("http://control", "token", node_id="node-a")
    client._current_version = "same-v"  # noqa: SLF001

    def _fake_get(*args, **kwargs):  # noqa: ANN002, ANN003
        _ = (args, kwargs)
        return _FakeResponse({"version_id": "same-v", "yaml_content": "rules: []"})

    monkeypatch.setattr("orchesis.sync.httpx.get", _fake_get)
    has_update, policy = client.check_for_update()
    assert has_update is False
    assert policy is None


def test_sync_client_returns_new_policy(monkeypatch) -> None:  # noqa: ANN001
    client = PolicySyncClient("http://control", "token", node_id="node-a")
    client._current_version = "v1"  # noqa: SLF001

    def _fake_get(*args, **kwargs):  # noqa: ANN002, ANN003
        _ = (args, kwargs)
        return _FakeResponse(
            {"version_id": "v2", "yaml_content": "rules:\n  - name: budget_limit\n    max_cost_per_call: 1.0"}
        )

    monkeypatch.setattr("orchesis.sync.httpx.get", _fake_get)
    has_update, policy = client.check_for_update()
    assert has_update is True
    assert isinstance(policy, dict)
    assert isinstance(policy.get("rules"), list)


def test_sync_status_fields() -> None:
    status = SyncStatus(
        node_id="node-1",
        policy_version="v1",
        last_sync="2026-03-01T00:00:00Z",
        in_sync=True,
        latency_ms=12.3,
    )
    assert status.node_id == "node-1"
    assert status.policy_version == "v1"
    assert status.last_sync.endswith("Z")
    assert status.in_sync is True
    assert status.latency_ms > 0


def test_sync_server_register_node() -> None:
    server = PolicySyncServer()
    server.set_current_version("v1")
    server.register_node("node-a", "v1")
    nodes = server.get_nodes()
    assert len(nodes) == 1
    assert nodes[0].node_id == "node-a"
    assert nodes[0].in_sync is True


def test_sync_server_detects_out_of_sync() -> None:
    server = PolicySyncServer()
    server.set_current_version("v2")
    server.register_node("node-a", "v1")
    out = server.get_out_of_sync()
    assert len(out) == 1
    assert out[0].node_id == "node-a"


@pytest.mark.asyncio
async def test_heartbeat_endpoint(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        current = (await client.get("/api/v1/policy", headers=_auth())).json()["version_id"]
        res = await client.post(
            "/api/v1/nodes/heartbeat",
            headers=_auth(),
            json={"node_id": "node-a", "policy_version": current},
        )
    assert res.status_code == 200
    payload = res.json()
    assert payload["in_sync"] is True
    assert payload["policy_changed"] is False


@pytest.mark.asyncio
async def test_nodes_endpoint(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        current = (await client.get("/api/v1/policy", headers=_auth())).json()["version_id"]
        await client.post(
            "/api/v1/nodes/heartbeat",
            headers=_auth(),
            json={"node_id": "node-a", "policy_version": current},
        )
        await client.post(
            "/api/v1/nodes/heartbeat",
            headers=_auth(),
            json={"node_id": "node-b", "policy_version": "old-version"},
        )
        res = await client.get("/api/v1/nodes", headers=_auth())
    assert res.status_code == 200
    payload = res.json()
    assert payload["total"] == 2
    assert payload["in_sync"] == 1
    assert payload["out_of_sync"] == 1


@pytest.mark.asyncio
async def test_force_sync_endpoint(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        current = (await client.get("/api/v1/policy", headers=_auth())).json()["version_id"]
        await client.post(
            "/api/v1/nodes/heartbeat",
            headers=_auth(),
            json={"node_id": "node-a", "policy_version": current},
        )
        forced = await client.post("/api/v1/nodes/node-a/force-sync", headers=_auth())
        heartbeat = await client.post(
            "/api/v1/nodes/heartbeat",
            headers=_auth(),
            json={"node_id": "node-a", "policy_version": current},
        )
    assert forced.status_code == 200
    assert heartbeat.status_code == 200
    assert heartbeat.json()["policy_changed"] is True


def test_background_sync_calls_callback(monkeypatch) -> None:  # noqa: ANN001
    client = PolicySyncClient("http://control", "token", node_id="node-a", poll_interval_seconds=1)
    called: list[dict[str, Any]] = []
    done = threading.Event()

    def _fake_sync_once() -> SyncStatus:
        client._current_version = "v2"  # noqa: SLF001
        client._latest_policy = {"rules": []}  # noqa: SLF001
        return SyncStatus("node-a", "v2", "2026-03-01T00:00:00Z", True, 1.0)

    monkeypatch.setattr(client, "sync_once", _fake_sync_once)

    def _on_update(policy: dict[str, Any]) -> None:
        called.append(policy)
        done.set()
        client._running = False  # noqa: SLF001

    client.start_background_sync(_on_update)
    assert done.wait(timeout=2.0) is True
    client.stop()
    assert called and called[0]["rules"] == []


class _FakeDownstream:
    async def list_tools(self) -> types.ListToolsResult:
        return types.ListToolsResult(
            tools=[types.Tool(name="read_file", description="read", inputSchema={"type": "object"})]
        )

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> types.CallToolResult:
        _ = (name, arguments)
        return types.CallToolResult(
            content=[types.TextContent(type="text", text="ok")],
            isError=False,
        )


@pytest.mark.asyncio
async def test_proxy_with_control_url() -> None:
    interceptor = McpToolInterceptor(policy={"rules": []}, downstream_session=_FakeDownstream())
    updated = {
        "rules": [
            {"name": "sql_restriction", "denied_operations": ["DROP"]},
        ]
    }
    interceptor.update_policy(updated, version_hint="v2")
    with pytest.raises(ValueError):
        await interceptor.call_tool("run_sql", {"query": "DROP TABLE users"})


@pytest.mark.asyncio
async def test_backward_compatible_no_control_url() -> None:
    interceptor = McpToolInterceptor(policy={"rules": []}, downstream_session=_FakeDownstream())
    result = await interceptor.call_tool("read_file", {"path": "/data/x.txt"})
    assert result.isError is False
