from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from orchesis.api import create_api_app
from orchesis.cli import main
from tests.cli_test_utils import CliRunner


def _write_policy(path: Path, with_token: bool = False) -> None:
    if with_token:
        path.write_text('api:\n  token: "policy-token-123"\nrules: []\n', encoding="utf-8")
    else:
        path.write_text("rules: []\n", encoding="utf-8")


async def _client(app):
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


def test_serve_prints_token(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    _write_policy(policy, with_token=False)
    captured: dict[str, object] = {}

    def _fake_create_api_app(**kwargs):  # noqa: ANN001
        captured.update(kwargs)
        return object()

    def _fake_run(app, host: str, port: int) -> None:  # noqa: ANN001
        _ = app, host, port
        return None

    fake_uvicorn = SimpleNamespace(run=_fake_run)
    monkeypatch.setattr(
        "orchesis.cli._load_server_runtime",
        lambda: (fake_uvicorn, _fake_create_api_app, object, object),
    )
    runner = CliRunner()
    result = runner.invoke(main, ["serve", "--policy", str(policy), "--port", "8090"])
    assert result.exit_code == 0
    assert "✓ Orchesis API server running" in result.output
    assert "Token: orchesis-" in result.output
    assert "Docs:  http://localhost:8090/docs" in result.output
    assert isinstance(captured.get("api_token"), str)


def test_serve_custom_token(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    _write_policy(policy, with_token=True)
    captured: dict[str, object] = {}

    def _fake_create_api_app(**kwargs):  # noqa: ANN001
        captured.update(kwargs)
        return object()

    fake_uvicorn = SimpleNamespace(run=lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        "orchesis.cli._load_server_runtime",
        lambda: (fake_uvicorn, _fake_create_api_app, object, object),
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["serve", "--policy", str(policy), "--token", "mytoken123", "--cors", "https://app.example.com"],
    )
    assert result.exit_code == 0
    assert "Token: mytoken123" in result.output
    assert captured.get("api_token") == "mytoken123"
    assert captured.get("cors_origins") == ["https://app.example.com"]


@pytest.mark.asyncio
async def test_health_endpoint_no_auth(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    _write_policy(policy, with_token=True)
    app = create_api_app(policy_path=str(policy))
    async with await _client(app) as client:
        response = await client.get("/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert "version" in payload
    assert "uptime_seconds" in payload


@pytest.mark.asyncio
async def test_cors_header_present(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    _write_policy(policy, with_token=True)
    app = create_api_app(policy_path=str(policy), cors_origins=["https://app.example.com"])
    async with await _client(app) as client:
        response = await client.get("/health", headers={"Origin": "https://app.example.com"})
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "https://app.example.com"


@pytest.mark.asyncio
async def test_docs_endpoint_returns_html(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    _write_policy(policy, with_token=True)
    app = create_api_app(policy_path=str(policy))
    async with await _client(app) as client:
        response = await client.get("/docs")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    assert "/api/v1/status" in response.text
