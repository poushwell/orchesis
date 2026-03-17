from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from orchesis.api import create_api_app
from orchesis.cli import main
from orchesis.threat_feed import ThreatFeed
from tests.cli_test_utils import CliRunner


class _FakeHttpResponse:
    def __init__(self, payload: str):
        self._payload = payload.encode("utf-8")

    def read(self) -> bytes:
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):  # noqa: ANN001
        _ = exc_type, exc, tb
        return False


def _policy_text() -> str:
    return 'api:\n  token: "orch_sk_test"\nrules: []\n'


async def _client(app):
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


def _auth() -> dict[str, str]:
    return {"Authorization": "Bearer orch_sk_test"}


def test_fetch_returns_signatures(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {"signatures": [{"threat_id": "TF-001", "name": "Test Threat"}]}
    monkeypatch.setattr(
        "orchesis.threat_feed.urlopen",
        lambda *_args, **_kwargs: _FakeHttpResponse(json.dumps(payload)),
    )
    feed = ThreatFeed({"feed_url": "https://example.invalid/feed"})
    added = feed.fetch()
    assert len(added) == 1
    assert added[0]["threat_id"] == "TF-001"


def test_apply_adds_to_threat_intel() -> None:
    feed = ThreatFeed({})
    feed._signatures = [{"threat_id": "TF-001", "name": "Test Threat"}]
    dummy = type("DummyThreatIntel", (), {"_threats": {}})()
    added = feed.apply(dummy)
    assert added == 1
    assert "TF-001" in dummy._threats


def test_import_export_roundtrip(tmp_path: Path) -> None:
    feed = ThreatFeed({})
    feed._signatures = [{"threat_id": "TF-001", "name": "One"}]
    out = tmp_path / "signatures.yaml"
    feed.export_signatures(str(out))
    loaded = ThreatFeed({})
    count = loaded.import_signatures(str(out))
    assert count == 1
    assert len(loaded._signatures) == 1
    assert loaded._signatures[0]["threat_id"] == "TF-001"


def test_stats_returned_correctly() -> None:
    feed = ThreatFeed({"feed_url": "https://x.example", "auto_update": True, "update_interval_hours": 12})
    feed._signatures = [{"threat_id": "TF-001"}]
    feed._last_updated = 1700000000.0
    stats = feed.get_stats()
    assert stats["signatures_count"] == 1
    assert stats["auto_update"] is True
    assert stats["feed_url"] == "https://x.example"
    assert isinstance(stats["last_updated"], str)
    assert isinstance(stats["next_update"], str)


@pytest.mark.asyncio
async def test_api_status_endpoint(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(_policy_text(), encoding="utf-8")
    app = create_api_app(policy_path=str(policy))
    async with await _client(app) as client:
        res = await client.get("/api/v1/threat-feed/status", headers=_auth())
    assert res.status_code == 200
    payload = res.json()
    assert "signatures_count" in payload
    assert "feed_url" in payload


@pytest.mark.asyncio
async def test_api_update_endpoint(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(_policy_text(), encoding="utf-8")
    app = create_api_app(policy_path=str(policy))
    monkeypatch.setattr(
        app.state.threat_feed,
        "fetch",
        lambda: [{"threat_id": "TF-001"}, {"threat_id": "TF-002"}],
    )
    async with await _client(app) as client:
        res = await client.post("/api/v1/threat-feed/update", headers=_auth())
    assert res.status_code == 200
    payload = res.json()
    assert payload["added"] == 2


def test_cli_threat_feed_command(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeFeed:
        def __init__(self, _cfg):  # noqa: ANN001
            self._signatures = [{"threat_id": "TF-001"}]

        def fetch(self):
            return [{"threat_id": "TF-002"}]

        def get_stats(self):
            return {"signatures_count": 1, "auto_update": False, "feed_url": "x", "last_updated": "", "next_update": ""}

        def export_signatures(self, path: str):
            Path(path).write_text("signatures: []\n", encoding="utf-8")

        def import_signatures(self, _path: str):
            return 1

    monkeypatch.setattr("orchesis.cli.ThreatFeed", _FakeFeed)
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("orchesis.yaml").write_text("rules: []\n", encoding="utf-8")
        Path("in.yaml").write_text("signatures: []\n", encoding="utf-8")
        result = runner.invoke(
            main,
            [
                "threat-feed",
                "--config",
                "orchesis.yaml",
                "--status",
                "--update",
                "--export",
                "out.yaml",
                "--import",
                "in.yaml",
            ],
        )
        assert result.exit_code == 0
        assert "Fetched signatures" in result.output
        assert "Imported signatures" in result.output
        assert "Exported signatures" in result.output
