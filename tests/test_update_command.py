from __future__ import annotations

import json
from urllib.error import URLError

import pytest

from orchesis import __version__
from orchesis.cli import main
from tests.cli_test_utils import CliRunner


class _FakeResp:
    def __init__(self, payload: dict):
        self._raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")

    def read(self) -> bytes:
        return self._raw

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):  # noqa: ANN001
        _ = (exc_type, exc, tb)
        return False


def test_update_check_parses_pypi(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("orchesis.cli.urlopen", lambda *_args, **_kwargs: _FakeResp({"info": {"version": "9.9.9"}}))
    runner = CliRunner()
    result = runner.invoke(main, ["update", "--check"])
    assert result.exit_code == 0
    assert "Checking for updates..." in result.output
    assert "Latest version:  9.9.9" in result.output


def test_update_shows_current_version(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("orchesis.cli.urlopen", lambda *_args, **_kwargs: _FakeResp({"info": {"version": str(__version__)}}))
    runner = CliRunner()
    result = runner.invoke(main, ["update", "--check"])
    assert result.exit_code == 0
    assert f"Current version: {__version__}" in result.output


def test_update_detects_newer_version(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("orchesis.cli.urlopen", lambda *_args, **_kwargs: _FakeResp({"info": {"version": "99.0.0"}}))
    runner = CliRunner()
    result = runner.invoke(main, ["update", "--check"])
    assert result.exit_code == 0
    assert "Update available!" in result.output


def test_update_already_up_to_date(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("orchesis.cli.urlopen", lambda *_args, **_kwargs: _FakeResp({"info": {"version": str(__version__)}}))
    runner = CliRunner()
    result = runner.invoke(main, ["update", "--check"])
    assert result.exit_code == 0
    assert f"✓ Orchesis {__version__} is up to date" in result.output


def test_update_handles_network_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("orchesis.cli.urlopen", lambda *_args, **_kwargs: (_ for _ in ()).throw(URLError("down")))
    runner = CliRunner()
    result = runner.invoke(main, ["update", "--check"])
    assert result.exit_code == 0
    assert "Could not check updates (network error)." in result.output
