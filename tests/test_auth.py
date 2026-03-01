from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

from click.testing import CliRunner

from orchesis.auth import AgentAuthenticator, CredentialStore
from orchesis.cli import main


def _params_hash(params: dict) -> str:
    return hashlib.sha256(
        json.dumps(params, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def test_register_agent_generates_secret() -> None:
    auth = AgentAuthenticator()
    cred = auth.register("my-agent")
    assert cred.agent_id == "my-agent"
    assert len(cred.secret_key) == 64


def test_register_agent_unique_secrets() -> None:
    auth = AgentAuthenticator()
    a = auth.register("a")
    b = auth.register("b")
    assert a.secret_key != b.secret_key


def test_compute_signature_deterministic() -> None:
    auth = AgentAuthenticator()
    sig1 = auth.compute_signature("ab" * 32, "a1", "100", "read_file", "ff" * 32)
    sig2 = auth.compute_signature("ab" * 32, "a1", "100", "read_file", "ff" * 32)
    assert sig1 == sig2


def test_verify_valid_signature() -> None:
    auth = AgentAuthenticator()
    cred = auth.register("a1")
    ts = str(int(time.time()))
    params_hash = _params_hash({"path": "/tmp"})
    sig = auth.compute_signature(cred.secret_key, "a1", ts, "read_file", params_hash)
    ok, reason = auth.verify("a1", ts, "read_file", params_hash, sig)
    assert ok is True
    assert reason == ""


def test_verify_wrong_signature_fails() -> None:
    auth = AgentAuthenticator()
    auth.register("a1")
    ts = str(int(time.time()))
    ok, reason = auth.verify("a1", ts, "read_file", _params_hash({"path": "/tmp"}), "deadbeef")
    assert ok is False
    assert "invalid signature" in reason


def test_verify_unknown_agent_fails() -> None:
    auth = AgentAuthenticator()
    ok, reason = auth.verify("missing", "1", "read_file", "00", "00")
    assert ok is False
    assert "unknown agent" in reason


def test_verify_revoked_agent_fails() -> None:
    auth = AgentAuthenticator()
    cred = auth.register("a1")
    auth.revoke("a1")
    ts = str(int(time.time()))
    params_hash = _params_hash({"path": "/tmp"})
    sig = auth.compute_signature(cred.secret_key, "a1", ts, "read_file", params_hash)
    ok, reason = auth.verify("a1", ts, "read_file", params_hash, sig)
    assert ok is False
    assert "revoked" in reason


def test_verify_expired_timestamp_fails(monkeypatch) -> None:
    auth = AgentAuthenticator(max_clock_skew=300)
    cred = auth.register("a1")
    monkeypatch.setattr("time.time", lambda: 2000.0)
    ts = "1000"
    params_hash = _params_hash({"path": "/tmp"})
    sig = auth.compute_signature(cred.secret_key, "a1", ts, "read_file", params_hash)
    ok, reason = auth.verify("a1", ts, "read_file", params_hash, sig)
    assert ok is False
    assert "timestamp too old/new" in reason


def test_verify_replay_detected() -> None:
    auth = AgentAuthenticator()
    cred = auth.register("a1")
    ts = str(int(time.time()))
    params_hash = _params_hash({"path": "/tmp"})
    sig = auth.compute_signature(cred.secret_key, "a1", ts, "read_file", params_hash)
    first, _ = auth.verify("a1", ts, "read_file", params_hash, sig)
    second, reason = auth.verify("a1", ts, "read_file", params_hash, sig)
    assert first is True
    assert second is False
    assert "replay detected" in reason


def test_authenticate_request_enforce_no_headers() -> None:
    auth = AgentAuthenticator(mode="enforce")
    ok, agent, reason = auth.authenticate_request({"tool": "read_file", "params": {}}, {})
    assert ok is False
    assert agent == ""
    assert "authentication required" in reason


def test_authenticate_request_log_no_headers_allows() -> None:
    auth = AgentAuthenticator(mode="log")
    ok, agent, reason = auth.authenticate_request({"tool": "read_file", "params": {}}, {})
    assert ok is True
    assert agent == ""
    assert reason == ""


def test_authenticate_request_optional_no_headers_allows() -> None:
    auth = AgentAuthenticator(mode="optional")
    ok, agent, reason = auth.authenticate_request({"tool": "read_file", "params": {}}, {})
    assert ok is True
    assert agent == ""
    assert reason == ""


def test_authenticate_request_partial_headers_fails() -> None:
    auth = AgentAuthenticator(mode="optional")
    ok, agent, reason = auth.authenticate_request(
        {"tool": "read_file", "params": {}},
        {"X-Orchesis-Agent": "a1"},
    )
    assert ok is False
    assert agent == "a1"
    assert "incomplete authentication headers" in reason


def test_rotate_secret_invalidates_old() -> None:
    auth = AgentAuthenticator()
    cred = auth.register("a1")
    old_key = cred.secret_key
    ts = str(int(time.time()))
    params_hash = _params_hash({"path": "/tmp"})
    old_sig = auth.compute_signature(old_key, "a1", ts, "read_file", params_hash)
    auth.rotate("a1")
    ok, reason = auth.verify("a1", ts, "read_file", params_hash, old_sig)
    assert ok is False
    assert "invalid signature" in reason


def test_list_agents_no_secrets() -> None:
    auth = AgentAuthenticator()
    auth.register("a1")
    row = auth.list_agents()[0]
    assert "secret_key" not in row


def test_credential_store_save_load(tmp_path: Path) -> None:
    path = tmp_path / "creds.yaml"
    store = CredentialStore(str(path))
    auth = AgentAuthenticator()
    auth.register("a1")
    store.save(auth.credentials)
    loaded = store.load()
    assert "a1" in loaded
    assert loaded["a1"].secret_key == auth.credentials["a1"].secret_key


def test_credential_file_permissions(tmp_path: Path) -> None:
    path = tmp_path / "creds.yaml"
    store = CredentialStore(str(path))
    auth = AgentAuthenticator()
    auth.register("a1")
    store.save(auth.credentials)
    if os.name != "nt":
        mode = path.stat().st_mode & 0o777
        assert mode == 0o600
    else:
        assert path.exists()


def test_cleanup_old_signatures(monkeypatch) -> None:
    auth = AgentAuthenticator(max_clock_skew=10)
    auth._used_signatures["old"] = 100.0  # noqa: SLF001
    auth._used_signatures["new"] = 1025.0  # noqa: SLF001
    monkeypatch.setattr("time.time", lambda: 1030.0)
    auth._cleanup_old_signatures()  # noqa: SLF001
    assert "old" not in auth._used_signatures  # noqa: SLF001
    assert "new" in auth._used_signatures  # noqa: SLF001


def test_auth_cli_register() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main, ["auth", "register", "my-agent"])
        assert result.exit_code == 0
        assert "Agent registered: my-agent" in result.output
        assert "Secret key:" in result.output


def test_auth_cli_list() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        register = runner.invoke(main, ["auth", "register", "my-agent"])
        assert register.exit_code == 0
        result = runner.invoke(main, ["auth", "list"])
        assert result.exit_code == 0
        assert "my-agent" in result.output
