from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from tests.cli_test_utils import CliRunner
from fastapi.testclient import TestClient

from orchesis.cli import main
from orchesis.credential_injector import CredentialInjector
from orchesis.credential_vault import CredentialNotFoundError, EnvVault, FileVault
from orchesis.demo_backend import app as demo_backend
from orchesis.proxy import create_proxy_app


def test_env_vault_reads_env_var(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_KEY", "abc123")
    vault = EnvVault()
    vault.set_mapping("openai_key", "OPENAI_KEY")
    assert vault.get("openai_key") == "abc123"


def test_env_vault_missing_var_raises(monkeypatch) -> None:
    monkeypatch.delenv("MISSING", raising=False)
    vault = EnvVault()
    vault.set_mapping("missing", "MISSING")
    with pytest.raises(CredentialNotFoundError):
        vault.get("missing")


def test_file_vault_set_get_roundtrip(tmp_path: Path) -> None:
    vault = FileVault(vault_path=tmp_path / "credentials.enc", passphrase="test-pass")
    vault.set("openai_key", "super-secret")
    assert vault.get("openai_key") == "super-secret"


def test_file_vault_missing_alias_raises(tmp_path: Path) -> None:
    vault = FileVault(vault_path=tmp_path / "credentials.enc", passphrase="test-pass")
    with pytest.raises(CredentialNotFoundError):
        vault.get("nope")


def test_injector_matches_exact_tool_name(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_KEY", "k-1")
    vault = EnvVault()
    vault.set_mapping("openai_key", "OPENAI_KEY")
    injector = CredentialInjector(
        {
            "inject": [
                {"alias": "openai_key", "target": "header", "header_name": "Authorization", "match_tools": ["web_search"]}
            ]
        },
        vault,
    )
    injected, aliases = injector.inject({"tool_name": "web_search", "params": {}, "headers": {}})
    assert "openai_key" in aliases
    assert injected["headers"]["Authorization"] == "k-1"


def test_injector_matches_glob_pattern(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    vault = EnvVault()
    vault.set_mapping("github_token", "GITHUB_TOKEN")
    injector = CredentialInjector(
        {
            "inject": [
                {"alias": "github_token", "target": "header", "header_name": "Authorization", "match_tools": ["github_*"]}
            ]
        },
        vault,
    )
    injected, _aliases = injector.inject({"tool_name": "github_list_repos", "params": {}, "headers": {}})
    assert injected["headers"]["Authorization"] == "tok"


def test_header_injection_with_template(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_KEY", "sk-xyz")
    vault = EnvVault()
    vault.set_mapping("openai_key", "OPENAI_KEY")
    injector = CredentialInjector(
        {
            "inject": [
                {
                    "alias": "openai_key",
                    "target": "header",
                    "header_name": "Authorization",
                    "header_template": "Bearer {value}",
                    "match_tools": ["web_search"],
                }
            ]
        },
        vault,
    )
    injected, _aliases = injector.inject({"tool_name": "web_search", "params": {}, "headers": {}})
    assert injected["headers"]["Authorization"] == "Bearer sk-xyz"


def test_param_injection_replaces_value(monkeypatch) -> None:
    monkeypatch.setenv("DB_PASSWORD", "p@ss")
    vault = EnvVault()
    vault.set_mapping("db_password", "DB_PASSWORD")
    injector = CredentialInjector(
        {
            "inject": [
                {"alias": "db_password", "target": "param", "param_name": "password", "match_tools": ["query_database"]}
            ]
        },
        vault,
    )
    injected, _aliases = injector.inject({"tool_name": "query_database", "params": {"password": "alias"}, "headers": {}})
    assert injected["params"]["password"] == "p@ss"


def test_injection_with_no_matching_rules_passthrough(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_KEY", "x")
    vault = EnvVault()
    vault.set_mapping("openai_key", "OPENAI_KEY")
    injector = CredentialInjector(
        {"inject": [{"alias": "openai_key", "target": "header", "header_name": "Authorization", "match_tools": ["web_search"]}]},
        vault,
    )
    injected, aliases = injector.inject({"tool_name": "read_file", "params": {}, "headers": {}})
    assert aliases == []
    assert injected["headers"] == {}


def test_scrub_removes_sensitive_values(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_KEY", "super-secret-value")
    vault = EnvVault()
    vault.set_mapping("openai_key", "OPENAI_KEY")
    injector = CredentialInjector(
        {"inject": [{"alias": "openai_key", "target": "header", "header_name": "Authorization", "match_tools": ["web_search"]}]},
        vault,
    )
    injected, _ = injector.inject({"tool_name": "web_search", "params": {}, "headers": {}})
    scrubbed = injector.scrub(injected)
    assert "super-secret-value" not in repr(scrubbed)
    assert scrubbed["headers"]["Authorization"] == "[REDACTED:openai_key]"


def test_credential_value_not_in_error_message(monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_KEY", raising=False)
    vault = EnvVault()
    vault.set_mapping("openai_key", "OPENAI_KEY")
    with pytest.raises(CredentialNotFoundError) as error:
        vault.get("openai_key")
    assert "OPENAI_KEY" not in str(error.value)


def test_proxy_injection_failure_denies(monkeypatch) -> None:
    monkeypatch.delenv("MISSING_TOKEN", raising=False)
    policy = {
        "rules": [],
        "credentials": {
            "vault": "env",
            "inject": [
                {"alias": "missing_token", "target": "header", "header_name": "Authorization", "match_tools": ["web_search"]}
            ],
        },
    }
    proxy_app = create_proxy_app(policy=policy, backend_app=demo_backend)
    client = TestClient(proxy_app)
    response = client.post("/execute", json={"tool": "web_search", "params": {"q": "x"}})
    assert response.status_code == 403
    assert "credential_injection_failed" in response.text


def test_multiple_credentials_injected_same_tool(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_KEY", "a")
    monkeypatch.setenv("DB_PASSWORD", "b")
    vault = EnvVault()
    vault.set_mapping("openai_key", "OPENAI_KEY")
    vault.set_mapping("db_password", "DB_PASSWORD")
    injector = CredentialInjector(
        {
            "inject": [
                {"alias": "openai_key", "target": "header", "header_name": "Authorization", "match_tools": ["query_database"]},
                {"alias": "db_password", "target": "param", "param_name": "password", "match_tools": ["query_database"]},
            ]
        },
        vault,
    )
    injected, aliases = injector.inject({"tool_name": "query_database", "params": {}, "headers": {}})
    assert set(aliases) == {"openai_key", "db_password"}
    assert injected["headers"]["Authorization"] == "a"
    assert injected["params"]["password"] == "b"


def test_credentials_list_shows_aliases_not_values(tmp_path: Path) -> None:
    vault = FileVault(vault_path=tmp_path / "credentials.enc", passphrase="pass")
    vault.set("openai_key", "very-secret")
    aliases = vault.list_aliases()
    assert "openai_key" in aliases
    assert "very-secret" not in "\n".join(aliases)


def test_credentials_cli_set_and_test_roundtrip() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        result_set = runner.invoke(
            main,
            ["credentials", "set", "openai_key", "--vault-path", ".orchesis/credentials.enc"],
            input="secret-value\nsecret-value\n",
        )
        assert result_set.exit_code == 0
        result_test = runner.invoke(
            main,
            ["credentials", "test", "openai_key", "--vault-path", ".orchesis/credentials.enc"],
        )
        assert result_test.exit_code == 0
        assert "accessible" in result_test.output


def test_credentials_cli_list_hides_values() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        _ = runner.invoke(
            main,
            ["credentials", "set", "openai_key", "--vault-path", ".orchesis/credentials.enc"],
            input="secret-value\nsecret-value\n",
        )
        listed = runner.invoke(main, ["credentials", "list", "--vault-path", ".orchesis/credentials.enc"])
        assert listed.exit_code == 0
        assert "openai_key" in listed.output
        assert "secret-value" not in listed.output


def test_credentials_cli_remove() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        _ = runner.invoke(
            main,
            ["credentials", "set", "openai_key", "--vault-path", ".orchesis/credentials.enc"],
            input="secret-value\nsecret-value\n",
        )
        removed = runner.invoke(main, ["credentials", "remove", "openai_key", "--vault-path", ".orchesis/credentials.enc"])
        assert removed.exit_code == 0
        test_result = runner.invoke(main, ["credentials", "test", "openai_key", "--vault-path", ".orchesis/credentials.enc"])
        assert test_result.exit_code != 0


def test_credentials_cli_env_mapping(monkeypatch) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        set_result = runner.invoke(main, ["credentials", "set", "openai_key", "--env"])
        assert set_result.exit_code == 0
        monkeypatch.setenv("OPENAI_KEY", "abc")
        test_result = runner.invoke(main, ["credentials", "test", "openai_key", "--policy", "missing.yaml"])
        assert test_result.exit_code != 0


def test_proxy_decisions_log_contains_credentials_injected(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("OPENAI_KEY", "secret-token")
    policy = {
        "rules": [],
        "credentials": {
            "vault": "env",
            "inject": [
                {"alias": "openai_key", "target": "header", "header_name": "Authorization", "match_tools": ["web_search"]}
            ],
        },
    }
    proxy_app = create_proxy_app(policy=policy, backend_app=demo_backend)
    client = TestClient(proxy_app)
    response = client.post("/execute", json={"tool": "web_search", "params": {"q": "x"}})
    assert response.status_code == 200
    log_path = Path(".orchesis/decisions.jsonl")
    assert log_path.exists()
    last = json.loads(log_path.read_text(encoding="utf-8").splitlines()[-1])
    assert last.get("credentials_injected") == ["openai_key"]
    assert "secret-token" not in json.dumps(last, ensure_ascii=False)


def test_injector_matching_aliases_reports_expected() -> None:
    vault = FileVault(vault_path=".orchesis/test_aliases.enc", passphrase="x")
    injector = CredentialInjector(
        {"inject": [{"alias": "github_token", "target": "header", "match_tools": ["github_*"]}]},
        vault,
    )
    assert injector.matching_aliases("github_create_issue") == ["github_token"]


def test_injector_keeps_existing_headers(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_KEY", "token")
    vault = EnvVault()
    vault.set_mapping("openai_key", "OPENAI_KEY")
    injector = CredentialInjector(
        {"inject": [{"alias": "openai_key", "target": "header", "header_name": "Authorization", "match_tools": ["web_search"]}]},
        vault,
    )
    injected, _ = injector.inject({"tool_name": "web_search", "params": {}, "headers": {"X-Trace": "1"}})
    assert injected["headers"]["X-Trace"] == "1"
    assert injected["headers"]["Authorization"] == "token"
