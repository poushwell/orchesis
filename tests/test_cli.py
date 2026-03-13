import json
import importlib
from pathlib import Path

from click.testing import CliRunner

from orchesis.cli import main
from orchesis import __version__


def _write_file(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def test_init_creates_sample_files_and_prints_instruction() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main, ["init"])
        assert result.exit_code == 0
        assert Path("policy.yaml").exists()
        assert Path("request.json").exists()
        assert (
            "Created policy.yaml and request.json. Edit them, then run: orchesis verify"
            in result.output
        )


def test_verify_outputs_decision_json_and_returns_zero_for_allow() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        _write_file(
            Path("policy.yaml"),
            """
rules:
  - name: budget_limit
    max_cost_per_call: 0.50
""".strip(),
        )
        _write_file(Path("request.json"), '{"tool":"sql_query","params":{},"cost":0.10}')

        result = runner.invoke(main, ["verify", "request.json", "--policy", "policy.yaml"])

        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["allowed"] is True
        assert Path("decisions.jsonl").exists()


def test_verify_returns_one_for_deny() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        _write_file(
            Path("policy.yaml"),
            """
rules:
  - name: sql_restriction
    denied_operations:
      - DROP
""".strip(),
        )
        _write_file(
            Path("request.json"),
            '{"tool":"sql_query","params":{"query":"DROP TABLE users"},"cost":0.10}',
        )

        result = runner.invoke(main, ["verify", "request.json", "--policy", "policy.yaml"])

        assert result.exit_code == 1
        payload = json.loads(result.output)
        assert payload["allowed"] is False
        assert "sql_restriction: DROP is denied" in payload["reasons"]


def test_validate_prints_ok_for_valid_policy() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        _write_file(
            Path("policy.yaml"),
            """
rules:
  - name: budget_limit
    max_cost_per_call: 0.50
""".strip(),
        )

        result = runner.invoke(main, ["validate", "--policy", "policy.yaml"])

        assert result.exit_code == 0
        assert "OK" in result.output


def test_validate_prints_errors_for_invalid_policy() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        _write_file(Path("policy.yaml"), "rules: [{}]")

        result = runner.invoke(main, ["validate", "--policy", "policy.yaml"])

        assert result.exit_code == 1
        assert "rules[0].name must be a non-empty string" in result.output


def test_audit_prints_summary_and_last_n_entries() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        _write_file(
            Path("decisions.jsonl"),
            "\n".join(
                [
                    '{"timestamp":"2026-03-01T10:00:00+00:00","tool":"sql_query","decision":"ALLOW","reasons":[],"rules_checked":["budget_limit"],"cost":0.1}',
                    '{"timestamp":"2026-03-01T11:00:00+00:00","tool":"sql_query","decision":"DENY","reasons":["sql_restriction: DROP is denied"],"rules_checked":["sql_restriction"],"cost":0.1}',
                    '{"timestamp":"2026-03-01T12:00:00+00:00","tool":"sql_query","decision":"DENY","reasons":["file_access: path is denied"],"rules_checked":["file_access"],"cost":0.1}',
                ]
            )
            + "\n",
        )

        result = runner.invoke(main, ["audit", "--limit", "2"])

        assert result.exit_code == 0
        assert "Total ALLOW: 1" in result.output
        assert "Total DENY: 2" in result.output
        assert "Top deny reasons:" in result.output
        assert "Last 2 decisions:" in result.output


def test_audit_since_filters_out_old_entries() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        _write_file(
            Path("decisions.jsonl"),
            "\n".join(
                [
                    '{"timestamp":"2000-01-01T00:00:00+00:00","tool":"sql_query","decision":"DENY","reasons":["old"],"rules_checked":[],"cost":0.1}',
                    '{"timestamp":"2099-01-01T00:00:00+00:00","tool":"sql_query","decision":"ALLOW","reasons":[],"rules_checked":[],"cost":0.1}',
                ]
            )
            + "\n",
        )

        result = runner.invoke(main, ["audit", "--since", "1"])

        assert result.exit_code == 0
        assert "Total ALLOW: 1" in result.output
        assert "Total DENY: 0" in result.output


def test_keygen_creates_keys_and_prints_message() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main, ["keygen"])

        assert result.exit_code == 0
        assert Path(".orchesis/keys/private.pem").exists()
        assert Path(".orchesis/keys/public.pem").exists()
        assert "Keys generated in .orchesis/keys/" in result.output


def test_verify_sign_writes_signature_field_to_log() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        runner.invoke(main, ["keygen"])
        _write_file(
            Path("policy.yaml"),
            """
rules:
  - name: budget_limit
    max_cost_per_call: 0.50
""".strip(),
        )
        _write_file(Path("request.json"), '{"tool":"sql_query","params":{},"cost":0.10}')

        result = runner.invoke(
            main, ["verify", "request.json", "--policy", "policy.yaml", "--sign"]
        )

        assert result.exit_code == 0
        line = Path("decisions.jsonl").read_text(encoding="utf-8").splitlines()[0]
        payload = json.loads(line)
        assert isinstance(payload.get("signature"), str)
        assert payload["signature"]


def test_audit_verify_reports_verified_tampered_and_unsigned() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        runner.invoke(main, ["keygen"])
        _write_file(
            Path("policy.yaml"),
            """
rules:
  - name: budget_limit
    max_cost_per_call: 1.00
""".strip(),
        )
        _write_file(Path("request.json"), '{"tool":"sql_query","params":{},"cost":0.10}')
        runner.invoke(main, ["verify", "request.json", "--policy", "policy.yaml", "--sign"])

        lines = Path("decisions.jsonl").read_text(encoding="utf-8").splitlines()
        signed_payload = json.loads(lines[0])
        tampered = dict(signed_payload)
        tampered["decision"] = "DENY"
        unsigned = {
            "timestamp": "2026-03-01T10:00:00+00:00",
            "tool": "sql_query",
            "decision": "ALLOW",
            "reasons": [],
            "rules_checked": [],
            "cost": 0.1,
        }
        _write_file(
            Path("decisions.jsonl"),
            "\n".join(
                [
                    json.dumps(signed_payload),
                    json.dumps(tampered),
                    json.dumps(unsigned),
                ]
            )
            + "\n",
        )

        result = runner.invoke(main, ["audit", "--verify"])

        assert result.exit_code == 0
        assert "OK" in result.output
        assert "TAMPERED" in result.output
        assert "UNSIGNED" in result.output
        assert "1 verified, 1 tampered, 1 unsigned" in result.output


def test_agents_lists_registered_agents() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        _write_file(
            Path("policy.yaml"),
            """
agents:
  - id: "cursor"
    name: "Cursor IDE Agent"
    trust_tier: operator
    allowed_tools: ["read_file", "write_file", "run_sql"]
default_trust_tier: intern
rules: []
""".strip(),
        )
        result = runner.invoke(main, ["agents", "--policy", "policy.yaml"])
        assert result.exit_code == 0
        assert "Registered agents:" in result.output
        assert "cursor" in result.output
        assert "operator" in result.output
        assert "Default tier: intern" in result.output


def test_invariants_command_runs() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        policy = Path("policy.yaml")
        policy.write_text(
            """
rules:
  - name: budget_limit
    max_cost_per_call: 2.0
  - name: file_access
    denied_paths: ["/etc", "/root", "/var"]
  - name: sql_restriction
    denied_operations: ["DROP", "DELETE", "TRUNCATE", "ALTER", "GRANT"]
""".strip(),
            encoding="utf-8",
        )
        result = runner.invoke(main, ["invariants", "--policy", str(policy)])
        assert result.exit_code == 0
        assert "Invariant Checks:" in result.output
        assert "10/10 passed" in result.output


def test_proxy_uses_orchesis_yaml_proxy_defaults(monkeypatch) -> None:
    class _FakeProxy:
        last_policy_path = None
        last_config = None

        def __init__(self, policy_path=None, config=None):
            self.__class__.last_policy_path = policy_path
            self.__class__.last_config = config

        def start(self, blocking=True):
            return None

        def stop(self):
            return None

    runner = CliRunner()
    with runner.isolated_filesystem():
        _write_file(
            Path("orchesis.yaml"),
            """
rules: []
proxy:
  host: "0.0.0.0"
  port: 8080
  timeout: 42
  upstream:
    anthropic: "https://anthropic.example"
    openai: "https://openai.example"
""".strip(),
        )
        monkeypatch.setattr("orchesis.proxy.LLMHTTPProxy", _FakeProxy)
        result = runner.invoke(main, ["proxy"])

    assert result.exit_code == 0
    assert _FakeProxy.last_policy_path == "orchesis.yaml"
    assert _FakeProxy.last_config is not None
    assert _FakeProxy.last_config.host == "0.0.0.0"
    assert _FakeProxy.last_config.port == 8080
    assert _FakeProxy.last_config.timeout == 42.0
    assert _FakeProxy.last_config.upstream["anthropic"] == "https://anthropic.example"
    assert _FakeProxy.last_config.upstream["openai"] == "https://openai.example"
    assert "Listening: http://0.0.0.0:8080" in result.output


def test_proxy_cli_flags_override_policy_proxy_settings(monkeypatch) -> None:
    class _FakeProxy:
        last_policy_path = None
        last_config = None

        def __init__(self, policy_path=None, config=None):
            self.__class__.last_policy_path = policy_path
            self.__class__.last_config = config

        def start(self, blocking=True):
            return None

        def stop(self):
            return None

    runner = CliRunner()
    with runner.isolated_filesystem():
        _write_file(
            Path("orchesis.yaml"),
            """
rules: []
proxy:
  host: "0.0.0.0"
  port: 8080
  timeout: 42
  upstream:
    anthropic: "https://anthropic.example"
    openai: "https://openai.example"
""".strip(),
        )
        monkeypatch.setattr("orchesis.proxy.LLMHTTPProxy", _FakeProxy)
        result = runner.invoke(
            main,
            [
                "proxy",
                "--policy",
                "orchesis.yaml",
                "--host",
                "127.0.0.1",
                "--port",
                "8101",
                "--timeout",
                "15",
                "--upstream-anthropic",
                "https://anthropic.override",
                "--upstream-openai",
                "https://openai.override",
            ],
        )

    assert result.exit_code == 0
    assert _FakeProxy.last_policy_path == "orchesis.yaml"
    assert _FakeProxy.last_config is not None
    assert _FakeProxy.last_config.host == "127.0.0.1"
    assert _FakeProxy.last_config.port == 8101
    assert _FakeProxy.last_config.timeout == 15.0
    assert _FakeProxy.last_config.upstream["anthropic"] == "https://anthropic.override"
    assert _FakeProxy.last_config.upstream["openai"] == "https://openai.override"
    assert "Listening: http://127.0.0.1:8101" in result.output


def test_version_flag() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_proxy_requires_config() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main, ["proxy", "--config", "missing.yaml"])
    assert result.exit_code != 0


def test_audit_openclaw_requires_config() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["audit-openclaw"])
    assert result.exit_code != 0


def test_no_command_shows_help() -> None:
    runner = CliRunner()
    result = runner.invoke(main, [])
    assert result.exit_code == 0
    assert "Usage:" in result.output


def test_unknown_command_shows_help() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["unknown-command"])
    assert result.exit_code != 0
    assert "No such command" in result.output


def test_cli_entry_point_importable() -> None:
    module = importlib.import_module("orchesis.cli")
    assert callable(getattr(module, "main"))


def test_version_matches_init() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output
