from __future__ import annotations

from orchesis.engine import evaluate


def _policy() -> dict:
    return {
        "rules": [],
        "session_policies": {
            "group": {
                "sandbox": {
                    "filesystem": {
                        "allowed_paths": ["/tmp/agent-work"],
                        "denied_paths": ["/etc", "/root", "~/.ssh", ".env"],
                        "max_file_size_bytes": 1024,
                        "deny_hidden_files": True,
                    },
                    "network": {
                        "allowed_domains": ["api.openai.com"],
                        "denied_domains": ["webhook.site", "requestbin.com"],
                        "max_request_size_bytes": 1024,
                        "deny_ip_addresses": True,
                    },
                    "execution": {
                        "deny_shell": True,
                        "deny_eval": True,
                        "deny_subprocess": True,
                        "allowed_commands": [],
                    },
                    "data": {
                        "deny_pii_in_output": True,
                        "deny_secrets_in_output": True,
                        "max_output_length": 20,
                    },
                }
            },
            "dm": {
                "sandbox": {
                    "filesystem": {"denied_paths": ["/etc"]},
                    "execution": {"deny_shell": False},
                }
            },
        },
    }


def test_sandbox_filesystem_denied_path() -> None:
    decision = evaluate({"tool": "read_file", "params": {"path": "/etc/passwd"}}, _policy(), session_type="group")
    assert decision.allowed is False
    assert any("sandbox: filesystem path" in item for item in decision.reasons)


def test_sandbox_filesystem_allowed_path() -> None:
    decision = evaluate(
        {"tool": "read_file", "params": {"path": "/tmp/agent-work/safe.txt"}},
        _policy(),
        session_type="group",
    )
    assert decision.allowed is True


def test_sandbox_filesystem_hidden_file_denied() -> None:
    decision = evaluate(
        {"tool": "read_file", "params": {"path": "/tmp/agent-work/.env"}},
        _policy(),
        session_type="group",
    )
    assert decision.allowed is False


def test_sandbox_filesystem_max_file_size() -> None:
    decision = evaluate(
        {"tool": "read_file", "params": {"path": "/tmp/agent-work/a.txt", "file_size_bytes": 5000}},
        _policy(),
        session_type="group",
    )
    assert decision.allowed is False
    assert any("max_file_size_bytes" in item for item in decision.reasons)


def test_sandbox_network_denied_domain() -> None:
    decision = evaluate(
        {"tool": "web_search", "params": {"url": "https://webhook.site/abc"}},
        _policy(),
        session_type="group",
    )
    assert decision.allowed is False
    assert any("domain" in item for item in decision.reasons)


def test_sandbox_network_deny_ip_address() -> None:
    decision = evaluate(
        {"tool": "web_search", "params": {"url": "http://1.2.3.4/a"}},
        _policy(),
        session_type="group",
    )
    assert decision.allowed is False
    assert any("IP address" in item for item in decision.reasons)


def test_sandbox_network_allowed_domain() -> None:
    decision = evaluate(
        {"tool": "web_search", "params": {"url": "https://api.openai.com/v1"}},
        _policy(),
        session_type="group",
    )
    assert decision.allowed is True


def test_sandbox_execution_deny_shell() -> None:
    decision = evaluate(
        {"tool": "shell", "params": {"command": "ls"}},
        _policy(),
        session_type="group",
    )
    assert decision.allowed is False
    assert any("shell execution denied" in item for item in decision.reasons)


def test_sandbox_data_max_output_length() -> None:
    decision = evaluate(
        {"tool": "send_message", "params": {"output": "x" * 100}},
        _policy(),
        session_type="group",
    )
    assert decision.allowed is False
    assert any("max_output_length" in item for item in decision.reasons)


def test_sandbox_group_vs_dm_different() -> None:
    group_decision = evaluate(
        {"tool": "shell", "params": {"command": "ls"}},
        _policy(),
        session_type="group",
    )
    dm_decision = evaluate(
        {"tool": "shell", "params": {"command": "ls"}},
        _policy(),
        session_type="dm",
    )
    assert group_decision.allowed is False
    assert dm_decision.allowed is True
