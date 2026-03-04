from __future__ import annotations

from orchesis.contrib.secret_scanner import SecretScanner
from orchesis.contrib.secret_scanner_plugin import SecretScannerPlugin
from orchesis.state import RateLimitTracker


def test_detect_openai_key() -> None:
    scanner = SecretScanner()
    findings = scanner.scan_text("token=sk-abcdefghijklmnopqrstuvwxyz123456")
    assert any(item["pattern"] == "openai_key" for item in findings)


def test_detect_aws_access_key() -> None:
    scanner = SecretScanner()
    findings = scanner.scan_text("AKIAABCDEFGHIJKLMNOP")
    assert any(item["pattern"] == "aws_access_key" for item in findings)


def test_detect_private_key() -> None:
    scanner = SecretScanner()
    findings = scanner.scan_text("-----BEGIN PRIVATE KEY-----")
    assert any(item["pattern"] in {"private_key", "ssh_private"} for item in findings)


def test_detect_postgres_url() -> None:
    scanner = SecretScanner()
    findings = scanner.scan_text("postgres://user:pass@db.local:5432/app")
    assert any(item["pattern"] == "postgres_url" for item in findings)


def test_detect_jwt_token() -> None:
    scanner = SecretScanner()
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    findings = scanner.scan_text(token)
    assert any(item["pattern"] == "jwt_token" for item in findings)


def test_detect_generic_secret() -> None:
    scanner = SecretScanner()
    findings = scanner.scan_text("password=SuperSecret123")
    assert any(item["pattern"] == "generic_secret" for item in findings)


def test_scan_dict_recursive() -> None:
    scanner = SecretScanner()
    data = {"config": {"auth": {"api_key": "sk-ant-abcdefghijklmnopqrstuvwxyz-1234"}}}
    findings = scanner.scan_dict(data, path="params")
    assert findings
    assert findings[0]["path"].startswith("params.config.auth")


def test_scan_tool_call() -> None:
    scanner = SecretScanner()
    findings = scanner.scan_tool_call("http_request", {"headers": {"Authorization": "Bearer abcdefghijklmnopqrstuvwxyz123456"}})
    assert findings
    assert findings[0]["tool"] == "http_request"


def test_has_secrets_true() -> None:
    scanner = SecretScanner()
    assert scanner.has_secrets("aws_secret_access_key=1234567890123456789012345")


def test_has_secrets_false_clean_text() -> None:
    scanner = SecretScanner()
    assert scanner.has_secrets("just a normal sentence") is False


def test_redact_secrets() -> None:
    scanner = SecretScanner()
    text = "my key is sk-abcdefghijklmnopqrstuvwxyz123456"
    findings = scanner.scan_text(text)
    redacted = SecretScanner.redact(text, findings)
    assert "sk-abcdefghijklmnopqrstuvwxyz123456" not in redacted
    assert "[REDACTED]" in redacted


def test_ignore_patterns() -> None:
    scanner = SecretScanner(ignore_patterns=["generic_secret"])
    findings = scanner.scan_text("password=SuperSecret123")
    assert not any(item["pattern"] == "generic_secret" for item in findings)


def test_plugin_blocks_on_secret() -> None:
    plugin = SecretScannerPlugin()
    reasons, checked = plugin.evaluate(
        {"type": "secret_scanner", "severity_threshold": "high"},
        {"tool": "write_file", "params": {"content": "AKIAABCDEFGHIJKLMNOP"}},
        state=RateLimitTracker(persist_path=None),
        agent_id="cursor",
        session_id="s1",
    )
    assert checked == ["secret_scanner"]
    assert any("secret_scanner:" in reason for reason in reasons)


def test_scan_text_handles_fuzzed_binary_input_gracefully() -> None:
    scanner = SecretScanner()
    crash_input = b"1\x00\x00\xff\xff\xff],\x00\x00\x88"
    findings = scanner.scan_text(crash_input)  # type: ignore[arg-type]
    assert isinstance(findings, list)
