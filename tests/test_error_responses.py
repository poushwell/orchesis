from __future__ import annotations

from dataclasses import fields

from orchesis.error_responses import ErrorResponseBuilder, SmartError


def test_build_prompt_injection_error() -> None:
    err = ErrorResponseBuilder.build("prompt_injection")
    assert err.code == "ORCH-SEC-001"
    assert err.blocked is True


def test_build_budget_exceeded_with_values() -> None:
    err = ErrorResponseBuilder.build("budget_exceeded", limit="10.00", current="12.34")
    assert "10.00" in err.reason
    assert "12.34" in err.reason


def test_build_tool_blocked_with_allowed_list() -> None:
    err = ErrorResponseBuilder.build("tool_blocked", tool="shell", agent="a1", allowed="read,write")
    assert "shell" in err.reason
    assert "read,write" in err.suggestion


def test_to_http_response_format() -> None:
    err = ErrorResponseBuilder.build("prompt_injection")
    payload = ErrorResponseBuilder.to_http_response(err)
    assert payload["error"] is True
    assert payload["code"] == err.code
    assert payload["suggestion"]


def test_to_hook_output_format() -> None:
    err = ErrorResponseBuilder.build("prompt_injection")
    output = ErrorResponseBuilder.to_hook_output(err)
    assert "[BLOCKED]" in output
    assert err.code in output


def test_to_header_compact() -> None:
    err = ErrorResponseBuilder.build("prompt_injection")
    header = ErrorResponseBuilder.to_header(err)
    assert "|" in header
    assert err.code in header


def test_unknown_error_type() -> None:
    err = ErrorResponseBuilder.build("something_new", reason="x", suggestion="y")
    assert err.code == "ORCH-UNKNOWN-001"
    assert err.suggestion == "y"


def test_all_templates_have_required_fields() -> None:
    required = {item.name for item in fields(SmartError)}
    for value in ErrorResponseBuilder.TEMPLATES.values():
        assert required == set(value.__dict__.keys())


def test_suggestion_always_present() -> None:
    for key in ErrorResponseBuilder.TEMPLATES:
        err = ErrorResponseBuilder.build(key)
        assert isinstance(err.suggestion, str)
        assert err.suggestion.strip()


def test_domain_blocked_formatting() -> None:
    err = ErrorResponseBuilder.build("domain_blocked", domain="example.com", blocked_list="example.com,corp.local")
    assert "example.com" in err.reason
    assert "corp.local" in err.suggestion


def test_approval_required_formatting() -> None:
    err = ErrorResponseBuilder.build("approval_required", tool="shell", agent="bot", approval_id="a-1")
    assert "a-1" in err.suggestion


def test_rate_limited_formatting() -> None:
    err = ErrorResponseBuilder.build(
        "rate_limited",
        agent="bot",
        current=10,
        max=10,
        window="60s",
        retry_after=30,
    )
    assert "30" in err.suggestion


def test_loop_detected_not_blocked() -> None:
    err = ErrorResponseBuilder.build("loop_detected", pattern="abc", count=5)
    assert err.blocked is False


def test_http_response_contains_detector() -> None:
    err = ErrorResponseBuilder.build("credential_leak", direction="request", pattern_name="api_key", pattern="sk-")
    payload = ErrorResponseBuilder.to_http_response(err)
    assert payload["detector"] == "secrets_filter"


def test_unknown_to_hook_output() -> None:
    err = ErrorResponseBuilder.build("unknown", reason="blocked", suggestion="change input")
    output = ErrorResponseBuilder.to_hook_output(err)
    assert "ORCH-UNKNOWN-001" in output

