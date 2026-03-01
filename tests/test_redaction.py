from __future__ import annotations

from orchesis.redaction import AuditRedactor


def test_redact_secret_in_params() -> None:
    redactor = AuditRedactor()
    event = {"params": {"api_key": "sk-abcdefghijklmnopqrstuvwxyz1234"}}
    redacted = redactor.redact_event(event)
    assert redacted != event
    assert "sk-abcdefghijklmnopqrstuvwxyz1234" not in str(redacted)


def test_redact_pii_in_reason() -> None:
    redactor = AuditRedactor()
    event = {"reasons": ["Contact user@example.com for support"]}
    redacted = redactor.redact_event(event)
    assert "user@example.com" not in str(redacted)


def test_redact_preserves_metadata() -> None:
    redactor = AuditRedactor(preserve_fields=["tool_name", "agent_id", "timestamp"])
    event = {
        "tool_name": "read_file",
        "agent_id": "a-1",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "params": {"email": "user@example.com"},
    }
    redacted = redactor.redact_event(event)
    assert redacted["tool_name"] == "read_file"
    assert redacted["agent_id"] == "a-1"
    assert redacted["timestamp"] == "2026-01-01T00:00:00+00:00"


def test_redact_deep_nested_dict() -> None:
    redactor = AuditRedactor()
    event = {"context": {"nested": {"user": {"ssn": "123-45-6789"}}}}
    redacted = redactor.redact_event(event)
    assert "123-45-6789" not in str(redacted)


def test_redact_disabled_passes_through() -> None:
    redactor = AuditRedactor(redact_pii=False, redact_secrets=False)
    event = {"params": {"email": "user@example.com"}}
    redacted = redactor.redact_event(event)
    assert redacted == event
    assert redacted is not event


def test_redact_string_mixed_content() -> None:
    redactor = AuditRedactor()
    text = "safe text + user@example.com + sk-abcdefghijklmnopqrstuvwxyz1234"
    out = redactor.redact_string(text)
    assert "safe text" in out
    assert "user@example.com" not in out
    assert "sk-abcdefghijklmnopqrstuvwxyz1234" not in out
