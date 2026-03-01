from __future__ import annotations

from orchesis.contrib.pii_detector import PiiDetector
from orchesis.contrib.pii_detector_plugin import PiiDetectorPlugin


def test_detect_email() -> None:
    findings = PiiDetector().scan_text("contact: user@example.com")
    assert any(item["pattern"] == "email" for item in findings)


def test_detect_phone() -> None:
    findings = PiiDetector().scan_text("call me +1 555-123-4567")
    assert any("phone" in item["pattern"] for item in findings)


def test_detect_ssn() -> None:
    findings = PiiDetector().scan_text("ssn 123-45-6789")
    assert any(item["pattern"] == "ssn" for item in findings)
    assert any(item["match"].endswith("6789") for item in findings if item["pattern"] == "ssn")


def test_detect_credit_card_visa() -> None:
    findings = PiiDetector().scan_text("card 4111 1111 1111 1111")
    assert any(item["pattern"] == "credit_card_visa" for item in findings)


def test_detect_iban() -> None:
    findings = PiiDetector().scan_text("iban DE89370400440532013000")
    assert any(item["pattern"] == "iban" for item in findings)


def test_detect_date_of_birth() -> None:
    findings = PiiDetector().scan_text("DOB: 01/31/1989")
    assert any(item["pattern"] == "date_of_birth" for item in findings)


def test_no_false_positive_normal_text() -> None:
    findings = PiiDetector().scan_text("just a normal sentence with no sensitive fields")
    assert findings == []


def test_scan_dict_recursive() -> None:
    findings = PiiDetector().scan_dict({"user": {"profile": {"email": "user@example.com"}}}, path="params")
    assert any(item.get("path") == "params.user.profile.email" for item in findings)


def test_classify_data_restricted() -> None:
    level = PiiDetector().classify_data("cc 4111 1111 1111 1111")
    assert level == "restricted"


def test_classify_data_public() -> None:
    level = PiiDetector().classify_data("simple text")
    assert level == "public"


def test_redact_text() -> None:
    detector = PiiDetector()
    redacted = detector.redact_text("email user@example.com and ssn 123-45-6789")
    assert "[REDACTED-email]" in redacted
    assert "[REDACTED-ssn]" in redacted


def test_plugin_blocks_on_pii() -> None:
    plugin = PiiDetectorPlugin({"block_on_pii": True})
    result = plugin.evaluate("read_file", {"user": {"ssn": "123-45-6789"}}, "agent_a", {})
    assert result["allowed"] is False
    assert result["classification"] == "restricted"


def test_plugin_allows_whitelisted_tool() -> None:
    plugin = PiiDetectorPlugin({"block_on_pii": True, "allowed_pii_tools": ["send_email"]})
    result = plugin.evaluate("send_email", {"to": "user@example.com"}, "agent_a", {})
    assert result["allowed"] is True
    assert result["pii_findings"]


def test_plugin_redact_for_audit() -> None:
    plugin = PiiDetectorPlugin({"redact_in_logs": True})
    event = {"params": {"email": "user@example.com", "ssn": "123-45-6789"}}
    redacted = plugin.redact_for_audit(event)
    assert "user@example.com" not in str(redacted)
    assert "123-45-6789" not in str(redacted)
