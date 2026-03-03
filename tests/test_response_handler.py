from __future__ import annotations

from orchesis.cost_tracker import CostTracker
from orchesis.request_parser import ParsedResponse, ToolCall
from orchesis.response_handler import ResponseProcessor


def test_process_response_without_secrets_allowed() -> None:
    processor = ResponseProcessor(scan_secrets=True)
    parsed = ParsedResponse(provider="openai", model="gpt-4o", content_text="hello world", input_tokens=1, output_tokens=1)
    result = processor.process(parsed)
    assert result["allowed"] is True
    assert result["secrets_found"] == []


def test_process_response_with_openai_key_blocked() -> None:
    processor = ResponseProcessor(scan_secrets=True)
    parsed = ParsedResponse(provider="openai", model="gpt-4o", content_text="sk-abcdefghijklmnopqrstuvwxyz123")
    result = processor.process(parsed)
    assert result["allowed"] is False
    assert "OpenAI API key" in result["reason"]


def test_process_response_with_aws_key_blocked() -> None:
    processor = ResponseProcessor(scan_secrets=True)
    parsed = ParsedResponse(provider="openai", model="gpt-4o", content_text="AKIA1234567890ABCDEF")
    result = processor.process(parsed)
    assert result["allowed"] is False
    assert any(item["type"] == "AWS access key" for item in result["secrets_found"])


def test_process_response_with_jwt_blocked() -> None:
    processor = ResponseProcessor(scan_secrets=True)
    parsed = ParsedResponse(provider="openai", model="gpt-4o", content_text="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0")
    result = processor.process(parsed)
    assert result["allowed"] is False
    assert any(item["type"] == "JWT token" for item in result["secrets_found"])


def test_process_response_with_private_key_blocked() -> None:
    processor = ResponseProcessor(scan_secrets=True)
    parsed = ParsedResponse(provider="openai", model="gpt-4o", content_text="-----BEGIN PRIVATE KEY-----\nabc")
    result = processor.process(parsed)
    assert result["allowed"] is False
    assert any(item["type"] == "Private key" for item in result["secrets_found"])


def test_cost_tracking_records_tokens() -> None:
    tracker = CostTracker()
    processor = ResponseProcessor(cost_tracker=tracker)
    parsed = ParsedResponse(provider="openai", model="gpt-4o-mini", input_tokens=1000, output_tokens=500)
    result = processor.process(parsed, task_id="task-1")
    assert result["cost"] > 0
    assert tracker.get_task_cost("task-1") > 0


def test_cost_tracking_calculates_from_model_rates() -> None:
    tracker = CostTracker()
    processor = ResponseProcessor(cost_tracker=tracker)
    parsed = ParsedResponse(provider="openai", model="gpt-4o-mini", input_tokens=1000, output_tokens=1000)
    result = processor.process(parsed)
    assert abs(result["cost"] - 0.00075) < 1e-9


def test_no_crash_when_tracker_none() -> None:
    processor = ResponseProcessor(cost_tracker=None)
    parsed = ParsedResponse(provider="anthropic", model="claude-sonnet-4", input_tokens=100, output_tokens=100)
    result = processor.process(parsed)
    assert result["cost"] == 0.0


def test_no_crash_when_response_has_no_usage_data() -> None:
    tracker = CostTracker()
    processor = ResponseProcessor(cost_tracker=tracker)
    parsed = ParsedResponse(provider="openai", model="gpt-4o")
    result = processor.process(parsed)
    assert result["tokens"]["input"] == 0
    assert result["tokens"]["output"] == 0


def test_multiple_secrets_detected_in_one_response() -> None:
    processor = ResponseProcessor(scan_secrets=True)
    text = "sk-abcdefghijklmnopqrstuvwxyz123 and AKIA1234567890ABCDEF"
    parsed = ParsedResponse(provider="openai", model="gpt-4o", content_text=text)
    result = processor.process(parsed)
    assert len(result["secrets_found"]) >= 2


def test_empty_content_text_passes() -> None:
    processor = ResponseProcessor(scan_secrets=True)
    parsed = ParsedResponse(provider="openai", model="gpt-4o", content_text="")
    result = processor.process(parsed)
    assert result["allowed"] is True


def test_partial_key_not_matching_pattern_passes() -> None:
    processor = ResponseProcessor(scan_secrets=True)
    parsed = ParsedResponse(provider="openai", model="gpt-4o", content_text="sk-short")
    result = processor.process(parsed)
    assert result["allowed"] is True


def test_process_includes_tool_calls_in_output() -> None:
    processor = ResponseProcessor(scan_secrets=False)
    parsed = ParsedResponse(provider="anthropic", tool_calls=[ToolCall(name="read_file", params={"path": "/tmp/a"})])
    result = processor.process(parsed)
    assert result["tool_calls"][0]["name"] == "read_file"


def test_secrets_found_property_returns_copy() -> None:
    processor = ResponseProcessor(scan_secrets=True)
    parsed = ParsedResponse(provider="openai", model="gpt-4o", content_text="AKIA1234567890ABCDEF")
    processor.process(parsed)
    first = processor.secrets_found
    first.append({"type": "x", "match_preview": "x"})
    second = processor.secrets_found
    assert len(second) < len(first)


def test_scan_disabled_does_not_block_secret_text() -> None:
    processor = ResponseProcessor(scan_secrets=False)
    parsed = ParsedResponse(provider="openai", model="gpt-4o", content_text="AKIA1234567890ABCDEF")
    result = processor.process(parsed)
    assert result["allowed"] is True

