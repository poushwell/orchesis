import json
from pathlib import Path

from orchesis.logger import append_decision, read_decisions
from orchesis.models import Decision


def _read_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def test_append_decision_creates_jsonl_file(tmp_path: Path) -> None:
    log_path = tmp_path / "decisions.jsonl"
    decision = Decision(allowed=True, rules_checked=["budget_limit"])
    request = {"tool": "sql_query", "cost": 0.1}

    append_decision(decision, request, log_path)

    assert log_path.exists()
    assert len(_read_lines(log_path)) == 1


def test_append_decision_writes_expected_payload_fields(tmp_path: Path) -> None:
    log_path = tmp_path / "decisions.jsonl"
    decision = Decision(
        allowed=False,
        reasons=["sql_restriction: DROP is denied"],
        rules_checked=["sql_restriction"],
        timestamp="2026-03-01T14:30:00+00:00",
    )
    request = {"tool": "sql_query", "cost": 0.1}

    append_decision(decision, request, log_path)

    line = _read_lines(log_path)[0]
    payload = json.loads(line)
    assert payload == {
        "timestamp": "2026-03-01T14:30:00+00:00",
        "tool": "sql_query",
        "decision": "DENY",
        "reasons": ["sql_restriction: DROP is denied"],
        "rules_checked": ["sql_restriction"],
        "cost": 0.1,
    }


def test_append_decision_appends_multiple_lines_in_order(tmp_path: Path) -> None:
    log_path = tmp_path / "decisions.jsonl"
    request = {"tool": "sql_query", "cost": 0.1}

    append_decision(Decision(allowed=True, timestamp="2026-03-01T10:00:00+00:00"), request, log_path)
    append_decision(Decision(allowed=False, timestamp="2026-03-01T11:00:00+00:00"), request, log_path)

    lines = _read_lines(log_path)
    assert len(lines) == 2
    first = json.loads(lines[0])
    second = json.loads(lines[1])
    assert first["decision"] == "ALLOW"
    assert second["decision"] == "DENY"


def test_read_decisions_returns_all_entries(tmp_path: Path) -> None:
    log_path = tmp_path / "decisions.jsonl"
    request = {"tool": "sql_query", "cost": 0.1}
    append_decision(Decision(allowed=True), request, log_path)
    append_decision(Decision(allowed=False, reasons=["x"]), request, log_path)

    items = read_decisions(log_path)

    assert len(items) == 2
    assert items[0]["decision"] == "ALLOW"
    assert items[1]["decision"] == "DENY"


def test_read_decisions_returns_empty_for_missing_file(tmp_path: Path) -> None:
    log_path = tmp_path / "missing.jsonl"

    items = read_decisions(log_path)

    assert items == []


def test_read_decisions_skips_blank_lines(tmp_path: Path) -> None:
    log_path = tmp_path / "decisions.jsonl"
    content = (
        '{"timestamp":"2026-03-01T10:00:00+00:00","tool":"sql_query","decision":"ALLOW",'
        '"reasons":[],"rules_checked":[],"cost":0.1}\n\n'
        '{"timestamp":"2026-03-01T11:00:00+00:00","tool":"sql_query","decision":"DENY",'
        '"reasons":["x"],"rules_checked":["sql_restriction"],"cost":0.1}\n'
    )
    log_path.write_text(content, encoding="utf-8")

    items = read_decisions(log_path)

    assert len(items) == 2


def test_append_decision_includes_signature_when_provided(tmp_path: Path) -> None:
    log_path = tmp_path / "decisions.jsonl"
    decision = Decision(allowed=True, timestamp="2026-03-01T10:00:00+00:00")
    request = {"tool": "sql_query", "cost": 0.1}

    append_decision(decision, request, log_path, signature="abc123")

    payload = json.loads(_read_lines(log_path)[0])
    assert payload["signature"] == "abc123"
