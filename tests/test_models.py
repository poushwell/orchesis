from datetime import datetime

from orchesis.models import Decision


def test_decision_defaults() -> None:
    decision = Decision()
    assert decision.allowed is True
    assert decision.reasons == []


def test_decision_with_deny_reasons() -> None:
    reasons = ["sql_restriction: DROP is denied"]
    decision = Decision(allowed=False, reasons=reasons)
    assert decision.allowed is False
    assert decision.reasons == reasons


def test_timestamp_is_auto_generated_with_timezone() -> None:
    decision = Decision()
    parsed = datetime.fromisoformat(decision.timestamp)
    assert parsed.tzinfo is not None
