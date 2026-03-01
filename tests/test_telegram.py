from __future__ import annotations

import httpx

from orchesis.integrations.telegram import TelegramEmitter, TelegramNotifier
from orchesis.telemetry import DecisionEvent


def _event(decision: str = "DENY") -> DecisionEvent:
    return DecisionEvent(
        event_id="evt-1",
        timestamp="2026-03-01T10:23:45+00:00",
        agent_id="cursor",
        tool="read_file",
        params_hash="hash",
        cost=0.1,
        decision=decision,
        reasons=["file_access: path '/etc/passwd' is denied"] if decision == "DENY" else [],
        rules_checked=["file_access"],
        rules_triggered=["file_access"],
        evaluation_order=["file_access"],
        evaluation_duration_us=45,
        policy_version="abc123def456",
        state_snapshot={"tool_counts": {}},
    )


def test_format_deny_telegram() -> None:
    notifier = TelegramNotifier("token", "chat")
    text = notifier.format_deny(_event("DENY"))
    assert "Agent Blocked" in text
    assert "cursor" in text


def test_send_telegram(monkeypatch) -> None:  # noqa: ANN001
    def _fake_post(url: str, json: dict, timeout: float):  # noqa: A002
        _ = (url, json, timeout)

        class _Resp:
            def raise_for_status(self) -> None:
                return None

        return _Resp()

    monkeypatch.setattr(httpx, "post", _fake_post)
    notifier = TelegramNotifier("token", "chat")
    assert notifier.send("hello") is True


def test_send_failure_silent_telegram(monkeypatch) -> None:  # noqa: ANN001
    def _fake_post(url: str, json: dict, timeout: float):  # noqa: A002
        _ = (url, json, timeout)
        raise httpx.TimeoutException("boom")

    monkeypatch.setattr(httpx, "post", _fake_post)
    notifier = TelegramNotifier("token", "chat")
    assert notifier.send("hello") is False


def test_emitter_filters_events_telegram(monkeypatch) -> None:  # noqa: ANN001
    sent: list[str] = []

    def _fake_send(self, text: str) -> bool:  # noqa: ANN001
        sent.append(text)
        return True

    monkeypatch.setattr(TelegramNotifier, "send", _fake_send)
    notifier = TelegramNotifier("token", "chat", notify_on=["DENY"])
    emitter = TelegramEmitter(notifier)
    emitter.emit(_event("ALLOW"))
    emitter.emit(_event("DENY"))
    assert len(sent) == 1
