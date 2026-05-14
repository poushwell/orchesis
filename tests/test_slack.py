from __future__ import annotations

import httpx

from orchesis.integrations.slack import SlackEmitter, SlackNotifier
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


def test_format_deny_message() -> None:
    notifier = SlackNotifier("https://hooks.slack.com/services/test")
    payload = notifier.format_deny(_event("DENY"))
    assert "blocks" in payload
    assert payload["blocks"][0]["text"]["text"] == "Agent Blocked"


def test_format_anomaly_message() -> None:
    notifier = SlackNotifier("https://hooks.slack.com/services/test")
    payload = notifier.format_anomaly({"severity": "high", "detail": "deny rate spike"})
    assert "Anomaly Detected" in payload["blocks"][0]["text"]["text"]


def test_send_success(monkeypatch) -> None:  # noqa: ANN001
    def _fake_post(url: str, json: dict, timeout: float):  # noqa: A002
        _ = (url, json, timeout)

        class _Resp:
            def raise_for_status(self) -> None:
                return None

        return _Resp()

    monkeypatch.setattr(httpx, "post", _fake_post)
    notifier = SlackNotifier("https://hooks.slack.com/services/test")
    assert notifier.send({"blocks": []}) is True


def test_send_failure_silent(monkeypatch) -> None:  # noqa: ANN001
    def _fake_post(url: str, json: dict, timeout: float):  # noqa: A002
        _ = (url, json, timeout)
        raise httpx.ConnectError("boom")

    monkeypatch.setattr(httpx, "post", _fake_post)
    notifier = SlackNotifier("https://hooks.slack.com/services/test")
    assert notifier.send({"blocks": []}) is False


def test_emitter_filters_events(monkeypatch) -> None:  # noqa: ANN001
    sent: list[dict] = []

    def _fake_send(self, payload: dict) -> bool:  # noqa: ANN001
        sent.append(payload)
        return True

    monkeypatch.setattr(SlackNotifier, "send", _fake_send)
    notifier = SlackNotifier("https://hooks.slack.com/services/test", notify_on=["DENY"])
    emitter = SlackEmitter(notifier)
    emitter.emit(_event("ALLOW"))
    emitter.emit(_event("DENY"))
    assert len(sent) == 1
