from __future__ import annotations

import hashlib
import hmac
import json
from urllib.error import URLError

from orchesis.telemetry import DecisionEvent
from orchesis import webhooks as webhooks_module
from orchesis.webhooks import WebhookConfig, WebhookEmitter


def _event(decision: str = "DENY") -> DecisionEvent:
    return DecisionEvent(
        event_id="evt-1",
        timestamp="2026-01-01T00:00:00+00:00",
        agent_id="untrusted_bot",
        tool="delete_file",
        params_hash="hash",
        cost=0.1,
        decision=decision,
        reasons=["context_rules: blocked"] if decision == "DENY" else [],
        rules_checked=["context_rules"],
        rules_triggered=["context_rules"],
        evaluation_order=["context_rules"],
        evaluation_duration_us=20,
        policy_version="abc123",
        state_snapshot={"tool_counts": {}},
    )


def test_webhook_filters_deny_only(monkeypatch) -> None:
    sent: list[dict] = []

    def _fake_urlopen(request, timeout: float):  # noqa: ANN001
        _ = timeout
        payload = json.loads(request.data.decode("utf-8"))
        sent.append(payload)

        class _Resp:
            status = 200

            def __enter__(self):  # noqa: ANN001
                return self

            def __exit__(self, exc_type, exc, tb):  # noqa: ANN001
                _ = (exc_type, exc, tb)
                return False

        return _Resp()

    monkeypatch.setattr(webhooks_module, "urlopen", _fake_urlopen)
    emitter = WebhookEmitter(WebhookConfig(url="https://example.com/hook", events=["DENY"]))
    emitter.emit(_event("ALLOW"))
    emitter.emit(_event("DENY"))
    assert len(sent) == 1
    assert sent[0]["decision"] == "DENY"


def test_webhook_payload_format() -> None:
    emitter = WebhookEmitter(WebhookConfig(url="https://example.com/hook"))
    payload = emitter._build_payload(_event("DENY"))
    assert payload["event_type"] == "decision"
    assert payload["event_id"] == "evt-1"
    assert payload["agent_id"] == "untrusted_bot"
    assert payload["tool"] == "delete_file"
    assert payload["decision"] == "DENY"
    assert payload["policy_version"] == "abc123"


def test_webhook_hmac_signature() -> None:
    secret = "whsec_test"
    emitter = WebhookEmitter(WebhookConfig(url="https://example.com/hook", secret=secret))
    payload = emitter._build_payload(_event("DENY"))
    assert "orchesis_signature" in payload
    payload_without_signature = dict(payload)
    signature = payload_without_signature.pop("orchesis_signature")
    raw = json.dumps(payload_without_signature, ensure_ascii=False, sort_keys=True).encode("utf-8")
    expected = "hmac-sha256=" + hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()
    assert signature == expected


def test_webhook_timeout_doesnt_crash(monkeypatch) -> None:
    def _timeout(request, timeout: float):  # noqa: ANN001
        _ = (request, timeout)
        raise URLError("timeout")

    monkeypatch.setattr(webhooks_module, "urlopen", _timeout)
    emitter = WebhookEmitter(WebhookConfig(url="https://example.com/hook", retry_count=0))
    emitter.emit(_event("DENY"))
    assert len(emitter.failed_deliveries) == 1
