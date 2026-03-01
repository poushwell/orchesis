from __future__ import annotations

import asyncio
import json

import pytest

from orchesis.models import Decision
from orchesis.proxy import OrchesisProxy, ProxyConfig


class _Engine:
    def evaluate(self, payload: dict):
        _ = payload
        return Decision(allowed=True, reasons=[], rules_checked=[])


def _policy(block_request: bool = True, redact: bool = True) -> dict:
    return {
        "proxy": {
            "scan_requests": True,
            "scan_responses": True,
            "secret_scanning": {
                "enabled": True,
                "severity_threshold": "high",
                "block_on_critical": block_request,
            },
            "pii_scanning": {
                "enabled": True,
                "severity_threshold": "medium",
                "block_on_critical": False,
            },
            "response_redaction": {
                "enabled": redact,
                "redact_secrets": True,
                "redact_pii": False,
            },
        }
    }


def test_proxy_scans_request_for_secrets() -> None:
    proxy = OrchesisProxy(_Engine(), ProxyConfig(upstream_url="http://localhost:3000"), policy=_policy())
    findings = proxy._scan_request("write_file", {"token": "sk-abcdefghijklmnopqrstuvwxyz123"})
    assert findings


@pytest.mark.asyncio
async def test_proxy_blocks_critical_secret_in_request() -> None:
    proxy = OrchesisProxy(_Engine(), ProxyConfig(upstream_url="http://localhost:3000"), policy=_policy(block_request=True))

    async def _forward(method, path, headers, body):
        _ = (method, path, headers, body)
        raise AssertionError("must not forward blocked request")

    proxy._forward_request = _forward  # type: ignore[method-assign]
    server = await asyncio.start_server(proxy.handle_request, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    body = json.dumps(
        {"tool_name": "write_file", "params": {"token": "sk-abcdefghijklmnopqrstuvwxyz123"}}
    ).encode("utf-8")
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(
        (
            "POST /invoke HTTP/1.1\r\n"
            "Host: test\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode("utf-8")
        + body
    )
    await writer.drain()
    raw = await reader.read()
    writer.close()
    await writer.wait_closed()
    server.close()
    await server.wait_closed()
    assert b"HTTP/1.1 403 Forbidden" in raw
    assert b"credential_leak_in_request" in raw


def test_proxy_scans_response_for_secrets() -> None:
    proxy = OrchesisProxy(_Engine(), ProxyConfig(upstream_url="http://localhost:3000"), policy=_policy())
    findings = proxy._scan_response_findings("read_file", b"api key sk-abcdefghijklmnopqrstuvwxyz123")
    assert findings["secrets"]


def test_proxy_redacts_secrets_in_response() -> None:
    proxy = OrchesisProxy(_Engine(), ProxyConfig(upstream_url="http://localhost:3000"), policy=_policy(redact=True))
    body = b'{"result":"API key is sk-abcdefghijklmnopqrstuvwxyz123"}'
    redacted = proxy._redact_response_body(body)
    assert b"[REDACTED-openai_key]" in redacted


def test_proxy_pii_scan_response() -> None:
    proxy = OrchesisProxy(_Engine(), ProxyConfig(upstream_url="http://localhost:3000"), policy=_policy())
    findings = proxy._scan_response_findings("read_file", b"Email: john.doe@example.com")
    assert findings["pii"]


def test_proxy_stats_tracks_secrets() -> None:
    proxy = OrchesisProxy(_Engine(), ProxyConfig(upstream_url="http://localhost:3000"), policy=_policy())
    proxy.stats.record_detection(secrets_detected=2, secrets_blocked=1, pii_detected=3)
    payload = proxy.stats.to_dict()
    assert payload["secrets_detected"] == 2
    assert payload["secrets_blocked"] == 1
    assert payload["pii_detected"] == 3


def test_proxy_scan_config_from_policy() -> None:
    proxy = OrchesisProxy(
        _Engine(),
        ProxyConfig(upstream_url="http://localhost:3000"),
        policy={
            "proxy": {
                "scan_requests": False,
                "scan_responses": False,
                "secret_scanning": {"enabled": False},
                "pii_scanning": {"enabled": False},
            }
        },
    )
    assert proxy._scan_requests is False
    assert proxy._scan_responses is False
    assert proxy._secret_enabled is False
    assert proxy._pii_enabled is False
