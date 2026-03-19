from __future__ import annotations

import json
from io import BytesIO
from unittest.mock import patch

import urllib.error

from orchesis.sdk import OrchesisClient


def _mock_json_response(payload: dict):
    class Resp:
        def read(self) -> bytes:
            return json.dumps(payload).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *args):
            _ = args

    return Resp()


def _http_error(code: int = 500) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        "http://localhost:8090/health",
        code,
        "Error",
        {},
        BytesIO(b'{"error":"boom"}'),
    )


def test_client_initializes() -> None:
    client = OrchesisClient(token="tkn")
    assert client.api_url == "http://localhost:8090"
    assert client.token == "tkn"


def test_health_check_method() -> None:
    with patch("urllib.request.urlopen") as mock:
        mock.return_value = _mock_json_response({"status": "ok"})
        client = OrchesisClient()
        payload = client.get_health()
    assert payload["status"] == "ok"


def test_request_builds_correctly() -> None:
    with patch("urllib.request.urlopen") as mock:
        mock.return_value = _mock_json_response({"ok": True})
        client = OrchesisClient(api_url="http://localhost:8090")
        _ = client.evaluate({"tool": "read_file"})
        req = mock.call_args[0][0]
    assert req.full_url.endswith("/api/v1/evaluate")
    assert req.get_method() == "POST"


def test_auth_header_included() -> None:
    with patch("urllib.request.urlopen") as mock:
        mock.return_value = _mock_json_response({"status": "ok"})
        client = OrchesisClient(token="secret")
        _ = client.get_health()
        req = mock.call_args[0][0]
    assert "Authorization" in req.headers
    assert req.headers["Authorization"] == "Bearer secret"


def test_no_auth_header_without_token() -> None:
    with patch("urllib.request.urlopen") as mock:
        mock.return_value = _mock_json_response({"status": "ok"})
        client = OrchesisClient()
        _ = client.get_health()
        req = mock.call_args[0][0]
    assert "Authorization" not in req.headers


def test_timeout_configurable() -> None:
    client = OrchesisClient(timeout=1.25)
    assert client.timeout == 1.25


def test_error_handled_gracefully() -> None:
    with patch("urllib.request.urlopen") as mock:
        mock.side_effect = _http_error(500)
        client = OrchesisClient()
        payload = client.get_health()
    assert "error" in payload


def test_evaluate_method() -> None:
    with patch("urllib.request.urlopen") as mock:
        mock.return_value = _mock_json_response({"allowed": True, "reasons": []})
        client = OrchesisClient()
        payload = client.evaluate({"tool": "read_file", "params": {"path": "/tmp/a.txt"}})
    assert payload["allowed"] is True


def test_is_connected_false_when_offline() -> None:
    with patch("urllib.request.urlopen") as mock:
        mock.side_effect = urllib.error.URLError("offline")
        client = OrchesisClient()
        assert client.is_connected() is False
