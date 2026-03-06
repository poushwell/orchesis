"""Tests for Orchesis Python SDK."""

from __future__ import annotations

import json
from io import BytesIO
from unittest.mock import patch

import pytest

from orchesis.sdk import (
    NotFoundError,
    OrchesisClient,
    OrchesisError,
    ServerError,
)


def _make_response(
    body: dict | None = None,
    status: int = 200,
) -> object:
    class Resp:
        def read(self) -> bytes:
            return json.dumps(body or {}).encode("utf-8")
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass

    return Resp()


def _make_http_error(status: int, body: dict | None = None) -> Exception:
    import urllib.error
    return urllib.error.HTTPError(
        "http://localhost:8080/stats",
        status,
        "Error",
        {},
        BytesIO(json.dumps(body or {}).encode("utf-8")),
    )


# --- HTTP Helpers (8 tests) ---


def test_get_success() -> None:
    with patch("urllib.request.urlopen") as mock:
        mock.return_value.read.return_value = json.dumps({"requests": 42}).encode("utf-8")
        mock.return_value.__enter__ = lambda s: s
        mock.return_value.__exit__ = lambda s, *a: None
        client = OrchesisClient("http://localhost:8080")
        result = client.get_stats()
        assert result["requests"] == 42


def test_post_success() -> None:
    with patch("urllib.request.urlopen") as mock:
        mock.return_value.read.return_value = json.dumps({"experiment_id": "exp-1"}).encode("utf-8")
        mock.return_value.__enter__ = lambda s: s
        mock.return_value.__exit__ = lambda s, *a: None
        client = OrchesisClient("http://localhost:8080")
        result = client.create_experiment("Test", [{"name": "a", "weight": 1.0}])
        assert result["experiment_id"] == "exp-1"


def test_delete_success() -> None:
    with patch("urllib.request.urlopen") as mock:
        mock.return_value.read.return_value = json.dumps({"deleted": True}).encode("utf-8")
        mock.return_value.__enter__ = lambda s: s
        mock.return_value.__exit__ = lambda s, *a: None
        client = OrchesisClient("http://localhost:8080")
        result = client.delete_session("sess-1")
        assert result["deleted"] is True


def test_404_raises_not_found() -> None:
    with patch("urllib.request.urlopen") as mock:
        mock.side_effect = _make_http_error(404)
        client = OrchesisClient("http://localhost:8080")
        with pytest.raises(NotFoundError) as exc:
            client.get_session("nonexistent")
        assert exc.value.status_code == 404


def test_500_raises_server_error() -> None:
    with patch("urllib.request.urlopen") as mock:
        mock.side_effect = _make_http_error(500)
        client = OrchesisClient("http://localhost:8080")
        with pytest.raises(ServerError) as exc:
            client.get_stats()
        assert exc.value.status_code == 500


def test_connection_refused() -> None:
    import urllib.error
    with patch("urllib.request.urlopen") as mock:
        mock.side_effect = urllib.error.URLError("Connection refused")
        client = OrchesisClient("http://localhost:8080")
        with pytest.raises(OrchesisError):
            client.get_stats()


def test_timeout_error() -> None:
    with patch("urllib.request.urlopen") as mock:
        mock.side_effect = TimeoutError("timed out")
        client = OrchesisClient("http://localhost:8080")
        with pytest.raises(OrchesisError):
            client.get_stats()


def test_auth_header_sent() -> None:
    with patch("urllib.request.urlopen") as mock:
        mock.return_value.read.return_value = b"{}"
        mock.return_value.__enter__ = lambda s: s
        mock.return_value.__exit__ = lambda s, *a: None
        client = OrchesisClient("http://localhost:8080", api_key="secret-token")
        client.get_stats()
        call_args = mock.call_args
        req = call_args[0][0]
        assert "Authorization" in req.headers
        assert "Bearer secret-token" in req.headers["Authorization"]


# --- Stats & Health (3 tests) ---


def test_get_stats() -> None:
    with patch("urllib.request.urlopen") as mock:
        mock.return_value.read.return_value = json.dumps({"requests": 10, "blocked": 0}).encode("utf-8")
        mock.return_value.__enter__ = lambda s: s
        mock.return_value.__exit__ = lambda s, *a: None
        client = OrchesisClient("http://localhost:8080")
        stats = client.get_stats()
        assert "requests" in stats
        assert stats["requests"] == 10


def test_is_healthy_true() -> None:
    with patch("urllib.request.urlopen") as mock:
        mock.return_value.read.return_value = b"{}"
        mock.return_value.__enter__ = lambda s: s
        mock.return_value.__exit__ = lambda s, *a: None
        client = OrchesisClient("http://localhost:8080")
        assert client.is_healthy() is True


def test_is_healthy_false() -> None:
    import urllib.error
    with patch("urllib.request.urlopen") as mock:
        mock.side_effect = urllib.error.URLError("refused")
        client = OrchesisClient("http://localhost:8080")
        assert client.is_healthy() is False


# --- Sessions (4 tests) ---


def test_list_sessions() -> None:
    with patch("urllib.request.urlopen") as mock:
        mock.return_value.read.return_value = json.dumps({"sessions": [{"id": "s1"}]}).encode("utf-8")
        mock.return_value.__enter__ = lambda s: s
        mock.return_value.__exit__ = lambda s, *a: None
        client = OrchesisClient("http://localhost:8080")
        sessions = client.list_sessions()
        assert isinstance(sessions, list)
        assert len(sessions) == 1
        assert sessions[0]["id"] == "s1"


def test_get_session() -> None:
    with patch("urllib.request.urlopen") as mock:
        mock.return_value.read.return_value = json.dumps({"session": {"id": "s1", "requests": 5}}).encode("utf-8")
        mock.return_value.__enter__ = lambda s: s
        mock.return_value.__exit__ = lambda s, *a: None
        client = OrchesisClient("http://localhost:8080")
        result = client.get_session("s1")
        assert result["id"] == "s1"
        assert result["requests"] == 5


def test_delete_session() -> None:
    with patch("urllib.request.urlopen") as mock:
        mock.return_value.read.return_value = json.dumps({"deleted": True}).encode("utf-8")
        mock.return_value.__enter__ = lambda s: s
        mock.return_value.__exit__ = lambda s, *a: None
        client = OrchesisClient("http://localhost:8080")
        result = client.delete_session("s1")
        assert result["deleted"] is True


def test_export_session() -> None:
    with patch("urllib.request.urlopen") as mock:
        mock.return_value.read.return_value = json.dumps({"air": {"version": "1.0"}}).encode("utf-8")
        mock.return_value.__enter__ = lambda s: s
        mock.return_value.__exit__ = lambda s, *a: None
        client = OrchesisClient("http://localhost:8080")
        result = client.export_session("s1")
        assert "air" in result


# --- Flow X-Ray (4 tests) ---


def test_list_flow_sessions() -> None:
    with patch("urllib.request.urlopen") as mock:
        mock.return_value.read.return_value = json.dumps({"sessions": [{"id": "f1"}]}).encode("utf-8")
        mock.return_value.__enter__ = lambda s: s
        mock.return_value.__exit__ = lambda s, *a: None
        client = OrchesisClient("http://localhost:8080")
        sessions = client.list_flow_sessions()
        assert isinstance(sessions, list)
        assert sessions[0]["id"] == "f1"


def test_analyze_flow() -> None:
    with patch("urllib.request.urlopen") as mock:
        mock.return_value.read.return_value = json.dumps({"topology": {"depth": 3}}).encode("utf-8")
        mock.return_value.__enter__ = lambda s: s
        mock.return_value.__exit__ = lambda s, *a: None
        client = OrchesisClient("http://localhost:8080")
        result = client.analyze_flow("f1")
        assert "topology" in result
        assert result["topology"]["depth"] == 3


def test_get_flow_graph() -> None:
    with patch("urllib.request.urlopen") as mock:
        mock.return_value.read.return_value = json.dumps({"nodes": [], "edges": []}).encode("utf-8")
        mock.return_value.__enter__ = lambda s: s
        mock.return_value.__exit__ = lambda s, *a: None
        client = OrchesisClient("http://localhost:8080")
        result = client.get_flow_graph("f1")
        assert "nodes" in result


def test_get_flow_patterns() -> None:
    with patch("urllib.request.urlopen") as mock:
        mock.return_value.read.return_value = json.dumps({"pattern_counts": {}}).encode("utf-8")
        mock.return_value.__enter__ = lambda s: s
        mock.return_value.__exit__ = lambda s, *a: None
        client = OrchesisClient("http://localhost:8080")
        result = client.get_flow_patterns()
        assert "pattern_counts" in result or "sessions_tracked" in result


# --- Experiments (8 tests) ---


def test_list_experiments() -> None:
    with patch("urllib.request.urlopen") as mock:
        mock.return_value.read.return_value = json.dumps({"experiments": [{"id": "e1"}]}).encode("utf-8")
        mock.return_value.__enter__ = lambda s: s
        mock.return_value.__exit__ = lambda s, *a: None
        client = OrchesisClient("http://localhost:8080")
        exps = client.list_experiments()
        assert isinstance(exps, list)
        assert exps[0]["id"] == "e1"


def test_create_experiment() -> None:
    with patch("urllib.request.urlopen") as mock:
        mock.return_value.read.return_value = json.dumps({"experiment_id": "exp-1"}).encode("utf-8")
        mock.return_value.__enter__ = lambda s: s
        mock.return_value.__exit__ = lambda s, *a: None
        client = OrchesisClient("http://localhost:8080")
        result = client.create_experiment("Test", [{"name": "a", "weight": 0.5}, {"name": "b", "weight": 0.5}])
        assert result["experiment_id"] == "exp-1"
        call_args = mock.call_args
        req = call_args[0][0]
        body = json.loads(req.data.decode("utf-8"))
        assert body["name"] == "Test"
        assert len(body["variants"]) == 2


def test_start_experiment() -> None:
    with patch("urllib.request.urlopen") as mock:
        mock.return_value.read.return_value = json.dumps({"started": True}).encode("utf-8")
        mock.return_value.__enter__ = lambda s: s
        mock.return_value.__exit__ = lambda s, *a: None
        client = OrchesisClient("http://localhost:8080")
        result = client.start_experiment("exp-1")
        assert result["started"] is True
        assert mock.call_args[0][0].full_url.endswith("/api/experiments/exp-1/start")


def test_stop_experiment() -> None:
    with patch("urllib.request.urlopen") as mock:
        mock.return_value.read.return_value = json.dumps({"variants": [], "winner": None}).encode("utf-8")
        mock.return_value.__enter__ = lambda s: s
        mock.return_value.__exit__ = lambda s, *a: None
        client = OrchesisClient("http://localhost:8080")
        result = client.stop_experiment("exp-1")
        assert "variants" in result or "winner" in result


def test_pause_resume() -> None:
    with patch("urllib.request.urlopen") as mock:
        mock.return_value.read.return_value = json.dumps({"paused": True}).encode("utf-8")
        mock.return_value.__enter__ = lambda s: s
        mock.return_value.__exit__ = lambda s, *a: None
        client = OrchesisClient("http://localhost:8080")
        result = client.pause_experiment("exp-1")
        assert result["paused"] is True
    with patch("urllib.request.urlopen") as mock:
        mock.return_value.read.return_value = json.dumps({"resumed": True}).encode("utf-8")
        mock.return_value.__enter__ = lambda s: s
        mock.return_value.__exit__ = lambda s, *a: None
        result = client.resume_experiment("exp-1")
        assert result["resumed"] is True


def test_get_results() -> None:
    with patch("urllib.request.urlopen") as mock:
        mock.return_value.read.return_value = json.dumps({"variants": [{"name": "a", "success_rate": 0.0}]}).encode("utf-8")
        mock.return_value.__enter__ = lambda s: s
        mock.return_value.__exit__ = lambda s, *a: None
        client = OrchesisClient("http://localhost:8080")
        result = client.get_experiment_results("exp-1")
        assert "variants" in result


def test_get_live_stats() -> None:
    with patch("urllib.request.urlopen") as mock:
        mock.return_value.read.return_value = json.dumps({"live": {"requests": 10}}).encode("utf-8")
        mock.return_value.__enter__ = lambda s: s
        mock.return_value.__exit__ = lambda s, *a: None
        client = OrchesisClient("http://localhost:8080")
        result = client.get_experiment_live("exp-1")
        assert isinstance(result, dict)


def test_create_with_kwargs() -> None:
    with patch("urllib.request.urlopen") as mock:
        mock.return_value.read.return_value = json.dumps({"experiment_id": "exp-1"}).encode("utf-8")
        mock.return_value.__enter__ = lambda s: s
        mock.return_value.__exit__ = lambda s, *a: None
        client = OrchesisClient("http://localhost:8080")
        client.create_experiment(
            "Test",
            [{"name": "a", "weight": 1.0}],
            target_models=["gpt-4"],
            max_requests=100,
        )
        call_args = mock.call_args
        req = call_args[0][0]
        body = json.loads(req.data.decode("utf-8"))
        assert body["target_models"] == ["gpt-4"]
        assert body["max_requests"] == 100


# --- Task Tracking (2 tests) ---


def test_get_outcomes() -> None:
    with patch("urllib.request.urlopen") as mock:
        mock.return_value.read.return_value = json.dumps({"success": 10, "failure": 2}).encode("utf-8")
        mock.return_value.__enter__ = lambda s: s
        mock.return_value.__exit__ = lambda s, *a: None
        client = OrchesisClient("http://localhost:8080")
        result = client.get_task_outcomes()
        assert isinstance(result, dict)


def test_get_correlations() -> None:
    with patch("urllib.request.urlopen") as mock:
        mock.return_value.read.return_value = json.dumps({"insights": []}).encode("utf-8")
        mock.return_value.__enter__ = lambda s: s
        mock.return_value.__exit__ = lambda s, *a: None
        client = OrchesisClient("http://localhost:8080")
        result = client.get_task_correlations()
        assert isinstance(result, dict)


# --- Compliance (3 tests) ---


def test_get_summary() -> None:
    with patch("urllib.request.urlopen") as mock:
        mock.return_value.read.return_value = json.dumps({"frameworks": {}}).encode("utf-8")
        mock.return_value.__enter__ = lambda s: s
        mock.return_value.__exit__ = lambda s, *a: None
        client = OrchesisClient("http://localhost:8080")
        result = client.get_compliance_summary()
        assert "frameworks" in result or isinstance(result, dict)


def test_get_coverage_all() -> None:
    with patch("urllib.request.urlopen") as mock:
        mock.return_value.read.return_value = json.dumps({"frameworks": {}}).encode("utf-8")
        mock.return_value.__enter__ = lambda s: s
        mock.return_value.__exit__ = lambda s, *a: None
        client = OrchesisClient("http://localhost:8080")
        result = client.get_compliance_coverage()
        assert isinstance(result, dict)


def test_get_coverage_framework() -> None:
    with patch("urllib.request.urlopen") as mock:
        mock.return_value.read.return_value = json.dumps({"items": []}).encode("utf-8")
        mock.return_value.__enter__ = lambda s: s
        mock.return_value.__exit__ = lambda s, *a: None
        client = OrchesisClient("http://localhost:8080")
        result = client.get_compliance_coverage("owasp")
        assert isinstance(result, dict)


# --- Integration (3 tests) ---


def test_context_manager() -> None:
    with patch("urllib.request.urlopen") as mock:
        mock.return_value.read.return_value = b"{}"
        mock.return_value.__enter__ = lambda s: s
        mock.return_value.__exit__ = lambda s, *a: None
        with OrchesisClient("http://localhost:8080") as client:
            assert client is not None
            client.get_stats()


def test_repr() -> None:
    client = OrchesisClient("http://localhost:8080")
    r = repr(client)
    assert "OrchesisClient" in r
    assert "localhost:8080" in r


def test_custom_headers() -> None:
    with patch("urllib.request.urlopen") as mock:
        mock.return_value.read.return_value = b"{}"
        mock.return_value.__enter__ = lambda s: s
        mock.return_value.__exit__ = lambda s, *a: None
        client = OrchesisClient("http://localhost:8080", headers={"X-Custom": "value"})
        client.get_stats()
        call_args = mock.call_args
        req = call_args[0][0]
        h = {k.lower(): v for k, v in req.headers.items()}
        assert "x-custom" in h
        assert h["x-custom"] == "value"
