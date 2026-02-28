from __future__ import annotations

import httpx
import pytest

from orchesis.client import EvaluateResult, OrchesisClient, OrchesisDenied, orchesis_guard


def test_evaluate_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    def _mock_request(**kwargs):
        _ = kwargs
        return httpx.Response(
            200,
            json={
                "allowed": True,
                "reasons": [],
                "rules_checked": ["budget_limit"],
                "evaluation_us": 120,
                "policy_version": "abc123",
            },
        )

    monkeypatch.setattr(httpx, "request", _mock_request)
    client = OrchesisClient(api_token="orch_sk_test")
    result = client.evaluate("read_file", params={"path": "/data/a.txt"})
    assert result.allowed is True
    assert bool(result) is True


def test_evaluate_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    def _mock_request(**kwargs):
        _ = kwargs
        return httpx.Response(
            200,
            json={
                "allowed": False,
                "reasons": ["sql_restriction: DROP is denied"],
                "rules_checked": ["sql_restriction"],
                "evaluation_us": 220,
                "policy_version": "abc123",
            },
        )

    monkeypatch.setattr(httpx, "request", _mock_request)
    client = OrchesisClient(api_token="orch_sk_test")
    result = client.evaluate("run_sql", params={"query": "DROP TABLE users"})
    assert result.allowed is False
    assert "DROP is denied" in result.reasons[0]


def test_is_allowed_convenience(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        OrchesisClient,
        "evaluate",
        lambda self, tool, **kwargs: EvaluateResult(True, [], [], 10, "v1"),  # noqa: ARG005
    )
    assert OrchesisClient(api_token="orch_sk_test").is_allowed("read_file") is True


def test_evaluate_result_bool() -> None:
    allow = EvaluateResult(True, [], [], 1, "v1")
    deny = EvaluateResult(False, ["blocked"], [], 1, "v1")
    assert bool(allow) is True
    assert bool(deny) is False


def test_get_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    def _mock_request(**kwargs):
        _ = kwargs
        return httpx.Response(200, json={"version_id": "v1", "yaml_content": "rules: []"})

    monkeypatch.setattr(httpx, "request", _mock_request)
    payload = OrchesisClient(api_token="orch_sk_test").get_policy()
    assert payload["version_id"] == "v1"


def test_update_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    def _mock_request(**kwargs):
        _ = kwargs
        return httpx.Response(200, json={"version_id": "v2", "loaded_at": "2026-01-01T00:00:00Z"})

    monkeypatch.setattr(httpx, "request", _mock_request)
    payload = OrchesisClient(api_token="orch_sk_test").update_policy("rules: []")
    assert payload["version_id"] == "v2"


def test_set_agent_tier(monkeypatch: pytest.MonkeyPatch) -> None:
    def _mock_request(**kwargs):
        _ = kwargs
        return httpx.Response(
            200,
            json={"agent_id": "bot", "previous_tier": "assistant", "new_tier": "blocked"},
        )

    monkeypatch.setattr(httpx, "request", _mock_request)
    payload = OrchesisClient(api_token="orch_sk_test").set_agent_tier("bot", "blocked")
    assert payload["new_tier"] == "blocked"


def test_status(monkeypatch: pytest.MonkeyPatch) -> None:
    def _mock_request(**kwargs):
        _ = kwargs
        return httpx.Response(200, json={"version": "0.6.0", "total_decisions": 10})

    monkeypatch.setattr(httpx, "request", _mock_request)
    payload = OrchesisClient(api_token="orch_sk_test").status()
    assert payload["total_decisions"] == 10


def test_auth_header_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = {}

    def _mock_request(**kwargs):
        seen["headers"] = kwargs.get("headers", {})
        return httpx.Response(
            200,
            json={
                "allowed": True,
                "reasons": [],
                "rules_checked": [],
                "evaluation_us": 5,
                "policy_version": "v1",
            },
        )

    monkeypatch.setattr(httpx, "request", _mock_request)
    _ = OrchesisClient(api_token="orch_sk_token").evaluate("read_file")
    assert seen["headers"]["Authorization"] == "Bearer orch_sk_token"


def test_connection_error_handled(monkeypatch: pytest.MonkeyPatch) -> None:
    def _mock_request(**kwargs):
        request = httpx.Request("GET", "http://localhost:8080/api/v1/status")
        raise httpx.ConnectError("boom", request=request)

    monkeypatch.setattr(httpx, "request", _mock_request)
    with pytest.raises(ConnectionError):
        OrchesisClient(api_token="orch_sk_test").status()


def test_orchesis_guard_decorator_allow(monkeypatch: pytest.MonkeyPatch) -> None:
    client = OrchesisClient(api_token="orch_sk_test")
    monkeypatch.setattr(
        client,
        "evaluate",
        lambda *args, **kwargs: EvaluateResult(True, [], [], 1, "v1"),  # noqa: ARG005
    )

    @orchesis_guard(client, tool="run_sql", agent_id="my_agent")
    def execute_query(query: str) -> str:
        return f"ok:{query}"

    assert execute_query("SELECT 1") == "ok:SELECT 1"


def test_orchesis_guard_decorator_deny(monkeypatch: pytest.MonkeyPatch) -> None:
    client = OrchesisClient(api_token="orch_sk_test")
    monkeypatch.setattr(
        client,
        "evaluate",
        lambda *args, **kwargs: EvaluateResult(  # noqa: ARG005
            False,
            ["sql_restriction: DROP is denied"],
            ["sql_restriction"],
            1,
            "v1",
        ),
    )

    @orchesis_guard(client, tool="run_sql", agent_id="my_agent")
    def execute_query(query: str) -> str:
        return f"ok:{query}"

    with pytest.raises(OrchesisDenied):
        _ = execute_query("DROP TABLE users")
