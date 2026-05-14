from __future__ import annotations

from unittest.mock import patch

import pytest

from orchesis.sdk import OrchesisClient, OrchesisError


def test_get_casura_incidents_method() -> None:
    client = OrchesisClient()
    with patch.object(client, "_request", return_value={"incidents": []}) as mock_request:
        payload = client.get_casura_incidents(limit=7)
    assert payload == {"incidents": []}
    mock_request.assert_called_once_with("GET", "/api/v1/casura/incidents?limit=7")


def test_search_incidents_method() -> None:
    client = OrchesisClient()
    with patch.object(client, "_request", return_value={"matches": []}) as mock_request:
        payload = client.search_incidents("prompt injection")
    assert payload == {"matches": []}
    mock_request.assert_called_once_with(
        "POST",
        "/api/v1/casura/incidents/search",
        {"query": "prompt injection"},
    )


def test_get_aabb_leaderboard_method() -> None:
    client = OrchesisClient()
    with patch.object(client, "_request", return_value={"leaderboard": []}) as mock_request:
        payload = client.get_aabb_leaderboard()
    assert payload == {"leaderboard": []}
    mock_request.assert_called_once_with("GET", "/api/v1/aabb/leaderboard")


def test_get_are_report_method() -> None:
    client = OrchesisClient()
    with patch.object(client, "_request", return_value={"slos": []}) as mock_request:
        payload = client.get_are_report()
    assert payload == {"slos": []}
    mock_request.assert_called_once_with("GET", "/api/v1/are/report")


def test_get_fleet_status_method() -> None:
    client = OrchesisClient()
    with patch.object(client, "_request", return_value={"agents": []}) as mock_request:
        payload = client.get_fleet_status()
    assert payload == {"agents": []}
    mock_request.assert_called_once_with("GET", "/api/v1/fleet/status")


def test_get_ecosystem_summary_method() -> None:
    client = OrchesisClient()
    with patch.object(client, "_request", return_value={"ecosystem": {}}) as mock_request:
        payload = client.get_ecosystem_summary()
    assert payload == {"ecosystem": {}}
    mock_request.assert_called_once_with("GET", "/api/v1/ecosystem/summary")


def test_repr_includes_url() -> None:
    client = OrchesisClient(api_url="http://localhost:8080")
    with patch.object(client, "is_connected", return_value=False):
        rep = repr(client)
    assert "OrchesisClient(url=http://localhost:8080" in rep


def test_all_methods_handle_error() -> None:
    client = OrchesisClient()
    methods = [
        lambda: client.get_casura_incidents(),
        lambda: client.search_incidents("x"),
        lambda: client.get_aabb_leaderboard(),
        lambda: client.get_are_report(),
        lambda: client.get_arc_certificates(),
        lambda: client.analyze_session("sess-1"),
        lambda: client.get_fleet_status(),
        lambda: client.get_ecosystem_summary(),
        lambda: client.get_compliance_certificate(),
    ]
    with patch.object(client, "_request", side_effect=OrchesisError("boom")):
        for fn in methods:
            with pytest.raises(OrchesisError):
                fn()
