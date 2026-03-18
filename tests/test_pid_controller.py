from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.pid_controller_v2 import PIDControllerV2


def test_pid_update_returns_correction() -> None:
    pid = PIDControllerV2()
    correction = pid.update(current_value=80.0, setpoint=100.0)
    assert isinstance(correction, float)
    assert correction > 0


def test_ews_tau_warning_triggered() -> None:
    pid = PIDControllerV2()
    result = pid.check_ews_tau([1, 2, 3, 4, 5, 6, 7])
    assert result["warning"] is True
    assert result["requests_to_failure"] == 15


def test_ews_tau_no_warning_stable() -> None:
    pid = PIDControllerV2()
    result = pid.check_ews_tau([3, 3, 3, 3, 3, 3])
    assert result["warning"] is False
    assert result["requests_to_failure"] is None


def test_zipf_drift_detected() -> None:
    pid = PIDControllerV2()
    result = pid.check_zipf_drift([100, 95, 92, 91, 90, 89, 88])
    assert result["warning"] is True
    assert result["drift"] >= 0.2


def test_latency_zscore_spike() -> None:
    pid = PIDControllerV2()
    result = pid.check_latency_zscore([100, 102, 99, 101, 350])
    assert result["warning"] is True
    assert result["spike_detected"] is True


def test_warning_level_combined() -> None:
    pid = PIDControllerV2()
    result = pid.get_warning_level(
        "s-1",
        {
            "values": [1, 2, 3, 4, 5, 6],
            "token_frequencies": [100, 95, 93, 92, 90],
            "latencies_ms": [100, 101, 99, 98, 380],
        },
    )
    assert result["level"] == "red"
    assert len(result["active_warnings"]) == 3


def _event(session_id: str, prompt_length: int, duration_us: int) -> dict:
    return {
        "event_id": f"evt-{session_id}-{prompt_length}",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "agent_id": "agent-pid",
        "tool": "tool.test",
        "params_hash": "abc",
        "cost": 0.1,
        "decision": "ALLOW",
        "reasons": [],
        "rules_checked": [],
        "rules_triggered": [],
        "evaluation_order": [],
        "evaluation_duration_us": duration_us,
        "policy_version": "v1",
        "state_snapshot": {"session_id": session_id, "prompt_length": prompt_length, "prompt_tokens": prompt_length},
    }


def test_api_check_ews_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)
    response = client.post(
        "/api/v1/pid/check-ews",
        json={"values": [1, 2, 3, 4, 5, 6]},
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.status_code == 200
    assert response.json()["warning"] is True


def test_api_warning_level_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    log_path = tmp_path / "decisions.jsonl"
    rows = [
        _event("sess-1", 10, 100_000),
        _event("sess-1", 15, 101_000),
        _event("sess-1", 20, 98_000),
        _event("sess-1", 22, 99_000),
        _event("sess-1", 28, 390_000),
    ]
    log_path.write_text("\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(log_path))
    client = TestClient(app)
    response = client.get("/api/v1/pid/sess-1/warning-level", headers={"Authorization": "Bearer test-token"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["level"] in {"yellow", "orange", "red"}
    assert isinstance(payload["active_warnings"], list)
