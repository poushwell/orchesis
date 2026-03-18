from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from orchesis.alert_rules import AlertRule, AlertRulesEngine
from orchesis.api import create_api_app


def _rule_config(**overrides):
    base = {
        "name": "high_cost",
        "metric": "cost_today",
        "operator": "gt",
        "threshold": 10.0,
        "action": "webhook",
        "cooldown_minutes": 60,
        "enabled": True,
    }
    base.update(overrides)
    return base


def test_rule_fires_on_threshold() -> None:
    engine = AlertRulesEngine([AlertRule(_rule_config())])
    fired = engine.evaluate({"cost_today": 11.0})
    assert len(fired) == 1
    assert fired[0]["rule"] == "high_cost"


def test_rule_respects_cooldown() -> None:
    engine = AlertRulesEngine([AlertRule(_rule_config(cooldown_minutes=60))])
    first = engine.evaluate({"cost_today": 12.0})
    second = engine.evaluate({"cost_today": 13.0})
    assert len(first) == 1
    assert second == []


def test_rule_disabled_does_not_fire() -> None:
    engine = AlertRulesEngine([AlertRule(_rule_config(enabled=False))])
    fired = engine.evaluate({"cost_today": 100.0})
    assert fired == []


def test_add_remove_rule() -> None:
    engine = AlertRulesEngine([])
    engine.add_rule(_rule_config(name="a"))
    assert len(engine.list_rules()) == 1
    assert engine.remove_rule("a") is True
    assert engine.remove_rule("a") is False


def test_evaluate_multiple_rules() -> None:
    rules = [
        AlertRule(_rule_config(name="high_cost", metric="cost_today", operator="gt", threshold=10)),
        AlertRule(_rule_config(name="low_cache", metric="cache_hit_rate", operator="lt", threshold=0.05, action="log")),
    ]
    engine = AlertRulesEngine(rules)
    fired = engine.evaluate({"cost_today": 15.0, "cache_hit_rate": 0.01})
    names = {item["rule"] for item in fired}
    assert names == {"high_cost", "low_cache"}


def test_api_crud_endpoints(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)
    headers = {"Authorization": "Bearer test-token"}

    add_resp = client.post("/api/v1/alert-rules", json=_rule_config(name="cost_now"), headers=headers)
    assert add_resp.status_code == 200
    assert add_resp.json()["name"] == "cost_now"

    list_resp = client.get("/api/v1/alert-rules", headers=headers)
    assert list_resp.status_code == 200
    assert any(item["name"] == "cost_now" for item in list_resp.json()["rules"])

    eval_resp = client.post(
        "/api/v1/alert-rules/evaluate",
        json={"metrics": {"cost_today": 50.0, "cache_hit_rate": 1.0}},
        headers=headers,
    )
    assert eval_resp.status_code == 200
    assert eval_resp.json()["count"] >= 1

    del_resp = client.delete("/api/v1/alert-rules/cost_now", headers=headers)
    assert del_resp.status_code == 200
    assert del_resp.json()["deleted"] is True


def test_yaml_config_loaded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        (
            "api:\n"
            "  token: test-token\n"
            "rules: []\n"
            "alert_rules:\n"
            "  - name: high_cost\n"
            "    metric: cost_today\n"
            "    operator: gt\n"
            "    threshold: 10.0\n"
            "    action: webhook\n"
            "    cooldown_minutes: 60\n"
            "  - name: low_cache\n"
            "    metric: cache_hit_rate\n"
            "    operator: lt\n"
            "    threshold: 0.05\n"
            "    action: log\n"
        ),
        encoding="utf-8",
    )
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)
    response = client.get("/api/v1/alert-rules", headers={"Authorization": "Bearer test-token"})
    assert response.status_code == 200
    payload = response.json()
    names = {item["name"] for item in payload["rules"]}
    assert "high_cost" in names
    assert "low_cache" in names
