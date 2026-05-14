from __future__ import annotations

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.shadow_mode import ShadowModeRunner


def test_shadow_evaluate_match() -> None:
    runner = ShadowModeRunner({}, lambda req, pol: {"decision": "ALLOW", "allowed": True})
    result = runner.shadow_evaluate({"request_id": "r1"}, {"decision": "ALLOW", "allowed": True})
    assert result["match"] is True
    assert result["divergence_reason"] is None


def test_shadow_evaluate_divergence() -> None:
    runner = ShadowModeRunner({}, lambda req, pol: {"decision": "DENY", "allowed": False})
    result = runner.shadow_evaluate({"request_id": "r2"}, {"decision": "ALLOW", "allowed": True})
    assert result["match"] is False
    assert "real=ALLOW" in str(result["divergence_reason"])


def test_divergence_rate_computed() -> None:
    runner = ShadowModeRunner({}, lambda req, pol: {"decision": "ALLOW", "allowed": True})
    runner.shadow_evaluate({"request_id": "a"}, {"decision": "ALLOW", "allowed": True})
    runner.shadow_evaluate({"request_id": "b"}, {"decision": "DENY", "allowed": False})
    report = runner.get_divergence_report()
    assert report["total_evaluated"] == 2
    assert report["divergences"] == 1
    assert report["divergence_rate"] == 0.5


def test_false_positives_counted() -> None:
    runner = ShadowModeRunner({}, lambda req, pol: {"decision": "DENY", "allowed": False})
    runner.shadow_evaluate({"request_id": "x"}, {"decision": "ALLOW", "allowed": True})
    report = runner.get_divergence_report()
    assert report["false_positives"] == 1
    assert report["false_negatives"] == 0


def test_recommendation_generated() -> None:
    runner = ShadowModeRunner({}, lambda req, pol: {"decision": "ALLOW", "allowed": True})
    for idx in range(30):
        runner.shadow_evaluate({"request_id": f"r-{idx}"}, {"decision": "ALLOW", "allowed": True})
    assert runner.get_recommendation() == "promote_shadow_policy"


def test_api_shadow_status(tmp_path) -> None:
    policy = tmp_path / "policy.yaml"
    shadow = tmp_path / "shadow_policy.yaml"
    policy.write_text(
        """
api:
  token: test-token
shadow_mode:
  enabled: true
  shadow_policy: shadow_policy.yaml
  log_divergences: true
rules:
  - name: budget_limit
    max_cost_per_call: 10.0
""".strip(),
        encoding="utf-8",
    )
    shadow.write_text(
        """
rules:
  - name: budget_limit
    max_cost_per_call: 0.1
""".strip(),
        encoding="utf-8",
    )
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)
    res = client.get("/api/v1/shadow/status", headers={"Authorization": "Bearer test-token"})
    assert res.status_code == 200
    body = res.json()
    assert body["enabled"] is True
    assert "report" in body


def test_api_divergences_endpoint(tmp_path) -> None:
    policy = tmp_path / "policy.yaml"
    shadow = tmp_path / "shadow_policy.yaml"
    policy.write_text(
        """
api:
  token: test-token
shadow_mode:
  enabled: true
  shadow_policy: shadow_policy.yaml
  log_divergences: true
rules:
  - name: budget_limit
    max_cost_per_call: 10.0
""".strip(),
        encoding="utf-8",
    )
    shadow.write_text(
        """
rules:
  - name: budget_limit
    max_cost_per_call: 0.1
""".strip(),
        encoding="utf-8",
    )
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)
    runner = app.state.shadow_runner
    assert isinstance(runner, ShadowModeRunner)
    runner.engine = lambda req, pol: {"decision": "DENY", "allowed": False}
    runner.shadow_evaluate({"request_id": "req-1"}, {"decision": "ALLOW", "allowed": True})
    div = client.get("/api/v1/shadow/divergences", headers={"Authorization": "Bearer test-token"})
    assert div.status_code == 200
    payload = div.json()
    assert payload["enabled"] is True
    assert payload["report"]["divergences"] >= 1
