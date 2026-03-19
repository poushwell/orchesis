from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.kolmogorov_importance import KolmogorovImportance


def _high_entropy_text(n: int = 4000) -> str:
    alphabet = [chr(code) for code in range(33, 127)]
    return "".join(alphabet[(i * 37 + 11) % len(alphabet)] for i in range(n))


def test_k_estimate_high_entropy() -> None:
    scorer = KolmogorovImportance()
    high = scorer.estimate_k(_high_entropy_text())
    low = scorer.estimate_k("a" * 4000)
    assert high > low


def test_k_estimate_low_entropy() -> None:
    scorer = KolmogorovImportance()
    low = scorer.estimate_k("a" * 4000)
    assert low < 0.5


def test_importance_computed() -> None:
    scorer = KolmogorovImportance()
    payload = scorer.compute_importance({"role": "assistant", "content": "This is a test message."})
    assert "k_score" in payload
    assert "importance" in payload
    assert 0.0 <= payload["importance"] <= 1.0


def test_role_weight_applied() -> None:
    scorer = KolmogorovImportance()
    content = _high_entropy_text(1000)
    user = scorer.compute_importance({"role": "user", "content": content})
    system = scorer.compute_importance({"role": "system", "content": content})
    assert system["importance"] >= user["importance"]


def test_correlation_recorded() -> None:
    scorer = KolmogorovImportance()
    scorer.record_correlation(0.8, 0.7, "DENY")
    scorer.record_correlation(0.4, 0.3, "ALLOW")
    stats = scorer.get_stats()
    assert stats["measurements"] == 2


def test_rho_computed() -> None:
    scorer = KolmogorovImportance()
    scorer.record_correlation(0.1, 0.2, "ALLOW")
    scorer.record_correlation(0.2, 0.4, "ALLOW")
    scorer.record_correlation(0.3, 0.6, "DENY")
    rho = scorer.compute_rho()
    assert rho > 0.9


def test_deny_higher_k_than_allow() -> None:
    scorer = KolmogorovImportance()
    allow_k = scorer.estimate_k("aaaaaaaaaaaaaaaaaaaaaaaa" * 30)
    deny_k = scorer.estimate_k(_high_entropy_text(2400))
    scorer.record_correlation(allow_k, 0.2, "ALLOW")
    scorer.record_correlation(deny_k, 0.8, "DENY")
    assert deny_k > allow_k


def test_api_estimate_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)
    response = client.post(
        "/api/v1/kolmogorov/estimate",
        json={"message": {"role": "system", "content": _high_entropy_text(600)}},
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert "k_score" in payload
    assert "importance" in payload


def test_stats_returned() -> None:
    scorer = KolmogorovImportance()
    scorer.record_correlation(0.1, 0.3, "ALLOW")
    scorer.record_correlation(0.2, 0.5, "DENY")
    scorer.record_correlation(0.4, 0.9, "DENY")
    stats = scorer.get_stats()
    assert "measurements" in stats
    assert "rho" in stats
    assert "rho_significant" in stats
