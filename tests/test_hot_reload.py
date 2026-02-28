from __future__ import annotations

from fastapi.testclient import TestClient

from orchesis.config import PolicyWatcher, load_policy
from orchesis.demo_backend import app as backend_app
from orchesis.proxy import create_proxy_app


def test_policy_watcher_detects_change(tmp_path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        "rules:\n  - name: budget_limit\n    max_cost_per_call: 1.0\n", encoding="utf-8"
    )

    reloaded: list[dict] = []
    watcher = PolicyWatcher(str(policy_path), lambda p: reloaded.append(p))

    assert watcher.check() is True
    assert len(reloaded) == 1

    policy_path.write_text(
        "rules:\n  - name: budget_limit\n    max_cost_per_call: 2.0\n", encoding="utf-8"
    )
    assert watcher.check() is True
    assert len(reloaded) == 2


def test_policy_watcher_no_false_reload(tmp_path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        "rules:\n  - name: budget_limit\n    max_cost_per_call: 1.0\n", encoding="utf-8"
    )

    calls = {"count": 0}
    watcher = PolicyWatcher(
        str(policy_path), lambda _: calls.__setitem__("count", calls["count"] + 1)
    )
    assert watcher.check() is True
    assert watcher.check() is False
    assert calls["count"] == 1


def test_proxy_reloads_policy_on_file_change(tmp_path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        "rules:\n  - name: budget_limit\n    max_cost_per_call: 1.0\n", encoding="utf-8"
    )
    proxy_app = create_proxy_app(
        policy=load_policy(policy_path),
        policy_path=str(policy_path),
        backend_app=backend_app,
    )
    client = TestClient(proxy_app)

    first = client.get("/data", headers={"x-cost": "0.5"})
    assert first.status_code == 200

    policy_path.write_text(
        "rules:\n  - name: budget_limit\n    max_cost_per_call: 0.1\n", encoding="utf-8"
    )
    second = client.get("/data", headers={"x-cost": "0.5"})
    assert second.status_code == 403


def test_hot_reload_does_not_reset_state(tmp_path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        "rules:\n  - name: rate_limit\n    max_requests_per_minute: 1\n", encoding="utf-8"
    )
    proxy_app = create_proxy_app(
        policy=load_policy(policy_path),
        policy_path=str(policy_path),
        backend_app=backend_app,
    )
    client = TestClient(proxy_app)

    first = client.get("/data")
    assert first.status_code == 200

    policy_path.write_text(
        "rules:\n  - name: rate_limit\n    max_requests_per_minute: 1\n  - name: budget_limit\n    max_cost_per_call: 1.0\n",
        encoding="utf-8",
    )
    second = client.get("/data")
    assert second.status_code == 403
    assert any("rate_limit" in reason for reason in second.json().get("reasons", []))
