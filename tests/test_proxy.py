from fastapi.testclient import TestClient

from orchesis.demo_backend import app
from orchesis.proxy import app as proxy_module_app
from orchesis.proxy import build_app_from_env, create_proxy_app


def test_demo_backend_get_data() -> None:
    client = TestClient(app)

    response = client.get("/data")

    assert response.status_code == 200
    assert response.json() == {"items": ["report.csv", "data.json"]}


def test_demo_backend_post_execute() -> None:
    client = TestClient(app)

    response = client.post(
        "/execute",
        json={"action": "run_sql", "params": {"query": "SELECT 1"}},
    )

    assert response.status_code == 200
    assert response.json() == {"status": "done"}


def test_demo_backend_delete_files_path() -> None:
    client = TestClient(app)

    response = client.delete("/files/tmp/a/b/report.csv")

    assert response.status_code == 200
    assert response.json() == {"deleted": True}


def test_proxy_allows_and_forwards_get_data() -> None:
    proxy_app = create_proxy_app(
        policy={"rules": [{"name": "budget_limit", "max_cost_per_call": 1.0}]},
        backend_app=app,
    )
    proxy_client = TestClient(proxy_app)

    response = proxy_client.get("/data")

    assert response.status_code == 200
    assert response.json() == {"items": ["report.csv", "data.json"]}
    assert response.headers.get("X-Orchesis-Decision") == "ALLOW"
    assert response.headers.get("X-Orchesis-Trace-Id")


def test_proxy_denies_and_does_not_forward_delete_when_path_blocked() -> None:
    state = {"delete_calls": 0}

    from fastapi import FastAPI

    backend = FastAPI()

    @backend.delete("/files/{path:path}")
    def delete_file(path: str) -> dict[str, bool]:
        _ = path
        state["delete_calls"] += 1
        return {"deleted": True}

    proxy_app = create_proxy_app(
        policy={"rules": [{"name": "file_access", "denied_paths": ["/etc"]}]},
        backend_app=backend,
    )
    proxy_client = TestClient(proxy_app)

    response = proxy_client.delete("/files/etc/passwd")

    assert response.status_code == 403
    assert response.json()["allowed"] is False
    assert response.headers.get("X-Orchesis-Decision") == "DENY"
    assert response.headers.get("X-Orchesis-Trace-Id")
    assert state["delete_calls"] == 0


def test_proxy_denies_post_execute_with_drop_query() -> None:
    proxy_app = create_proxy_app(
        policy={"rules": [{"name": "sql_restriction", "denied_operations": ["DROP"]}]},
        backend_app=app,
    )
    proxy_client = TestClient(proxy_app)

    response = proxy_client.post(
        "/execute",
        json={"action": "run_sql", "params": {"query": "DROP TABLE users"}},
    )

    assert response.status_code == 403
    assert "sql_restriction: DROP is denied" in response.json()["reasons"]


def test_proxy_budget_limit_uses_x_cost_header() -> None:
    proxy_app = create_proxy_app(
        policy={"rules": [{"name": "budget_limit", "max_cost_per_call": 0.5}]},
        backend_app=app,
    )
    proxy_client = TestClient(proxy_app)

    response = proxy_client.get("/data", headers={"x-cost": "0.9"})

    assert response.status_code == 403
    assert response.json()["allowed"] is False


def test_proxy_module_exports_default_app() -> None:
    assert proxy_module_app is not None


def test_build_app_from_env_uses_policy_path(monkeypatch, tmp_path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
rules:
  - name: file_access
    denied_paths:
      - "/etc"
""".strip(),
        encoding="utf-8",
    )
    monkeypatch.setenv("POLICY_PATH", str(policy_path))
    monkeypatch.setenv("BACKEND_URL", "http://backend:8081")

    env_proxy_app = build_app_from_env()
    client = TestClient(env_proxy_app)

    response = client.delete("/files/etc/passwd")

    assert response.status_code == 403
    assert "file_access: path '/etc/passwd' is denied by '/etc'" in response.json()["reasons"]
