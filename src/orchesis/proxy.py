"""FastAPI proxy layer using Orchesis rule engine."""

import os
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from orchesis.config import load_policy
from orchesis.engine import evaluate


def _extract_tool(request: Request, body_json: dict[str, Any] | None) -> str:
    if body_json and isinstance(body_json.get("tool"), str):
        return body_json["tool"]

    first_segment = request.url.path.strip("/").split("/", maxsplit=1)[0]
    suffix = first_segment or "root"
    return f"{request.method.lower()}_{suffix}"


def _extract_params(request: Request, body_json: dict[str, Any] | None) -> dict[str, Any]:
    params: dict[str, Any] = {}

    if body_json and isinstance(body_json.get("params"), dict):
        params.update(body_json["params"])
    elif body_json and isinstance(body_json.get("query"), str):
        params["query"] = body_json["query"]

    if request.url.path.startswith("/files/"):
        raw_path = request.url.path.removeprefix("/files/")
        params["path"] = f"/{raw_path}" if raw_path else "/"

    return params


def _extract_cost(request: Request, body_json: dict[str, Any] | None) -> float:
    header_cost = request.headers.get("x-cost")
    if header_cost is not None:
        try:
            return float(header_cost)
        except ValueError:
            return 0.0

    if body_json and isinstance(body_json.get("cost"), int | float):
        return float(body_json["cost"])

    return 0.0


def create_proxy_app(
    policy: dict[str, Any],
    *,
    backend_url: str = "http://backend",
    backend_app: FastAPI | None = None,
    backend_transport: httpx.AsyncBaseTransport | None = None,
) -> FastAPI:
    """Create a proxy app that evaluates rules before forwarding requests."""
    app = FastAPI(title="Orchesis Proxy")

    transport = backend_transport
    if transport is None and backend_app is not None:
        transport = httpx.ASGITransport(app=backend_app)

    @app.middleware("http")
    async def decision_middleware(request: Request, call_next: Any) -> Response:
        _ = call_next
        raw_body = await request.body()
        body_json: dict[str, Any] | None = None
        if raw_body:
            try:
                parsed = await request.json()
                if isinstance(parsed, dict):
                    body_json = parsed
            except ValueError:
                body_json = None

        eval_request = {
            "tool": _extract_tool(request, body_json),
            "params": _extract_params(request, body_json),
            "cost": _extract_cost(request, body_json),
            "context": {"method": request.method, "path": request.url.path},
        }
        decision = evaluate(eval_request, policy)

        if not decision.allowed:
            return JSONResponse(
                status_code=403,
                content={
                    "allowed": False,
                    "reasons": decision.reasons,
                    "rules_checked": decision.rules_checked,
                },
            )

        target_path = request.url.path
        if request.url.query:
            target_path = f"{target_path}?{request.url.query}"

        forwarded_headers = {
            key: value for key, value in request.headers.items() if key.lower() != "host"
        }

        async with httpx.AsyncClient(
            base_url=backend_url,
            transport=transport,
            timeout=10.0,
        ) as client:
            forwarded = await client.request(
                method=request.method,
                url=target_path,
                content=raw_body,
                headers=forwarded_headers,
            )

        return Response(
            content=forwarded.content,
            status_code=forwarded.status_code,
            media_type=forwarded.headers.get("content-type"),
        )

    return app


def _default_policy_path() -> str:
    project_root = __file__
    # src/orchesis/proxy.py -> project root
    for _ in range(3):
        project_root = os.path.dirname(project_root)
    return os.path.join(project_root, "examples", "policy.yaml")


def build_app_from_env() -> FastAPI:
    """Create proxy app configured from environment variables."""
    policy_path = os.getenv("POLICY_PATH", _default_policy_path())
    backend_url = os.getenv("BACKEND_URL", "http://127.0.0.1:8081")
    policy = load_policy(policy_path)
    return create_proxy_app(policy=policy, backend_url=backend_url)


app = build_app_from_env()
