"""Python SDK client for Orchesis Control API."""

from __future__ import annotations

import inspect
from dataclasses import dataclass
from functools import wraps
from typing import Any

import httpx


@dataclass
class EvaluateResult:
    allowed: bool
    reasons: list[str]
    rules_checked: list[str]
    evaluation_us: int
    policy_version: str

    def __bool__(self) -> bool:
        return self.allowed


class OrchesisDenied(Exception):
    """Raised when Orchesis denies a tool call."""

    def __init__(self, reasons: list[str], tool: str):
        self.reasons = reasons
        self.tool = tool
        super().__init__(f"Orchesis denied '{tool}': {', '.join(reasons)}")


class OrchesisClient:
    """Python client for Orchesis Control API."""

    def __init__(
        self,
        base_url: str = "http://localhost:8080",
        api_token: str | None = None,
        timeout: float = 5.0,
    ):
        self._base_url = base_url.rstrip("/")
        self._token = api_token
        self._timeout = timeout

    def evaluate(
        self,
        tool: str,
        params: dict[str, Any] | None = None,
        cost: float = 0.0,
        agent_id: str | None = None,
        session_id: str | None = None,
    ) -> EvaluateResult:
        payload: dict[str, Any] = {"tool": tool, "params": params or {}, "cost": float(cost)}
        context: dict[str, Any] = {}
        if agent_id:
            context["agent"] = agent_id
        if session_id:
            context["session"] = session_id
        if context:
            payload["context"] = context
        response = self._request("POST", "/api/v1/evaluate", json=payload, auth_required=True)
        return EvaluateResult(
            allowed=bool(response.get("allowed", False)),
            reasons=list(response.get("reasons", [])),
            rules_checked=list(response.get("rules_checked", [])),
            evaluation_us=int(response.get("evaluation_us", 0)),
            policy_version=str(response.get("policy_version", "")),
        )

    def is_allowed(self, tool: str, **kwargs) -> bool:
        return bool(self.evaluate(tool, **kwargs))

    def get_policy(self) -> dict[str, Any]:
        return self._request("GET", "/api/v1/policy", auth_required=True)

    def update_policy(self, yaml_content: str) -> dict[str, Any]:
        return self._request(
            "POST",
            "/api/v1/policy",
            json={"yaml_content": yaml_content},
            auth_required=True,
        )

    def validate_policy(self, yaml_content: str) -> dict[str, Any]:
        return self._request(
            "POST",
            "/api/v1/policy/validate",
            json={"yaml_content": yaml_content},
            auth_required=True,
        )

    def rollback_policy(self) -> dict[str, Any]:
        return self._request("POST", "/api/v1/policy/rollback", auth_required=True)

    def policy_history(self) -> list[dict[str, Any]]:
        response = self._request("GET", "/api/v1/policy/history", auth_required=True)
        items = response.get("versions", [])
        return items if isinstance(items, list) else []

    def list_agents(self) -> list[dict[str, Any]]:
        response = self._request("GET", "/api/v1/agents", auth_required=True)
        items = response.get("agents", [])
        return items if isinstance(items, list) else []

    def get_agent(self, agent_id: str) -> dict[str, Any]:
        return self._request("GET", f"/api/v1/agents/{agent_id}", auth_required=True)

    def set_agent_tier(self, agent_id: str, tier: str) -> dict[str, Any]:
        return self._request(
            "PUT",
            f"/api/v1/agents/{agent_id}/tier",
            json={"trust_tier": tier},
            auth_required=True,
        )

    def status(self) -> dict[str, Any]:
        return self._request("GET", "/api/v1/status", auth_required=False)

    def health(self) -> dict[str, Any]:
        try:
            return self._request("GET", "/health", auth_required=False)
        except RuntimeError:
            return self.status()

    def audit_stats(self, **filters) -> dict[str, Any]:
        return self._request("GET", "/api/v1/audit/stats", params=filters, auth_required=True)

    def anomalies(self) -> list[dict[str, Any]]:
        response = self._request("GET", "/api/v1/audit/anomalies", auth_required=True)
        items = response.get("anomalies", [])
        return items if isinstance(items, list) else []

    def reliability_report(self) -> dict[str, Any]:
        return self._request("GET", "/api/v1/reliability", auth_required=True)

    def _request(
        self,
        method: str,
        path: str,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        auth_required: bool = True,
    ) -> dict[str, Any]:
        headers: dict[str, str] = {"Accept": "application/json"}
        if auth_required:
            if not self._token:
                raise RuntimeError("API token is required for this endpoint")
            headers["Authorization"] = f"Bearer {self._token}"
        url = f"{self._base_url}{path}"
        try:
            response = httpx.request(
                method=method,
                url=url,
                json=json,
                params=params,
                headers=headers,
                timeout=self._timeout,
            )
        except httpx.RequestError as error:
            raise ConnectionError(f"Failed to connect to Orchesis API at {url}") from error
        if response.status_code >= 400:
            detail: str
            try:
                payload = response.json()
            except ValueError:
                payload = {"error": response.text}
            detail = str(payload)
            raise RuntimeError(f"Orchesis API error {response.status_code}: {detail}")
        try:
            data = response.json()
        except ValueError:
            return {}
        return data if isinstance(data, dict) else {}


def orchesis_guard(client: OrchesisClient, tool: str, agent_id: str | None = None):
    """Decorator that enforces Orchesis policy on a function."""

    def _decorator(func):
        signature = inspect.signature(func)

        @wraps(func)
        def _wrapped(*args, **kwargs):
            bound = signature.bind_partial(*args, **kwargs)
            bound.apply_defaults()
            params = {
                key: value for key, value in bound.arguments.items() if key not in {"self", "cls"}
            }
            result = client.evaluate(tool=tool, params=params, agent_id=agent_id)
            if not result.allowed:
                raise OrchesisDenied(result.reasons, tool)
            return func(*args, **kwargs)

        return _wrapped

    return _decorator
