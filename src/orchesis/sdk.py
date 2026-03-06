"""Orchesis Python SDK — programmatic access to the proxy API."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SDKConfig:
    """SDK configuration."""

    base_url: str = "http://localhost:8080"
    timeout: float = 30.0
    headers: dict[str, str] = field(default_factory=dict)
    api_key: str = ""


class OrchesisError(Exception):
    """Base exception for SDK errors."""

    def __init__(self, message: str, status_code: int = 0, response: Any = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response = response


class NotFoundError(OrchesisError):
    """Resource not found (404)."""

    pass


class ServerError(OrchesisError):
    """Proxy server error (5xx)."""

    pass


class OrchesisClient:
    """
    Python client for Orchesis proxy API.

    Usage:
        client = OrchesisClient("http://localhost:8080")

        # Stats
        stats = client.get_stats()
        print(stats["total_requests"])

        # Experiments
        exp = client.create_experiment("Sonnet vs Opus", [
            {"name": "sonnet", "weight": 0.5, "model_override": "claude-sonnet-4-20250514"},
            {"name": "opus", "weight": 0.5, "model_override": "claude-opus-4-20250514"},
        ])
        client.start_experiment(exp["experiment_id"])
        results = client.get_experiment_results(exp["experiment_id"])

        # Flow X-Ray
        sessions = client.list_flow_sessions()
        analysis = client.analyze_flow(sessions[0]["session_id"])

        # Task tracking
        outcomes = client.get_task_outcomes()
        correlations = client.get_task_correlations()

    Thread-safe (stateless HTTP calls). Zero dependencies (stdlib urllib).
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8080",
        timeout: float = 30.0,
        api_key: str = "",
        headers: dict[str, str] | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._api_key = api_key
        self._headers = dict(headers or {})
        if api_key:
            self._headers["Authorization"] = f"Bearer {api_key}"

    # --- HTTP helpers ---

    def _request(
        self,
        method: str,
        path: str,
        body: dict | None = None,
        params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """
        Make HTTP request to proxy API.
        Returns parsed JSON response.
        Raises OrchesisError on failure.
        """
        url = f"{self._base_url}{path}"
        if params:
            query = "&".join(f"{k}={v}" for k, v in params.items())
            url = f"{url}?{query}"

        data = None
        if body is not None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            **self._headers,
        }

        req = urllib.request.Request(url, data=data, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                content = resp.read().decode("utf-8")
                if not content.strip():
                    return {}
                return json.loads(content)
        except urllib.error.HTTPError as e:
            body_text = ""
            try:
                body_text = e.read().decode("utf-8")
            except Exception:
                pass
            response = None
            try:
                response = json.loads(body_text)
            except Exception:
                response = {"error": body_text}

            if e.code == 404:
                raise NotFoundError(f"Not found: {path}", status_code=404, response=response) from e
            if e.code >= 500:
                raise ServerError(
                    f"Server error: {e.code}", status_code=e.code, response=response
                ) from e
            raise OrchesisError(
                f"HTTP {e.code}: {path}", status_code=e.code, response=response
            ) from e
        except urllib.error.URLError as e:
            raise OrchesisError(f"Connection failed: {e.reason}") from e
        except OSError as e:
            raise OrchesisError(f"Connection failed: {e}") from e

    def _get(self, path: str, **params: str) -> dict[str, Any]:
        return self._request("GET", path, params=params if params else None)

    def _post(self, path: str, body: dict | None = None) -> dict[str, Any]:
        return self._request("POST", path, body=body)

    def _delete(self, path: str) -> dict[str, Any]:
        return self._request("DELETE", path)

    # =========================================
    # Stats & Health
    # =========================================

    def get_stats(self) -> dict[str, Any]:
        """Get full proxy statistics."""
        return self._get("/stats")

    def is_healthy(self) -> bool:
        """Check if proxy is responding."""
        try:
            self._get("/stats")
            return True
        except OrchesisError:
            return False

    def get_dashboard_overview(self) -> dict[str, Any]:
        """Get dashboard overview metrics."""
        return self._get("/api/dashboard/overview")

    # =========================================
    # Sessions (Time Machine)
    # =========================================

    def list_sessions(self) -> list[dict[str, Any]]:
        """List all recorded sessions."""
        result = self._get("/api/sessions")
        return result.get("sessions", []) if isinstance(result, dict) else []

    def get_session(self, session_id: str) -> dict[str, Any]:
        """Get session summary."""
        result = self._get(f"/api/sessions/{session_id}")
        return result.get("session", result)

    def delete_session(self, session_id: str) -> dict[str, Any]:
        """Delete a recorded session."""
        return self._delete(f"/sessions/{session_id}")

    def export_session(self, session_id: str) -> dict[str, Any]:
        """Export session as AIR document."""
        return self._get(f"/api/sessions/{session_id}/export")

    # =========================================
    # Agent DNA
    # =========================================

    def list_agents(self) -> list[dict[str, Any]]:
        """Get agent DNA profiles."""
        result = self._get("/api/dashboard/agents")
        return result.get("agents", []) if isinstance(result, dict) else []

    # =========================================
    # Flow X-Ray
    # =========================================

    def list_flow_sessions(self) -> list[dict[str, Any]]:
        """List sessions with flow data."""
        result = self._get("/api/flow/sessions")
        return result.get("sessions", []) if isinstance(result, dict) else []

    def analyze_flow(self, session_id: str) -> dict[str, Any]:
        """Get full flow analysis for a session."""
        return self._get(f"/api/flow/analyze/{session_id}")

    def get_flow_graph(self, session_id: str) -> dict[str, Any]:
        """Get raw flow graph JSON for visualization."""
        return self._get(f"/api/flow/graph/{session_id}")

    def get_flow_patterns(self) -> dict[str, Any]:
        """Get aggregate pattern stats across all sessions."""
        return self._get("/api/flow/patterns")

    # =========================================
    # Experiments (A/B Testing)
    # =========================================

    def list_experiments(self) -> list[dict[str, Any]]:
        """List all experiments."""
        result = self._get("/api/experiments")
        return result.get("experiments", []) if isinstance(result, dict) else []

    def create_experiment(
        self,
        name: str,
        variants: list[dict[str, Any]],
        split_strategy: str = "sticky_session",
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Create a new A/B experiment.

        Args:
            name: Human-readable experiment name
            variants: List of variant dicts, e.g.:
                [{"name": "control", "weight": 0.5},
                 {"name": "sonnet", "weight": 0.5, "model_override": "claude-sonnet-4-20250514"}]
            split_strategy: "random", "sticky_session", "sticky_agent", "round_robin"
            **kwargs: target_models, target_agents, max_requests, max_duration_seconds, etc.

        Returns:
            Created experiment dict with experiment_id.
        """
        body = {
            "name": name,
            "variants": variants,
            "split_strategy": split_strategy,
            **kwargs,
        }
        return self._post("/api/experiments", body=body)

    def start_experiment(self, experiment_id: str) -> dict[str, Any]:
        """Start an experiment (begin traffic splitting)."""
        return self._post(f"/api/experiments/{experiment_id}/start")

    def stop_experiment(self, experiment_id: str) -> dict[str, Any]:
        """Stop experiment and get final results."""
        return self._post(f"/api/experiments/{experiment_id}/stop")

    def pause_experiment(self, experiment_id: str) -> dict[str, Any]:
        """Pause a running experiment."""
        return self._post(f"/api/experiments/{experiment_id}/pause")

    def resume_experiment(self, experiment_id: str) -> dict[str, Any]:
        """Resume a paused experiment."""
        return self._post(f"/api/experiments/{experiment_id}/resume")

    def get_experiment_results(self, experiment_id: str) -> dict[str, Any]:
        """Get current experiment results (can call while running)."""
        return self._get(f"/api/experiments/{experiment_id}/results")

    def get_experiment_live(self, experiment_id: str) -> dict[str, Any]:
        """Get real-time experiment stats."""
        return self._get(f"/api/experiments/{experiment_id}/live")

    # =========================================
    # Task Tracking
    # =========================================

    def get_task_outcomes(self) -> dict[str, Any]:
        """Get task outcome distribution (success, failure, loop, etc)."""
        return self._get("/api/tasks/outcomes")

    def get_task_correlations(self) -> dict[str, Any]:
        """Get task correlations (success rate by model, tool count, turns)."""
        return self._get("/api/tasks/correlations")

    # =========================================
    # Compliance
    # =========================================

    def get_compliance_summary(self) -> dict[str, Any]:
        """Get compliance summary across all frameworks."""
        return self._get("/api/compliance/summary")

    def get_compliance_coverage(self, framework: str = "") -> dict[str, Any]:
        """Get compliance coverage matrix, optionally for specific framework."""
        if framework:
            return self._get(f"/api/compliance/coverage/{framework}")
        return self._get("/api/compliance/coverage")

    def get_compliance_findings(self) -> list[dict[str, Any]]:
        """Get compliance findings list."""
        result = self._get("/api/compliance/findings")
        return result.get("findings", []) if isinstance(result, dict) else []

    # =========================================
    # Context manager
    # =========================================

    def __enter__(self) -> OrchesisClient:
        return self

    def __exit__(self, *args: Any) -> None:
        pass

    def __repr__(self) -> str:
        return f"OrchesisClient(base_url={self._base_url!r})"
