"""Governance control-plane HTTP API."""

from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse

from orchesis.audit import AuditEngine, AuditQuery
from orchesis.config import load_policy, validate_policy, validate_policy_warnings
from orchesis.corpus import RegressionCorpus
from orchesis.engine import evaluate
from orchesis.events import EventBus
from orchesis.metrics import MetricsCollector
from orchesis.policy_store import PolicyStore
from orchesis.state import RateLimitTracker
from orchesis.telemetry import JsonlEmitter


def create_api_app(
    policy_path: str = "policy.yaml",
    state_persist: str = ".orchesis/state.jsonl",
    decisions_log: str = ".orchesis/decisions.jsonl",
    history_path: str = ".orchesis/policy_versions.jsonl",
) -> FastAPI:
    """Create governance control-plane API."""
    app = FastAPI(title="Orchesis Control API")
    @app.exception_handler(HTTPException)
    async def _http_error_handler(request, exc: HTTPException):  # noqa: ANN001
        _ = request
        if exc.status_code == 401:
            return JSONResponse(status_code=401, content={"error": "unauthorized"})
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    started_at = time.perf_counter()
    policy_file = Path(policy_path)
    policy_file.parent.mkdir(parents=True, exist_ok=True)

    if not policy_file.exists():
        policy_file.write_text("rules: []\n", encoding="utf-8")

    store = PolicyStore(history_path=history_path)
    current_version = store.load(str(policy_file))
    tracker = RateLimitTracker(persist_path=state_persist)
    event_bus = EventBus()
    metrics = MetricsCollector()
    _ = event_bus.subscribe(JsonlEmitter(decisions_log))
    _ = event_bus.subscribe(metrics)
    corpus = RegressionCorpus()

    app.state.store = store
    app.state.tracker = tracker
    app.state.event_bus = event_bus
    app.state.metrics = metrics
    app.state.corpus = corpus
    app.state.policy_path = str(policy_file)
    app.state.decisions_log = decisions_log
    app.state.current_version = current_version

    def _refresh_current_version() -> None:
        app.state.current_version = store.current or store.load(str(policy_file))

    def _auth_token_from_policy() -> str | None:
        policy = app.state.current_version.policy
        api_config = policy.get("api")
        if isinstance(api_config, dict):
            token = api_config.get("token")
            if isinstance(token, str) and token:
                return token
        return None

    def _required_token() -> str | None:
        return os.getenv("API_TOKEN") or _auth_token_from_policy()

    def _require_auth(authorization: str | None) -> None:
        expected = _required_token()
        if expected is None:
            raise HTTPException(status_code=401, detail={"error": "unauthorized"})
        if not isinstance(authorization, str) or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail={"error": "unauthorized"})
        provided = authorization.split(" ", 1)[1].strip()
        if provided != expected:
            raise HTTPException(status_code=401, detail={"error": "unauthorized"})

    def _audit_engine() -> AuditEngine:
        return AuditEngine(app.state.decisions_log)

    @app.post("/api/v1/policy")
    def post_policy(
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        yaml_content = body.get("yaml_content")
        if not isinstance(yaml_content, str):
            raise HTTPException(status_code=400, detail={"error": "yaml_content is required"})
        policy_file.write_text(yaml_content, encoding="utf-8")
        try:
            loaded = load_policy(policy_file)
        except ValueError as error:
            raise HTTPException(status_code=400, detail={"error": str(error)}) from error
        errors = validate_policy(loaded)
        if errors:
            raise HTTPException(status_code=400, detail={"errors": errors})
        version = store.load(str(policy_file))
        _refresh_current_version()
        return {"version_id": version.version_id, "loaded_at": version.loaded_at}

    @app.get("/api/v1/policy")
    def get_policy(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        _refresh_current_version()
        current = app.state.current_version
        yaml_content = policy_file.read_text(encoding="utf-8")
        return {
            "version_id": current.version_id,
            "yaml_content": yaml_content,
            "loaded_at": current.loaded_at,
            "agents_count": len(current.registry.agents),
        }

    @app.get("/api/v1/policy/history")
    def policy_history(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        _refresh_current_version()
        current = app.state.current_version
        versions = [
            {
                "version_id": version.version_id,
                "loaded_at": version.loaded_at,
                "active": version.version_id == current.version_id,
            }
            for version in store.history()
        ]
        return {"versions": versions}

    @app.post("/api/v1/policy/rollback")
    def policy_rollback(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        _refresh_current_version()
        previous = app.state.current_version.version_id
        rolled = store.rollback()
        if rolled is None:
            raise HTTPException(status_code=400, detail={"error": "rollback unavailable"})
        _refresh_current_version()
        # Materialize rolled version as active file content for local consumers.
        policy_file.write_text(
            yaml.safe_dump(rolled.policy, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )
        return {"rolled_back_to": rolled.version_id, "previous": previous}

    @app.post("/api/v1/policy/validate")
    def policy_validate(
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        yaml_content = body.get("yaml_content")
        if not isinstance(yaml_content, str):
            raise HTTPException(status_code=400, detail={"error": "yaml_content is required"})
        tmp_path = policy_file.parent / ".tmp_validate_policy.yaml"
        tmp_path.write_text(yaml_content, encoding="utf-8")
        try:
            loaded = load_policy(tmp_path)
        except ValueError as error:
            return {"valid": False, "errors": [str(error)], "warnings": []}
        finally:
            if tmp_path.exists():
                tmp_path.unlink()
        errors = validate_policy(loaded)
        warnings = validate_policy_warnings(loaded)
        return {"valid": len(errors) == 0, "errors": errors, "warnings": warnings}

    @app.get("/api/v1/agents")
    def get_agents(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        _refresh_current_version()
        registry = app.state.current_version.registry
        agents = []
        for agent_id in sorted(registry.agents):
            identity = registry.agents[agent_id]
            agents.append(
                {
                    "id": identity.agent_id,
                    "name": identity.name,
                    "trust_tier": identity.trust_tier.name.lower(),
                    "allowed_tools": identity.allowed_tools,
                    "denied_tools": identity.denied_tools,
                    "max_cost_per_call": identity.max_cost_per_call,
                    "daily_budget": identity.daily_budget,
                    "rate_limit_per_minute": identity.rate_limit_per_minute,
                }
            )
        return {"agents": agents, "default_tier": registry.default_tier.name.lower()}

    @app.get("/api/v1/agents/{agent_id}")
    def get_agent(agent_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        _refresh_current_version()
        identity = app.state.current_version.registry.get(agent_id)
        audit = _audit_engine()
        events = audit.query(AuditQuery(agent_id=agent_id, limit=10_000))
        total = len(events)
        deny = sum(1 for event in events if event.decision == "DENY")
        deny_rate = (deny / total) if total else 0.0
        last_seen = events[0].timestamp if events else None
        return {
            "id": identity.agent_id,
            "name": identity.name,
            "trust_tier": identity.trust_tier.name.lower(),
            "stats": {
                "total_decisions": total,
                "deny_rate": deny_rate,
                "last_seen": last_seen,
            },
        }

    @app.put("/api/v1/agents/{agent_id}/tier")
    def update_agent_tier(
        agent_id: str,
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        trust_tier = body.get("trust_tier")
        if not isinstance(trust_tier, str):
            raise HTTPException(status_code=400, detail={"error": "trust_tier is required"})
        tier_name = trust_tier.strip().lower()
        _refresh_current_version()
        policy = dict(app.state.current_version.policy)
        agents = policy.get("agents")
        if not isinstance(agents, list):
            raise HTTPException(status_code=404, detail={"error": "agent not found"})
        previous_tier: str | None = None
        found = False
        for item in agents:
            if not isinstance(item, dict):
                continue
            if item.get("id") == agent_id:
                prev = item.get("trust_tier")
                previous_tier = prev if isinstance(prev, str) else "intern"
                item["trust_tier"] = tier_name
                found = True
                break
        if not found:
            raise HTTPException(status_code=404, detail={"error": "agent not found"})

        policy_file.write_text(yaml.safe_dump(policy, sort_keys=False, allow_unicode=True), encoding="utf-8")
        version = store.load(str(policy_file))
        _refresh_current_version()
        return {
            "agent_id": agent_id,
            "previous_tier": previous_tier,
            "new_tier": tier_name,
            "policy_version": version.version_id,
        }

    @app.get("/api/v1/status")
    def status() -> dict[str, Any]:
        _refresh_current_version()
        audit = _audit_engine()
        stats_1h = audit.stats(AuditQuery(since_hours=1, limit=1_000_000))
        anomalies = audit.anomalies()
        snapshot = metrics.snapshot()
        counters = snapshot.get("counters", {})
        total_decisions = sum(
            value
            for key, value in counters.items()
            if isinstance(key, str)
            and key.startswith("orchesis_decisions_total|decision=")
            and isinstance(value, int)
        )
        corpus_stats = corpus.stats()
        return {
            "version": "0.3.1",
            "uptime_seconds": int(max(0.0, time.perf_counter() - started_at)),
            "policy_version": app.state.current_version.version_id,
            "total_decisions": total_decisions,
            "decisions_per_minute": stats_1h.events_per_minute,
            "active_agents": stats_1h.unique_agents,
            "deny_rate_1h": stats_1h.deny_rate,
            "anomaly_count_1h": len(anomalies),
            "subscriber_count": event_bus.subscriber_count,
            "corpus_size": corpus_stats["total"],
        }

    @app.get("/api/v1/audit/stats")
    def audit_stats(
        agent_id: str | None = None,
        since_hours: float | None = None,
        tool: str | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        audit = _audit_engine()
        stats = audit.stats(
            AuditQuery(agent_id=agent_id, tool=tool, since_hours=since_hours, limit=1_000_000)
        )
        return {
            "total_events": stats.total_events,
            "allow_count": stats.allow_count,
            "deny_count": stats.deny_count,
            "deny_rate": stats.deny_rate,
            "unique_agents": stats.unique_agents,
            "unique_tools": stats.unique_tools,
            "unique_sessions": stats.unique_sessions,
            "top_denied_tools": stats.top_denied_tools,
            "top_denied_agents": stats.top_denied_agents,
            "top_deny_reasons": stats.top_deny_reasons,
            "avg_evaluation_us": stats.avg_evaluation_us,
            "p95_evaluation_us": stats.p95_evaluation_us,
            "events_per_minute": stats.events_per_minute,
        }

    @app.get("/api/v1/audit/anomalies")
    def audit_anomalies(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        audit = _audit_engine()
        return {"anomalies": audit.anomalies()}

    @app.get("/api/v1/audit/timeline/{agent_id}")
    def audit_timeline(
        agent_id: str,
        hours: float = 24,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        audit = _audit_engine()
        events = [event.__dict__ for event in audit.timeline(agent_id, hours=hours)]
        return {"agent_id": agent_id, "events": events}

    @app.post("/api/v1/evaluate")
    def evaluate_remote(
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        _refresh_current_version()
        started_ns = time.perf_counter_ns()
        decision = evaluate(
            body,
            app.state.current_version.policy,
            state=tracker,
            emitter=event_bus,
            registry=app.state.current_version.registry,
        )
        elapsed_us = max(0, (time.perf_counter_ns() - started_ns) // 1000)
        return {
            "allowed": decision.allowed,
            "reasons": decision.reasons,
            "rules_checked": decision.rules_checked,
            "evaluation_us": int(elapsed_us),
            "policy_version": app.state.current_version.version_id,
        }

    return app
