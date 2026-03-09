"""Governance control-plane HTTP API."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

import yaml
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from orchesis.auth import AgentAuthenticator, CredentialStore
from orchesis.audit import AuditEngine, AuditQuery
from orchesis.config import load_policy, validate_policy, validate_policy_warnings
from orchesis.corpus import RegressionCorpus
from orchesis.engine import evaluate
from orchesis.events import EventBus
from orchesis.forensics import ForensicsEngine, Incident
from orchesis.integrations import SlackEmitter, SlackNotifier, TelegramEmitter, TelegramNotifier
from orchesis.integrations.forensics_emitter import ForensicsEmitter
from orchesis.metrics import MetricsCollector
from orchesis.otel import OTelEmitter, TraceContext
from orchesis.policy_store import PolicyStore
from orchesis.plugins import load_plugins_for_policy
from orchesis.reliability import ReliabilityReportGenerator
from orchesis.redaction import AuditRedactor
from orchesis.state import RateLimitTracker
from orchesis.structured_log import StructuredLogger
from orchesis.sync import PolicySyncServer
from orchesis.telemetry import JsonlEmitter


def create_api_app(
    policy_path: str = "policy.yaml",
    state_persist: str = ".orchesis/state.jsonl",
    decisions_log: str = ".orchesis/decisions.jsonl",
    history_path: str = ".orchesis/policy_versions.jsonl",
    plugin_modules: list[str] | None = None,
) -> FastAPI:
    """Create governance control-plane API."""
    app = FastAPI(title="Orchesis Control API")
    logger = StructuredLogger("api")

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
    decision_log_subscriber_id: int | None = None
    _ = event_bus.subscribe(metrics)
    _ = event_bus.subscribe(OTelEmitter(".orchesis/traces.jsonl"))
    corpus = RegressionCorpus()
    alert_subscriber_ids: list[int] = []
    alert_notifiers: list[Any] = []

    app.state.store = store
    app.state.tracker = tracker
    app.state.event_bus = event_bus
    app.state.metrics = metrics
    app.state.corpus = corpus
    app.state.policy_path = str(policy_file)
    app.state.decisions_log = decisions_log
    app.state.incidents_log = ".orchesis/incidents.jsonl"
    app.state.current_version = current_version
    app.state.plugin_modules = list(plugin_modules or [])
    app.state.plugins = load_plugins_for_policy(current_version.policy, app.state.plugin_modules)
    app.state.sync_server = PolicySyncServer()
    app.state.sync_server.set_current_version(current_version.version_id)
    app.state.proxy_stats = None
    app.state.authenticator = None
    app.state.auth_mode = "optional"

    def _build_audit_redactor(candidate_policy: dict[str, Any]) -> AuditRedactor | None:
        logging_cfg = candidate_policy.get("logging")
        if not isinstance(logging_cfg, dict):
            return None
        redaction_cfg = logging_cfg.get("redaction")
        if not isinstance(redaction_cfg, dict):
            return None
        if not bool(redaction_cfg.get("enabled", False)):
            return None
        preserve_fields = (
            redaction_cfg.get("preserve_fields")
            if isinstance(redaction_cfg.get("preserve_fields"), list)
            else None
        )
        return AuditRedactor(
            redact_secrets=bool(redaction_cfg.get("redact_secrets", True)),
            redact_pii=bool(redaction_cfg.get("redact_pii", True)),
            preserve_fields=[item for item in preserve_fields if isinstance(item, str)]
            if preserve_fields is not None
            else None,
        )

    def _sync_decision_emitter(candidate_policy: dict[str, Any]) -> None:
        nonlocal decision_log_subscriber_id
        if decision_log_subscriber_id is not None:
            event_bus.unsubscribe(decision_log_subscriber_id)
            decision_log_subscriber_id = None
        redactor = _build_audit_redactor(candidate_policy)
        decision_log_subscriber_id = event_bus.subscribe(JsonlEmitter(decisions_log, redactor=redactor))

    def _incident_alert_callback(incident: Incident) -> None:
        for notifier in list(alert_notifiers):
            try:
                if isinstance(notifier, SlackNotifier):
                    notifier.send(
                        notifier.format_anomaly(
                            {
                                "severity": incident.severity,
                                "detail": f"{incident.title} (agent={incident.agent_id}, tool={incident.tool})",
                            }
                        )
                    )
                elif isinstance(notifier, TelegramNotifier):
                    notifier.send(
                        f"Incident [{incident.severity.upper()}]: {incident.title} "
                        f"(agent={incident.agent_id}, tool={incident.tool})"
                    )
            except Exception:
                continue

    _ = event_bus.subscribe(
        ForensicsEmitter(
            incidents_path=app.state.incidents_log,
            alert_callback=_incident_alert_callback,
        )
    )

    def _sync_alerts(candidate_policy: dict[str, Any]) -> None:
        alert_notifiers.clear()
        for sub_id in alert_subscriber_ids:
            event_bus.unsubscribe(sub_id)
        alert_subscriber_ids.clear()
        alerts = candidate_policy.get("alerts")
        if not isinstance(alerts, dict):
            return
        slack_cfg = alerts.get("slack")
        if isinstance(slack_cfg, dict):
            webhook_url = slack_cfg.get("webhook_url")
            if isinstance(webhook_url, str) and webhook_url.strip():
                notifier = SlackNotifier(
                    webhook_url=webhook_url.strip(),
                    channel=slack_cfg.get("channel") if isinstance(slack_cfg.get("channel"), str) else None,
                    notify_on=slack_cfg.get("notify_on") if isinstance(slack_cfg.get("notify_on"), list) else None,
                )
                alert_notifiers.append(notifier)
                alert_subscriber_ids.append(event_bus.subscribe(SlackEmitter(notifier)))
        telegram_cfg = alerts.get("telegram")
        if isinstance(telegram_cfg, dict):
            bot_token = telegram_cfg.get("bot_token")
            chat_id = telegram_cfg.get("chat_id")
            if (
                isinstance(bot_token, str)
                and bot_token.strip()
                and isinstance(chat_id, str)
                and chat_id.strip()
            ):
                notifier = TelegramNotifier(
                    bot_token=bot_token.strip(),
                    chat_id=chat_id.strip(),
                    notify_on=telegram_cfg.get("notify_on")
                    if isinstance(telegram_cfg.get("notify_on"), list)
                    else None,
                )
                alert_notifiers.append(notifier)
                alert_subscriber_ids.append(event_bus.subscribe(TelegramEmitter(notifier)))

    def _refresh_current_version() -> None:
        app.state.current_version = store.current or store.load(str(policy_file))
        app.state.plugins = load_plugins_for_policy(
            app.state.current_version.policy,
            app.state.plugin_modules,
        )
        _sync_decision_emitter(app.state.current_version.policy)
        app.state.sync_server.set_current_version(app.state.current_version.version_id)
        _sync_alerts(app.state.current_version.policy)
        _sync_auth(app.state.current_version.policy)

    def _sync_auth(candidate_policy: dict[str, Any]) -> None:
        auth = candidate_policy.get("authentication")
        if not isinstance(auth, dict) or not bool(auth.get("enabled", False)):
            app.state.authenticator = None
            app.state.auth_mode = "optional"
            return
        mode = str(auth.get("mode", "enforce")).lower()
        if mode not in {"enforce", "log", "optional"}:
            mode = "enforce"
        skew = auth.get("max_clock_skew", 300)
        credentials_file = auth.get("credentials_file", ".orchesis/credentials.yaml")
        store_obj = CredentialStore(str(credentials_file))
        credentials = store_obj.load()
        app.state.authenticator = AgentAuthenticator(
            credentials=credentials,
            mode=mode,
            max_clock_skew=int(skew) if isinstance(skew, int | float) else 300,
        )
        app.state.auth_mode = mode

    _sync_decision_emitter(current_version.policy)
    _sync_alerts(current_version.policy)
    _sync_auth(current_version.policy)

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

    @app.middleware("http")
    async def trace_headers_middleware(request: Request, call_next):
        trace = TraceContext.from_headers(dict(request.headers))
        request.state.trace_context = trace
        response = await call_next(request)
        response.headers["X-Orchesis-Trace-Id"] = trace.trace_id
        decision_header = getattr(request.state, "orchesis_decision", None)
        if isinstance(decision_header, str):
            response.headers["X-Orchesis-Decision"] = decision_header
        return response

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
        logger.info("policy updated", version_id=version.version_id)
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
        logger.warn("policy rolled back", previous=previous, rolled_back_to=rolled.version_id)
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
    def get_agent(
        agent_id: str, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
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

        policy_file.write_text(
            yaml.safe_dump(policy, sort_keys=False, allow_unicode=True), encoding="utf-8"
        )
        version = store.load(str(policy_file))
        _refresh_current_version()
        logger.warn(
            "agent tier changed",
            agent_id=agent_id,
            previous_tier=previous_tier,
            new_tier=tier_name,
            policy_version=version.version_id,
        )
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
            "version": "0.7.0",
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

    @app.get("/favicon.ico")
    def favicon() -> Response:
        return Response(status_code=204)

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

    @app.get("/api/v1/reliability")
    def reliability(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        generator = ReliabilityReportGenerator(
            corpus_path="tests/corpus",
            decisions_log=app.state.decisions_log,
        )
        return json.loads(generator.to_json(generator.generate()))

    def _evaluate_payload(body: dict[str, Any], trace: TraceContext) -> dict[str, Any]:
        payload = dict(body)
        tool_name = payload.get("tool_name")
        if not isinstance(tool_name, str) or not tool_name.strip():
            tool_name = payload.get("tool")
        if not isinstance(tool_name, str) or not tool_name.strip():
            raise HTTPException(status_code=400, detail={"error": "tool_name or tool is required"})
        params = payload.get("params")
        params = dict(params) if isinstance(params, dict) else {}
        context = payload.get("context")
        payload_context = dict(context) if isinstance(context, dict) else {}

        agent_id = payload.get("agent_id")
        if isinstance(agent_id, str) and agent_id.strip():
            payload_context["agent"] = agent_id.strip()
        elif not isinstance(payload_context.get("agent"), str):
            payload_context["agent"] = "__global__"
        session_type = payload.get("session_type")
        session_type = session_type if isinstance(session_type, str) and session_type.strip() else "cli"
        channel = payload.get("channel")
        channel = channel.strip().lower() if isinstance(channel, str) and channel.strip() else None
        if channel is not None:
            payload_context["channel"] = channel

        payload_context["trace_id"] = trace.trace_id
        if trace.parent_span_id:
            payload_context["parent_span_id"] = trace.parent_span_id

        debug_mode = bool(payload.pop("debug", False))
        eval_payload = {
            "tool": tool_name.strip(),
            "params": params,
            "cost": payload.get("cost", 0.0),
            "context": payload_context,
        }
        started_ns = time.perf_counter_ns()
        decision = evaluate(
            eval_payload,
            app.state.current_version.policy,
            state=tracker,
            emitter=event_bus,
            registry=app.state.current_version.registry,
            plugins=app.state.plugins,
            session_type=session_type,
            channel=channel,
            debug=debug_mode,
        )
        elapsed_us = max(0, (time.perf_counter_ns() - started_ns) // 1000)
        reason_text = decision.reasons[0] if decision.reasons else ""
        reason, rule, severity = _parse_reason(reason_text)
        response = {
            "decision": "ALLOW" if decision.allowed else "DENY",
            "allowed": decision.allowed,
            "reason": reason,
            "rule": rule,
            "severity": severity,
            "latency_us": int(elapsed_us),
            "policy_version": app.state.current_version.version_id,
            "recommendations": [] if decision.allowed else _recommendations_for_rule(rule),
            # Backward-compatible fields for existing clients/tests.
            "reasons": decision.reasons,
            "rules_checked": decision.rules_checked,
            "evaluation_us": int(elapsed_us),
            "tool_name": tool_name.strip(),
            "agent_id": payload_context.get("agent", "__global__"),
            "channel": channel,
            "debug": debug_mode,
        }
        if debug_mode:
            response["debug_trace"] = decision.debug_trace
        return response

    def _authenticate_request(request: Request, eval_payload: dict[str, Any]) -> tuple[bool, str]:
        authenticator = getattr(app.state, "authenticator", None)
        mode = str(getattr(app.state, "auth_mode", "optional"))
        if authenticator is None:
            return True, ""
        allowed, agent_id, reason = authenticator.authenticate_request(eval_payload, dict(request.headers))
        if not allowed:
            if mode == "enforce":
                raise HTTPException(status_code=401, detail={"error": "unauthorized", "reason": reason})
            if mode == "log":
                logger.warn("authentication failed (log mode)", reason=reason)
                return True, ""
            return True, ""
        return True, agent_id

    @app.post("/api/v1/evaluate")
    def evaluate_remote(
        body: dict[str, Any],
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        _refresh_current_version()
        trace = getattr(request.state, "trace_context", TraceContext())
        tool_name = body.get("tool_name")
        if not isinstance(tool_name, str) or not tool_name.strip():
            tool_name = body.get("tool")
        params = body.get("params")
        eval_payload = {"tool": tool_name or "", "params": params if isinstance(params, dict) else {}}
        _ok, verified_agent_id = _authenticate_request(request, eval_payload)
        if verified_agent_id:
            body = dict(body)
            body["agent_id"] = verified_agent_id
        response = _evaluate_payload(body=body, trace=trace)
        request.state.orchesis_decision = "ALLOW" if response["allowed"] else "DENY"
        logger.debug(
            "remote evaluation completed",
            allowed=response["allowed"],
            agent_id=response.get("agent_id", "__global__"),
            tool=response.get("tool_name"),
            debug=bool(response.get("debug", False)),
        )
        return response

    @app.post("/api/v1/evaluate/batch")
    def evaluate_batch(
        body: dict[str, Any],
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        _refresh_current_version()
        trace = getattr(request.state, "trace_context", TraceContext())
        evaluations = body.get("evaluations")
        if not isinstance(evaluations, list):
            raise HTTPException(status_code=400, detail={"error": "evaluations must be a list"})
        results: list[dict[str, Any]] = []
        for item in evaluations:
            if isinstance(item, dict):
                tool_name = item.get("tool_name")
                if not isinstance(tool_name, str) or not tool_name.strip():
                    tool_name = item.get("tool")
                params = item.get("params")
                eval_payload = {"tool": tool_name or "", "params": params if isinstance(params, dict) else {}}
                _ok, verified_agent_id = _authenticate_request(request, eval_payload)
                if verified_agent_id:
                    item = dict(item)
                    item["agent_id"] = verified_agent_id
                results.append(_evaluate_payload(item, trace))
        denied_count = sum(1 for item in results if item.get("allowed") is False)
        request.state.orchesis_decision = "DENY" if denied_count > 0 else "ALLOW"
        return {
            "results": results,
            "summary": {
                "total": len(results),
                "allowed": len(results) - denied_count,
                "denied": denied_count,
            },
        }

    @app.get("/api/v1/proxy/stats")
    def proxy_stats() -> dict[str, Any]:
        stats = getattr(app.state, "proxy_stats", None)
        if hasattr(stats, "to_dict"):
            payload = stats.to_dict()
            if isinstance(payload, dict):
                return payload
        if isinstance(stats, dict):
            return stats
        return {
            "requests_total": 0,
            "requests_allowed": 0,
            "requests_denied": 0,
            "requests_passthrough": 0,
            "requests_error": 0,
            "bytes_proxied": 0,
            "avg_latency_ms": 0.0,
            "uptime_seconds": 0,
        }

    @app.post("/api/v1/nodes/heartbeat")
    def nodes_heartbeat(
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Record node heartbeat and indicate if policy changed."""
        _require_auth(authorization)
        _refresh_current_version()
        node_id = body.get("node_id")
        policy_version = body.get("policy_version")
        if not isinstance(node_id, str) or not node_id:
            raise HTTPException(status_code=400, detail={"error": "node_id is required"})
        if not isinstance(policy_version, str) or not policy_version:
            raise HTTPException(status_code=400, detail={"error": "policy_version is required"})
        app.state.sync_server.register_node(node_id=node_id, policy_version=policy_version)
        forced = app.state.sync_server.consume_force_sync(node_id)
        current_version = app.state.current_version.version_id
        in_sync = policy_version == current_version
        return {
            "in_sync": in_sync,
            "current_version": current_version,
            "policy_changed": (not in_sync) or forced,
        }

    @app.get("/api/v1/nodes")
    def list_nodes(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        """List known enforcement nodes and sync state."""
        _require_auth(authorization)
        _refresh_current_version()
        nodes = app.state.sync_server.get_nodes()
        payload_nodes = [
            {
                "node_id": item.node_id,
                "policy_version": item.policy_version,
                "last_seen": item.last_sync,
                "in_sync": item.in_sync,
            }
            for item in nodes
        ]
        in_sync_count = sum(1 for item in nodes if item.in_sync)
        out_of_sync_count = len(nodes) - in_sync_count
        return {
            "nodes": payload_nodes,
            "total": len(nodes),
            "in_sync": in_sync_count,
            "out_of_sync": out_of_sync_count,
        }

    @app.post("/api/v1/nodes/{node_id}/force-sync")
    def force_sync_node(
        node_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Request policy re-pull for a node."""
        _require_auth(authorization)
        known = {item.node_id for item in app.state.sync_server.get_nodes()}
        if node_id not in known:
            raise HTTPException(status_code=404, detail={"error": "node not found"})
        app.state.sync_server.request_force_sync(node_id)
        return {"message": f"sync requested for {node_id}"}

    @app.get("/api/v1/incidents")
    def incidents_list(
        since: str | None = None,
        severity: str | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        engine = ForensicsEngine(decisions_path=app.state.decisions_log)
        incidents = engine.detect_incidents(since=since, severity_filter=severity)
        return {"incidents": [incident.__dict__ for incident in incidents], "total": len(incidents)}

    @app.get("/api/v1/incidents/report")
    def incidents_report(
        since: str | None = None,
        format: str = "json",  # noqa: A002
        authorization: str | None = Header(default=None),
    ) -> Any:
        _require_auth(authorization)
        engine = ForensicsEngine(decisions_path=app.state.decisions_log)
        report = engine.build_report(since=since)
        if format.lower() == "markdown":
            return {"markdown": engine.export_markdown(report)}
        return json.loads(engine.export_json(report))

    @app.get("/api/v1/agents/{agent_id}/risk")
    def agent_risk(agent_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        engine = ForensicsEngine(decisions_path=app.state.decisions_log)
        return engine.agent_risk_profile(agent_id)

    @app.get("/api/v1/incidents/timeline")
    def incidents_timeline(
        agent_id: str | None = None,
        incident_id: str | None = None,
        last: int = 50,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        engine = ForensicsEngine(decisions_path=app.state.decisions_log)
        events = engine.attack_timeline(
            incident_id=incident_id,
            agent_id=agent_id,
            last_n=max(1, int(last)),
        )
        return {"events": events}

    @app.get("/api/v1/incidents/{incident_id}")
    def incident_detail(
        incident_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        engine = ForensicsEngine(decisions_path=app.state.decisions_log)
        incident = engine.get_incident(incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail={"error": "incident not found"})
        return incident.__dict__

    return app


def _recommendations_for_rule(rule: str) -> list[str]:
    mapping = {
        "file_access": ["Remove sensitive paths from agent workspace"],
        "sql_restriction": ["Use read-only SQL operations for agent queries"],
        "rate_limit": ["Reduce request rate or increase policy rate limit"],
        "budget_limit": ["Reduce cost per request or raise budget threshold"],
        "token_budget": ["Lower context size or split tool calls into smaller chunks"],
    }
    return mapping.get(rule, ["Review policy and request payload before retrying"])


def _parse_reason(reason: str) -> tuple[str, str, str]:
    text = reason.strip() if isinstance(reason, str) and reason.strip() else "blocked_by_policy"
    rule = text.split(":", 1)[0].strip() if ":" in text else "policy"
    lowered = text.lower()
    if "daily token budget" in lowered:
        severity = "high"
    elif "denied" in lowered or "exceeded" in lowered:
        severity = "medium"
    else:
        severity = "low"
    return text, rule, severity
