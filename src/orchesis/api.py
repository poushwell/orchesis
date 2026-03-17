"""Governance control-plane HTTP API."""

from __future__ import annotations

import json
import os
import time
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.routing import APIRoute
from fastapi.responses import JSONResponse, Response

from orchesis.auth import AgentAuthenticator, CredentialStore
from orchesis.agent_health import AgentHealthScore
from orchesis.audit import AuditEngine, AuditQuery
from orchesis.compliance_report import ComplianceReportGenerator
from orchesis.agent_store import AgentPolicyStore, build_agent_overwatch_snapshot
from orchesis.config import load_policy, validate_policy, validate_policy_warnings
from orchesis.corpus import RegressionCorpus
from orchesis.engine import evaluate
from orchesis.events import EventBus
from orchesis.forensics import ForensicsEngine, Incident
from orchesis.integrations import SlackEmitter, SlackNotifier, TelegramEmitter, TelegramNotifier
from orchesis.integrations.forensics_emitter import ForensicsEmitter
from orchesis.metrics import MetricsCollector
from orchesis.mcp_monitor import McpRuntimeMonitor
from orchesis.otel import OTelEmitter, TraceContext
from orchesis.policy_store import PolicyStore
from orchesis.plugins import load_plugins_for_policy
from orchesis.reliability import ReliabilityReportGenerator
from orchesis.redaction import AuditRedactor
from orchesis.replay import read_events_from_jsonl
from orchesis.state import RateLimitTracker
from orchesis.structured_log import StructuredLogger
from orchesis.sync import PolicySyncServer
from orchesis.telemetry import JsonlEmitter
from orchesis.flow_xray import FlowAnalyzer
from orchesis.context_dna import ContextDNA
from orchesis.context_dna_store import ContextDNAStore
from orchesis.agent_profile import AgentIntelligenceProfile
from orchesis.pipeline import check_budget
from orchesis.evidence_record import EvidenceRecord
from orchesis.token_yield import TokenYieldTracker
from orchesis import __version__


def create_api_app(
    policy_path: str = "policy.yaml",
    state_persist: str = ".orchesis/state.jsonl",
    decisions_log: str = ".orchesis/decisions.jsonl",
    history_path: str = ".orchesis/policy_versions.jsonl",
    plugin_modules: list[str] | None = None,
    api_token: str | None = None,
    cors_origins: list[str] | None = None,
) -> FastAPI:
    """Create governance control-plane API."""
    app = FastAPI(title="Orchesis Control API", docs_url=None, redoc_url=None)
    logger = StructuredLogger("api")
    if isinstance(cors_origins, list) and cors_origins:
        allow_all = "*" in cors_origins
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"] if allow_all else cors_origins,
            allow_credentials=(not allow_all),
            allow_methods=["*"],
            allow_headers=["*"],
        )

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
    app.state.agent_policy_store = AgentPolicyStore(
        policy_file.parent / ".orchesis" / "agent_policies.json",
        decisions_log_path=decisions_log,
    )
    app.state.incidents_log = ".orchesis/incidents.jsonl"
    app.state.current_version = current_version
    app.state.plugin_modules = list(plugin_modules or [])
    app.state.plugins = load_plugins_for_policy(current_version.policy, app.state.plugin_modules)
    app.state.sync_server = PolicySyncServer()
    app.state.sync_server.set_current_version(current_version.version_id)
    app.state.proxy_stats = None
    app.state.authenticator = None
    app.state.auth_mode = "optional"
    app.state.flow_analyzer = FlowAnalyzer({"enabled": True})
    app.state.flow_decisions = {}
    app.state.api_token_override = api_token.strip() if isinstance(api_token, str) and api_token.strip() else None
    app.state.token_yield = TokenYieldTracker()
    app.state.dna_store = ContextDNAStore(str(policy_file.parent / ".orchesis" / "dna"))
    mcp_monitor_cfg = (
        current_version.policy.get("mcp_monitor")
        if isinstance(current_version.policy, dict) and isinstance(current_version.policy.get("mcp_monitor"), dict)
        else {}
    )
    monitor_enabled = bool(mcp_monitor_cfg.get("enabled", False))
    monitor_paths_raw = mcp_monitor_cfg.get("config_paths")
    monitor_paths = (
        [item for item in monitor_paths_raw if isinstance(item, str) and item.strip()]
        if isinstance(monitor_paths_raw, list)
        else []
    )
    if not monitor_paths:
        monitor_paths = [str(policy_file)]
    monitor_interval = (
        int(mcp_monitor_cfg.get("interval_seconds", 30))
        if isinstance(mcp_monitor_cfg.get("interval_seconds", 30), int | float)
        else 30
    )
    app.state.mcp_monitor = McpRuntimeMonitor(monitor_paths, interval_seconds=monitor_interval)
    if monitor_enabled:
        app.state.mcp_monitor.start()

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
        _sync_agent_teams_from_policy(app.state.current_version.policy)

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

    def _sync_agent_teams_from_policy(candidate_policy: dict[str, Any]) -> None:
        agents = candidate_policy.get("agents")
        if not isinstance(agents, list):
            return
        for item in agents:
            if not isinstance(item, dict):
                continue
            agent_id = item.get("id")
            if not isinstance(agent_id, str) or not agent_id.strip():
                continue
            team_id = item.get("team")
            if not isinstance(team_id, str):
                team_id = item.get("team_id")
            if isinstance(team_id, str) and team_id.strip():
                app.state.agent_policy_store.set_agent_team(agent_id.strip(), team_id.strip())
            else:
                app.state.agent_policy_store.update_policy(agent_id.strip(), {"team_id": None})

    _sync_decision_emitter(current_version.policy)
    _sync_alerts(current_version.policy)
    _sync_auth(current_version.policy)
    _sync_agent_teams_from_policy(current_version.policy)

    def _auth_token_from_policy() -> str | None:
        token_override = getattr(app.state, "api_token_override", None)
        if isinstance(token_override, str) and token_override.strip():
            return token_override.strip()
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

    def _extract_session_id(payload: dict[str, Any]) -> str | None:
        direct = payload.get("session_id")
        if isinstance(direct, str) and direct.strip():
            return direct.strip()
        context = payload.get("context")
        if isinstance(context, dict):
            nested = context.get("session_id")
            if isinstance(nested, str) and nested.strip():
                return nested.strip()
        return None

    def _flow_share_payload(session_id: str) -> dict[str, str]:
        issued_at = datetime.now(timezone.utc).isoformat()
        token_seed = f"{session_id}:{issued_at}"
        token = hashlib.sha256(token_seed.encode("utf-8")).hexdigest()[:8]
        return {"token": token, "url": f"http://localhost:8080/flow/{token}"}

    def _build_evidence_record(session_id: str) -> dict[str, Any]:
        audit = _audit_engine()
        decisions = audit.query(AuditQuery(session_id=session_id, limit=1_000_000))
        return EvidenceRecord().build(session_id=session_id, decisions_log=decisions)

    def _build_compliance_report(agent_id: str) -> dict[str, Any]:
        source = Path(app.state.decisions_log)
        events = read_events_from_jsonl(source) if source.exists() else []
        filtered = [event for event in events if str(getattr(event, "agent_id", "")) == str(agent_id)]
        return ComplianceReportGenerator().generate(agent_id=str(agent_id), decisions_log=filtered)

    def _build_context_budget_payload(session_id: str | None = None) -> dict[str, Any]:
        source = Path(app.state.decisions_log)
        events = read_events_from_jsonl(source) if source.exists() else []
        target_session = session_id if isinstance(session_id, str) and session_id.strip() else None
        level_rank = {"normal": 0, "L0": 1, "L1": 2, "L2": 3}
        degradation_events = {"L0": 0, "L1": 0, "L2": 0}
        tokens_saved = 0
        current_level = "normal"
        latest_ts: datetime | None = None
        latest_model = "gpt-4o-mini"
        for event in events:
            snapshot = event.state_snapshot if isinstance(event.state_snapshot, dict) else {}
            event_session = _extract_session_id(snapshot)
            if target_session is not None and event_session != target_session:
                continue
            level_raw = snapshot.get("context_budget_level")
            level = str(level_raw) if isinstance(level_raw, str) else "normal"
            if level in degradation_events:
                degradation_events[level] += 1
            tokens_saved += int(snapshot.get("context_tokens_saved", 0) or 0)
            event_ts = _parse_health_ts(str(event.timestamp))
            if event_ts is not None and (latest_ts is None or event_ts > latest_ts):
                latest_ts = event_ts
                if isinstance(snapshot.get("model"), str) and snapshot.get("model"):
                    latest_model = str(snapshot.get("model"))
                if level_rank.get(level, 0) >= level_rank.get(current_level, 0):
                    current_level = level
        context_cfg = app.state.current_version.policy.get("context_budget")
        model_windows = (
            context_cfg.get("model_context_windows")
            if isinstance(context_cfg, dict) and isinstance(context_cfg.get("model_context_windows"), dict)
            else {}
        )
        context_window = int(model_windows.get(latest_model, 128000))
        session_name = target_session if target_session is not None else "global"
        return {
            "session_id": session_name,
            "current_level": current_level if current_level in {"normal", "L0", "L1", "L2"} else "normal",
            "degradation_events": degradation_events,
            "tokens_saved_by_degradation": int(tokens_saved),
            "model": latest_model,
            "context_window": context_window,
        }

    def _record_flow_decision(payload: dict[str, Any], response: dict[str, Any]) -> None:
        session_id = _extract_session_id(payload)
        if session_id is None:
            return
        tool_name = payload.get("tool_name")
        if not isinstance(tool_name, str) or not tool_name.strip():
            tool_name = payload.get("tool")
        cost_raw = payload.get("cost", 0.0)
        try:
            cost_usd = float(cost_raw)
        except (TypeError, ValueError):
            cost_usd = 0.0
        duration_ms = max(0.0, float(response.get("latency_us", 0.0) or 0.0) / 1000.0)
        allowed = bool(response.get("allowed", False))
        node_id = app.state.flow_analyzer.record_request(
            session_id=session_id,
            model="governance-evaluator",
            messages=[{"role": "system", "content": str(tool_name or "")}],
            tools=[],
        )
        app.state.flow_analyzer.record_response(
            session_id=session_id,
            node_id=node_id,
            tokens_in=0,
            tokens_out=0,
            cost_usd=cost_usd,
            latency_ms=duration_ms,
            status="ok" if allowed else "denied",
            tool_calls=[],
        )
        decisions = app.state.flow_decisions.setdefault(session_id, [])
        decisions.append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tool_name": str(tool_name or ""),
                "allowed": allowed,
                "decision": "ALLOW" if allowed else "DENY",
                "reasons": list(response.get("reasons", []))
                if isinstance(response.get("reasons"), list)
                else [],
                "cost_usd": cost_usd,
                "duration_ms": duration_ms,
            }
        )
        if len(decisions) > 2000:
            del decisions[:-2000]
        agent_id = str(response.get("agent_id", "__global__") or "__global__")
        dna = app.state.dna_store.get(agent_id)
        if dna is None:
            dna = ContextDNA(agent_id=agent_id)
        dna.observe(payload, response)
        dna.compute_baseline()
        app.state.dna_store.save(dna)

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

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "version": __version__,
            "uptime_seconds": int(max(0.0, time.perf_counter() - started_at)),
        }

    @app.get("/docs")
    def docs_index() -> Response:
        rows: list[str] = []
        for route in app.routes:
            if not isinstance(route, APIRoute):
                continue
            methods = sorted(method for method in route.methods if method not in {"HEAD", "OPTIONS"})
            if not methods:
                continue
            rows.append(
                "<tr>"
                f"<td>{', '.join(methods)}</td>"
                f"<td><code>{route.path}</code></td>"
                "</tr>"
            )
        rows.sort()
        html = (
            "<!doctype html><html><head><meta charset='utf-8'><title>Orchesis API Docs</title>"
            "<style>body{font-family:Arial,sans-serif;padding:24px;background:#0b0f14;color:#e6edf3}"
            "table{border-collapse:collapse;width:100%}th,td{border:1px solid #30363d;padding:8px;text-align:left}"
            "th{background:#161b22}code{color:#7ee787}</style></head><body>"
            "<h1>Orchesis API Endpoints</h1>"
            "<p>Use <code>Authorization: Bearer &lt;token&gt;</code> for protected routes.</p>"
            "<table><thead><tr><th>Method</th><th>Path</th></tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table></body></html>"
        )
        return Response(content=html, media_type="text/html; charset=utf-8")

    @app.on_event("shutdown")
    async def _shutdown_monitor() -> None:
        monitor = getattr(app.state, "mcp_monitor", None)
        if monitor is not None and hasattr(monitor, "stop"):
            monitor.stop()

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

    @app.get("/api/v1/evidence/{session_id}")
    def evidence_record_endpoint(
        session_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return _build_evidence_record(session_id)

    @app.get("/api/v1/evidence/{session_id}/text")
    def evidence_record_text_endpoint(
        session_id: str,
        authorization: str | None = Header(default=None),
    ) -> Response:
        _require_auth(authorization)
        record = _build_evidence_record(session_id)
        text_report = EvidenceRecord().export_text(record)
        return Response(content=text_report, media_type="text/plain; charset=utf-8")

    @app.get("/api/v1/evidence/{session_id}/download")
    def evidence_record_download_endpoint(
        session_id: str,
        authorization: str | None = Header(default=None),
    ) -> Response:
        _require_auth(authorization)
        record = _build_evidence_record(session_id)
        payload = json.dumps(record, ensure_ascii=False, indent=2).encode("utf-8")
        headers = {"Content-Disposition": f'attachment; filename="evidence_{session_id}.json"'}
        return Response(content=payload, media_type="application/json", headers=headers)

    @app.get("/api/v1/compliance/report/{agent_id}")
    def compliance_report_endpoint(
        agent_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return _build_compliance_report(agent_id)

    @app.get("/api/v1/compliance/report/{agent_id}/text")
    def compliance_report_text_endpoint(
        agent_id: str,
        authorization: str | None = Header(default=None),
    ) -> Response:
        _require_auth(authorization)
        report = _build_compliance_report(agent_id)
        text_report = ComplianceReportGenerator().export_text(report)
        return Response(content=text_report, media_type="text/plain; charset=utf-8")

    @app.get("/api/v1/context-budget/stats")
    def context_budget_stats_endpoint(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return _build_context_budget_payload(None)

    @app.get("/api/v1/context-budget/{session_id}")
    def context_budget_session_endpoint(
        session_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return _build_context_budget_payload(session_id)

    @app.post("/api/v1/policy/reload")
    def policy_reload(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        try:
            loaded = load_policy(policy_file)
        except ValueError as error:
            raise HTTPException(status_code=400, detail={"errors": [str(error)]}) from error
        errors = validate_policy(loaded)
        if errors:
            raise HTTPException(status_code=400, detail={"errors": errors})
        version = store.load(str(policy_file))
        _refresh_current_version()
        return {
            "status": "reloaded",
            "version": version.version_id,
            "timestamp": time.time(),
        }

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

    @app.get("/api/v1/agents/{agent_id}/health")
    def get_agent_health(
        agent_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        _refresh_current_version()
        audit = _audit_engine()
        events = audit.query(AuditQuery(agent_id=agent_id, since_hours=48, limit=20_000))
        now = datetime.now(timezone.utc)
        last_24: list[Any] = []
        previous_24: list[Any] = []
        for event in events:
            ts = _parse_health_ts(str(getattr(event, "timestamp", "")))
            if ts is None:
                continue
            elapsed_hours = (now - ts).total_seconds() / 3600.0
            if elapsed_hours <= 24.0:
                last_24.append(event)
            elif elapsed_hours <= 48.0:
                previous_24.append(event)
        metrics_snapshot = app.state.metrics.snapshot()
        cache_hit_rate = _cache_hit_rate_from_metrics(metrics_snapshot)
        scorer = AgentHealthScore()
        current_stats = _build_health_stats(
            events=last_24,
            agent_id=agent_id,
            policy_store=app.state.agent_policy_store,
            decisions_log=app.state.decisions_log,
            cache_hit_rate=cache_hit_rate,
        )
        previous_score: float | None = None
        if previous_24:
            previous_stats = _build_health_stats(
                events=previous_24,
                agent_id=agent_id,
                policy_store=app.state.agent_policy_store,
                decisions_log=app.state.decisions_log,
                cache_hit_rate=cache_hit_rate,
            )
            previous_score = float(scorer.compute(previous_stats)["score"])
        health = scorer.compute({**current_stats, "previous_score": previous_score})
        return {"agent_id": agent_id, **health}

    @app.get("/api/v1/agents/{agent_id}/profile")
    def get_agent_profile(
        agent_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        health = get_agent_health(agent_id, authorization)
        builder = AgentIntelligenceProfile()
        return builder.build(
            agent_id=agent_id,
            dna_store=app.state.dna_store,
            health_score=health,
            decisions_log=app.state.decisions_log,
        )

    @app.get("/api/v1/overwatch")
    def get_overwatch(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        snapshot = build_agent_overwatch_snapshot(
            decisions_log_path=app.state.decisions_log,
            policy_store=app.state.agent_policy_store,
        )
        return snapshot

    @app.get("/api/v1/overwatch/{agent_id}/threats")
    def get_overwatch_threats(
        agent_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        source = Path(app.state.decisions_log)
        if not source.exists():
            return {"agent_id": agent_id, "threats": []}
        rows: list[dict[str, Any]] = []
        for event in read_events_from_jsonl(source):
            if event.agent_id != agent_id or event.decision != "DENY":
                continue
            reason = event.reasons[0] if event.reasons else "blocked_by_policy"
            rows.append(
                {
                    "timestamp": event.timestamp,
                    "type": reason.split(":", 1)[0],
                    "severity": _reason_to_severity(reason),
                    "blocked": True,
                    "rule_id": reason.split(":", 1)[0],
                }
            )
        rows.sort(key=lambda item: str(item["timestamp"]), reverse=True)
        return {"agent_id": agent_id, "threats": rows[:50]}

    @app.post("/api/v1/overwatch/{agent_id}/budget")
    def post_overwatch_budget(
        agent_id: str,
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        daily_limit = body.get("daily_limit")
        if not isinstance(daily_limit, int | float):
            raise HTTPException(status_code=400, detail={"error": "daily_limit must be a number"})
        policy = app.state.agent_policy_store.set_daily_limit(agent_id, float(daily_limit))
        return {"agent_id": agent_id, "policy": policy}

    @app.post("/api/v1/overwatch/{agent_id}/team")
    def post_overwatch_team(
        agent_id: str,
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        team_id = body.get("team_id")
        if not isinstance(team_id, str) or not team_id.strip():
            raise HTTPException(status_code=400, detail={"error": "team_id is required"})
        app.state.agent_policy_store.set_agent_team(agent_id, team_id.strip())
        return {"agent_id": agent_id, "team_id": team_id.strip()}

    @app.get("/api/v1/overwatch/teams")
    def get_overwatch_teams(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        team_ids = app.state.agent_policy_store.list_teams()
        return {
            "teams": [app.state.agent_policy_store.get_team_summary(team_id) for team_id in team_ids]
        }

    @app.get("/api/v1/overwatch/teams/{team_id}")
    def get_overwatch_team(
        team_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.agent_policy_store.get_team_summary(team_id)

    @app.get("/api/v1/overwatch/{agent_id}/policy")
    def get_overwatch_policy(
        agent_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return {"agent_id": agent_id, "policy": app.state.agent_policy_store.get_policy(agent_id)}

    @app.post("/api/v1/overwatch/{agent_id}/policy")
    def post_overwatch_policy(
        agent_id: str,
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        if not isinstance(body, dict):
            raise HTTPException(status_code=400, detail={"error": "policy patch body is required"})
        policy = app.state.agent_policy_store.update_policy(agent_id, body)
        return {"agent_id": agent_id, "policy": policy}

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
            "version": __version__,
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

    @app.get("/api/v1/token-yield/{session_id}")
    def token_yield_session(
        session_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.token_yield.get_yield(session_id)

    @app.get("/api/v1/token-yield/global")
    def token_yield_global(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.token_yield.get_global_stats()

    @app.get("/api/v1/mcp/monitor/status")
    def mcp_monitor_status(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        monitor = app.state.mcp_monitor
        stats = monitor.get_stats()
        return {"status": "ok", "monitor": stats}

    @app.get("/api/v1/mcp/monitor/alerts")
    def mcp_monitor_alerts(
        since: float | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        monitor = app.state.mcp_monitor
        alerts = monitor.get_alerts(since=since)
        return {"alerts": alerts, "total": len(alerts)}

    @app.post("/api/v1/mcp/monitor/check")
    def mcp_monitor_check(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        monitor = app.state.mcp_monitor
        changes = monitor.check_once()
        return {"changes": changes, "count": len(changes)}

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

    @app.get("/api/v1/flow/{session_id}/share-token")
    def flow_share_token(
        session_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        share = _flow_share_payload(session_id)
        return {"session_id": session_id, "token": share["token"], "url": share["url"]}

    @app.get("/api/v1/flow/{session_id}/export")
    def flow_export(
        session_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        analysis = app.state.flow_analyzer.analyze_session(session_id)
        graph = app.state.flow_analyzer.get_session_graph(session_id)
        decisions_raw = app.state.flow_decisions.get(session_id, [])
        decisions = [dict(item) for item in decisions_raw if isinstance(item, dict)]
        phase_counts: dict[str, int] = {}
        if graph is not None:
            for node in graph.nodes.values():
                key = f"{node.node_type.value}_phase"
                phase_counts[key] = phase_counts.get(key, 0) + 1
        pipeline_phases = [{"phase": key, "count": value} for key, value in sorted(phase_counts.items())]
        if not pipeline_phases:
            pipeline_phases = [{"phase": "evaluate_phase", "count": len(decisions)}]
        total_requests = len(decisions)
        blocked = sum(1 for item in decisions if item.get("allowed") is False)
        cost_usd = round(sum(float(item.get("cost_usd", 0.0) or 0.0) for item in decisions), 8)
        duration_ms = round(sum(float(item.get("duration_ms", 0.0) or 0.0) for item in decisions), 6)
        if analysis is not None:
            if total_requests == 0:
                total_requests = int(analysis.topology.total_llm_calls)
            if cost_usd == 0.0:
                cost_usd = round(float(analysis.topology.total_cost_usd), 8)
            if duration_ms == 0.0:
                duration_ms = round(float(analysis.topology.total_latency_ms), 6)
        share = _flow_share_payload(session_id)
        return {
            "session_id": session_id,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "pipeline_phases": pipeline_phases,
            "decisions": decisions,
            "summary": {
                "total_requests": total_requests,
                "blocked": blocked,
                "cost_usd": cost_usd,
                "duration_ms": duration_ms,
            },
            "share_url": share["url"],
        }

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
        session_id = _extract_session_id(payload)
        if not isinstance(session_id, str) or not session_id.strip():
            session_id = str(payload_context.get("trace_id", "__global__"))
        prompt_tokens_raw = payload.get("prompt_tokens", payload_context.get("prompt_tokens", 0))
        completion_tokens_raw = payload.get("completion_tokens", payload_context.get("completion_tokens", 0))
        unique_ratio_raw = payload.get(
            "unique_content_ratio",
            payload_context.get("unique_content_ratio", 1.0),
        )
        cache_hit_raw = payload.get("cache_hit", payload_context.get("cache_hit", False))
        prompt_tokens = int(prompt_tokens_raw) if isinstance(prompt_tokens_raw, int | float) else 0
        completion_tokens = (
            int(completion_tokens_raw) if isinstance(completion_tokens_raw, int | float) else 0
        )
        unique_ratio = float(unique_ratio_raw) if isinstance(unique_ratio_raw, int | float) else 1.0
        cache_hit = bool(cache_hit_raw)
        app.state.token_yield.record(
            session_id=session_id,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            cache_hit=cache_hit,
            unique_content_ratio=unique_ratio,
        )
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
        effective_agent_id = (
            str(body.get("agent_id", "")).strip()
            if isinstance(body.get("agent_id"), str)
            else "__global__"
        ) or "__global__"
        budget_allowed, budget_meta = check_budget(
            effective_agent_id,
            policy_store=app.state.agent_policy_store,
            decisions_log_path=app.state.decisions_log,
        )
        if not budget_allowed:
            raise HTTPException(status_code=429, detail=budget_meta)
        response = _evaluate_payload(body=body, trace=trace)
        request.state.orchesis_decision = "ALLOW" if response["allowed"] else "DENY"
        _record_flow_decision(body, response)
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
                effective_agent_id = (
                    str(item.get("agent_id", "")).strip()
                    if isinstance(item.get("agent_id"), str)
                    else "__global__"
                ) or "__global__"
                budget_allowed, budget_meta = check_budget(
                    effective_agent_id,
                    policy_store=app.state.agent_policy_store,
                    decisions_log_path=app.state.decisions_log,
                )
                if not budget_allowed:
                    raise HTTPException(status_code=429, detail=budget_meta)
                result = _evaluate_payload(item, trace)
                _record_flow_decision(item, result)
                results.append(result)
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


def _reason_to_severity(reason: str) -> str:
    _, _, severity = _parse_reason(reason)
    return severity


def _parse_health_ts(value: str) -> datetime | None:
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _cache_hit_rate_from_metrics(snapshot: dict[str, Any]) -> float:
    if not isinstance(snapshot, dict):
        return 0.0
    for key in ("cache_hit_rate_percent", "semantic_cache_hit_rate_percent"):
        value = snapshot.get(key)
        if isinstance(value, int | float):
            return max(0.0, min(1.0, float(value) / 100.0))
    gauges = snapshot.get("gauges")
    if isinstance(gauges, dict):
        for key in ("cache_hit_rate_percent", "semantic_cache_hit_rate_percent"):
            value = gauges.get(key)
            if isinstance(value, int | float):
                return max(0.0, min(1.0, float(value) / 100.0))
    return 0.0


def _build_health_stats(
    *,
    events: list[Any],
    agent_id: str,
    policy_store: AgentPolicyStore,
    decisions_log: str,
    cache_hit_rate: float,
) -> dict[str, float]:
    total = len(events)
    denied = sum(1 for event in events if str(getattr(event, "decision", "")).upper() == "DENY")
    block_rate = (denied / total) if total else 0.0
    threat_frequency = block_rate
    loop_signals = 0
    error_signals = 0
    latencies_ms: list[float] = []
    total_cost = 0.0
    for event in events:
        reasons = getattr(event, "reasons", [])
        if isinstance(reasons, list):
            reason_text = " ".join(str(item).lower() for item in reasons)
            if "loop" in reason_text:
                loop_signals += 1
            if "error" in reason_text or "timeout" in reason_text or "exception" in reason_text:
                error_signals += 1
        duration_us = getattr(event, "evaluation_duration_us", 0)
        if isinstance(duration_us, int | float):
            latencies_ms.append(max(0.0, float(duration_us) / 1000.0))
        total_cost += float(getattr(event, "cost", 0.0) or 0.0)
    loop_frequency = (loop_signals / total) if total else 0.0
    error_rate = (error_signals / total) if total else 0.0
    latency_ms = (sum(latencies_ms) / len(latencies_ms)) if latencies_ms else 0.0
    policy = policy_store.get_policy(agent_id)
    budget = policy.get("budget_daily")
    if isinstance(budget, int | float) and float(budget) > 0.0:
        budget_limit = float(budget)
        cost_today = policy_store.get_cost_today(agent_id, decisions_log)
        cost_budget_ratio = max(0.0, min(1.0, cost_today / budget_limit))
        savings_rate = max(0.0, min(1.0, (budget_limit - cost_today) / budget_limit))
    else:
        cost_budget_ratio = max(0.0, min(1.0, total_cost / 25.0))
        savings_rate = max(0.0, min(1.0, 1.0 - cost_budget_ratio))
    return {
        "block_rate": block_rate,
        "threat_frequency": threat_frequency,
        "cost_budget_ratio": cost_budget_ratio,
        "savings_rate": savings_rate,
        "cache_hit_rate": max(0.0, min(1.0, float(cache_hit_rate))),
        "loop_frequency": loop_frequency,
        "error_rate": error_rate,
        "latency_ms": latency_ms,
    }
