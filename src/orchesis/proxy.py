"""FastAPI proxy layer using Orchesis rule engine."""

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
import json
import os
import threading
import time
from typing import Any
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from orchesis.contrib.secret_scanner import SecretScanner
from orchesis.config import PolicyWatcher, load_policy
from orchesis.engine import evaluate
from orchesis.events import EventBus
from orchesis.forensics import Incident
from orchesis.integrations import SlackEmitter, SlackNotifier, TelegramEmitter, TelegramNotifier
from orchesis.integrations.forensics_emitter import ForensicsEmitter
from orchesis.metrics import MetricsCollector
from orchesis.otel import OTelEmitter, TraceContext
from orchesis.policy_store import PolicyStore
from orchesis.state import RateLimitTracker
from orchesis.structured_log import StructuredLogger
from orchesis.telemetry import JsonlEmitter
from orchesis.webhooks import WebhookConfig, WebhookEmitter


@dataclass
class ProxyConfig:
    listen_host: str = "127.0.0.1"
    listen_port: int = 8100
    upstream_url: str | None = None
    intercept_mode: str = "tool_call"
    timeout_seconds: float = 30.0
    max_body_size: int = 10_000_000
    log_decisions: bool = True
    buffer_responses: bool = True


@dataclass
class ProxyStats:
    """Runtime statistics for asyncio proxy mode."""

    requests_total: int = 0
    requests_allowed: int = 0
    requests_denied: int = 0
    requests_passthrough: int = 0
    requests_error: int = 0
    bytes_proxied: int = 0
    avg_latency_ms: float = 0.0
    start_time: float = field(default_factory=time.time)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            uptime = max(0.0, time.time() - self.start_time)
            return {
                "requests_total": self.requests_total,
                "requests_allowed": self.requests_allowed,
                "requests_denied": self.requests_denied,
                "requests_passthrough": self.requests_passthrough,
                "requests_error": self.requests_error,
                "bytes_proxied": self.bytes_proxied,
                "avg_latency_ms": self.avg_latency_ms,
                "uptime_seconds": int(uptime),
            }

    def record_request(self, decision: str, latency_ms: float, bytes_count: int) -> None:
        with self._lock:
            self.requests_total += 1
            label = (decision or "").upper()
            if label == "ALLOW":
                self.requests_allowed += 1
            elif label == "DENY":
                self.requests_denied += 1
            elif label == "PASSTHROUGH":
                self.requests_passthrough += 1
            elif label == "ERROR":
                self.requests_error += 1
            self.bytes_proxied += max(0, int(bytes_count))
            if self.requests_total == 1:
                self.avg_latency_ms = max(0.0, float(latency_ms))
            else:
                prev = self.avg_latency_ms
                n = float(self.requests_total)
                self.avg_latency_ms = ((prev * (n - 1.0)) + max(0.0, float(latency_ms))) / n


class OrchesisProxy:
    """Asyncio HTTP proxy that can enforce Orchesis policy checks."""

    def __init__(self, engine, config: ProxyConfig, event_bus=None, redactor=None):
        self._engine = engine
        self._config = config
        self._event_bus = event_bus
        self._redactor = redactor
        self._stats = ProxyStats()
        self._server: asyncio.base_events.Server | None = None
        self._secret_scanner = SecretScanner()

    @property
    def stats(self) -> ProxyStats:
        return self._stats

    async def start(self):
        self._server = await asyncio.start_server(
            self.handle_request,
            host=self._config.listen_host,
            port=self._config.listen_port,
        )
        return self._server

    async def stop(self):
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def handle_request(self, reader, writer):
        started = time.perf_counter()
        decision_label = "ERROR"
        bytes_count = 0
        try:
            parsed = await self._read_http_request(reader)
            if parsed is None:
                writer.write(self._build_error_response(400, "bad_request", "Malformed HTTP request"))
                await writer.drain()
                decision_label = "ERROR"
                return
            method, path, headers, body = parsed
            bytes_count = len(body)

            if len(body) > self._config.max_body_size:
                writer.write(self._build_error_response(413, "payload_too_large", "Request body too large"))
                await writer.drain()
                decision_label = "ERROR"
                return

            tool_call = self._extract_tool_call(method, path, headers, body)
            allowed = True
            deny_reason = "blocked_by_policy"
            deny_rule = "policy"
            deny_severity = "medium"
            if self._config.intercept_mode != "passthrough":
                if self._config.intercept_mode == "all":
                    payload = {
                        "tool": tool_call[0] if tool_call else f"http_{method.lower()}",
                        "params": tool_call[1] if tool_call else {"path": path, "method": method},
                        "context": {"path": path, "method": method, "agent": headers.get("x-agent", "proxy_agent")},
                        "cost": 0.0,
                    }
                    decision = self._evaluate(payload)
                    allowed = bool(getattr(decision, "allowed", True))
                    if not allowed:
                        reason, rule, severity = self._extract_reason_rule_severity(decision)
                        deny_reason, deny_rule, deny_severity = reason, rule, severity
                elif tool_call is not None:
                    payload = {
                        "tool": tool_call[0],
                        "params": tool_call[1],
                        "context": {"path": path, "method": method, "agent": headers.get("x-agent", "proxy_agent")},
                        "cost": 0.0,
                    }
                    decision = self._evaluate(payload)
                    allowed = bool(getattr(decision, "allowed", True))
                    if not allowed:
                        reason, rule, severity = self._extract_reason_rule_severity(decision)
                        deny_reason, deny_rule, deny_severity = reason, rule, severity
                else:
                    decision_label = "PASSTHROUGH"

            if self._config.intercept_mode == "passthrough":
                decision_label = "PASSTHROUGH"

            if not allowed and self._config.intercept_mode != "passthrough":
                writer.write(self._build_deny_response(deny_reason, deny_rule, deny_severity))
                await writer.drain()
                decision_label = "DENY"
                self._emit_event(
                    {
                        "event": "proxy_decision",
                        "decision": "DENY",
                        "rule": deny_rule,
                        "reason": deny_reason,
                        "path": path,
                        "method": method,
                    }
                )
                return

            status, resp_headers, resp_body = await self._forward_request(method, path, headers, body)
            if self._config.buffer_responses and tool_call is not None:
                self._scan_response(tool_call[0], resp_body)

            response_bytes = self._build_response_bytes(status, resp_headers, resp_body)
            writer.write(response_bytes)
            await writer.drain()
            if decision_label not in {"PASSTHROUGH", "DENY"}:
                decision_label = "ALLOW"
            self._emit_event(
                {
                    "event": "proxy_decision",
                    "decision": decision_label,
                    "path": path,
                    "method": method,
                    "status": status,
                }
            )
        except Exception:
            try:
                writer.write(self._build_error_response(400, "bad_request", "Malformed HTTP request"))
                await writer.drain()
            except Exception:
                pass
            decision_label = "ERROR"
        finally:
            latency_ms = (time.perf_counter() - started) * 1000.0
            self._stats.record_request(decision_label, latency_ms, bytes_count)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def _extract_tool_call(
        self, method: str, path: str, headers: dict[str, str], body: bytes
    ) -> tuple[str, dict[str, Any]] | None:
        if method.upper() != "POST":
            return None
        parsed: dict[str, Any] | None = None
        content_type = headers.get("content-type", "").lower()
        if body and ("json" in content_type or content_type == ""):
            try:
                loaded = json.loads(body.decode("utf-8"))
                if isinstance(loaded, dict):
                    parsed = loaded
            except Exception:
                parsed = None

        if parsed is not None:
            tool_name = parsed.get("tool_name")
            params = parsed.get("params")
            if isinstance(tool_name, str) and isinstance(params, dict):
                return tool_name, params

            function_name = parsed.get("function")
            arguments = parsed.get("arguments")
            if isinstance(function_name, str) and isinstance(arguments, dict):
                return function_name, arguments

            action = parsed.get("action")
            input_params = parsed.get("input")
            if isinstance(action, str) and isinstance(input_params, dict):
                return action, input_params

            if parsed.get("method") == "tools/call":
                rpc_params = parsed.get("params")
                if isinstance(rpc_params, dict):
                    name = rpc_params.get("name")
                    args = rpc_params.get("arguments")
                    if isinstance(name, str):
                        return name, args if isinstance(args, dict) else {}

            jsonrpc_method = parsed.get("method")
            if parsed.get("jsonrpc") == "2.0" and isinstance(jsonrpc_method, str):
                rpc_params = parsed.get("params")
                return jsonrpc_method, rpc_params if isinstance(rpc_params, dict) else {}

        parts = [item for item in path.split("/") if item]
        if len(parts) >= 2 and parts[0] == "tools":
            tool_name = parts[1]
            params: dict[str, Any] = {}
            if body:
                try:
                    loaded = json.loads(body.decode("utf-8"))
                    if isinstance(loaded, dict):
                        params = loaded
                except Exception:
                    params = {}
            return tool_name, params
        return None

    def _build_deny_response(self, reason: str, rule: str, severity: str = "medium") -> bytes:
        payload = {
            "error": "blocked_by_policy",
            "reason": reason,
            "rule": rule,
            "severity": severity,
            "documentation": "https://orchesis.dev/docs/policies",
        }
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        lines = [
            "HTTP/1.1 403 Forbidden",
            "Content-Type: application/json",
            f"Content-Length: {len(body)}",
            "Connection: close",
            "X-Orchesis-Decision: DENY",
            f"X-Orchesis-Rule: {rule}",
            "",
            "",
        ]
        return "\r\n".join(lines).encode("utf-8") + body

    async def _forward_request(
        self, method: str, path: str, headers: dict[str, str], body: bytes
    ) -> tuple[int, dict[str, str], bytes]:
        upstream = self._config.upstream_url
        if not isinstance(upstream, str) or not upstream.strip():
            return 502, {"content-type": "application/json"}, b'{"error":"upstream_not_configured"}'

        parsed = urlsplit(upstream)
        if parsed.scheme not in {"http"}:
            return 502, {"content-type": "application/json"}, b'{"error":"unsupported_upstream_scheme"}'
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 80
        base_path = parsed.path or ""
        target_path = path if path.startswith("/") else f"/{path}"
        full_path = f"{base_path}{target_path}"

        req_headers = dict(headers)
        req_headers["host"] = f"{host}:{port}"
        req_headers["connection"] = "close"
        req_headers["content-length"] = str(len(body))

        request_head = [f"{method} {full_path} HTTP/1.1"]
        for key, value in req_headers.items():
            if key.lower() in {"proxy-connection"}:
                continue
            request_head.append(f"{key}: {value}")
        request_bytes = ("\r\n".join(request_head) + "\r\n\r\n").encode("utf-8") + body

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self._config.timeout_seconds,
            )
        except Exception:
            return 502, {"content-type": "application/json"}, b'{"error":"upstream_connection_failed"}'

        try:
            writer.write(request_bytes)
            await asyncio.wait_for(writer.drain(), timeout=self._config.timeout_seconds)
            response = await self._read_http_response(reader)
            if response is None:
                return 502, {"content-type": "application/json"}, b'{"error":"invalid_upstream_response"}'
            return response
        except Exception:
            return 502, {"content-type": "application/json"}, b'{"error":"upstream_timeout"}'
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def _scan_response(self, tool_name: str, response_body: bytes) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        try:
            text = response_body.decode("utf-8", errors="ignore")
            findings = self._secret_scanner.scan_text(text)
            if findings:
                self._emit_event(
                    {
                        "event": "proxy_response_scan",
                        "tool": tool_name,
                        "findings": findings[:10],
                        "count": len(findings),
                    }
                )
        except Exception:
            return []
        return findings

    def _evaluate(self, payload: dict[str, Any]):
        if hasattr(self._engine, "evaluate"):
            return self._engine.evaluate(payload)
        if callable(self._engine):
            return self._engine(payload)
        raise TypeError("Proxy engine must be callable or provide evaluate().")

    def _emit_event(self, event: dict[str, Any]) -> None:
        if self._event_bus is None:
            return
        try:
            self._event_bus.emit(event)
        except Exception:
            pass

    def _extract_reason_rule_severity(self, decision) -> tuple[str, str, str]:
        reasons = getattr(decision, "reasons", [])
        reason = reasons[0] if isinstance(reasons, list) and reasons else "blocked_by_policy"
        rule = reason.split(":", 1)[0] if ":" in reason else "policy"
        severity = "high" if "daily token budget" in reason.lower() else "medium"
        return reason, rule, severity

    async def _read_http_request(
        self, reader
    ) -> tuple[str, str, dict[str, str], bytes] | None:
        header_bytes = await self._read_headers(reader)
        if header_bytes is None:
            return None
        try:
            header_text = header_bytes.decode("iso-8859-1")
            lines = header_text.split("\r\n")
            request_line = lines[0]
            method, path, _http = request_line.split(" ", 2)
            headers: dict[str, str] = {}
            for line in lines[1:]:
                if not line:
                    continue
                if ":" not in line:
                    return None
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()
            content_length = int(headers.get("content-length", "0") or "0")
            if content_length < 0:
                return None
            if content_length > self._config.max_body_size:
                return method, path, headers, b"x" * (self._config.max_body_size + 1)
            body = b""
            if content_length > 0:
                body = await asyncio.wait_for(
                    reader.readexactly(content_length),
                    timeout=self._config.timeout_seconds,
                )
            return method, path, headers, body
        except Exception:
            return None

    async def _read_http_response(
        self, reader
    ) -> tuple[int, dict[str, str], bytes] | None:
        header_bytes = await self._read_headers(reader)
        if header_bytes is None:
            return None
        try:
            header_text = header_bytes.decode("iso-8859-1")
            lines = header_text.split("\r\n")
            status_line = lines[0]
            _http, status_code, _rest = status_line.split(" ", 2)
            headers: dict[str, str] = {}
            for line in lines[1:]:
                if not line:
                    continue
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()
            content_length = int(headers.get("content-length", "0") or "0")
            if content_length > 0:
                body = await asyncio.wait_for(
                    reader.readexactly(content_length),
                    timeout=self._config.timeout_seconds,
                )
            else:
                body = await asyncio.wait_for(reader.read(), timeout=self._config.timeout_seconds)
            return int(status_code), headers, body
        except Exception:
            return None

    async def _read_headers(self, reader) -> bytes | None:
        try:
            raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=self._config.timeout_seconds)
            return raw[:-4]
        except Exception:
            return None

    def _build_error_response(self, status: int, error: str, message: str) -> bytes:
        reasons = {400: "Bad Request", 413: "Payload Too Large", 502: "Bad Gateway"}
        phrase = reasons.get(status, "Error")
        payload = {"error": error, "message": message}
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        lines = [
            f"HTTP/1.1 {status} {phrase}",
            "Content-Type: application/json",
            f"Content-Length: {len(body)}",
            "Connection: close",
            "",
            "",
        ]
        return "\r\n".join(lines).encode("utf-8") + body

    def _build_response_bytes(self, status: int, headers: dict[str, str], body: bytes) -> bytes:
        phrase_map = {
            200: "OK",
            201: "Created",
            204: "No Content",
            400: "Bad Request",
            403: "Forbidden",
            404: "Not Found",
            500: "Internal Server Error",
            502: "Bad Gateway",
        }
        phrase = phrase_map.get(status, "OK")
        merged = dict(headers)
        merged["content-length"] = str(len(body))
        merged["connection"] = "close"
        merged["x-orchesis-decision"] = "ALLOW"
        head = [f"HTTP/1.1 {status} {phrase}"]
        for key, value in merged.items():
            head.append(f"{key}: {value}")
        return ("\r\n".join(head) + "\r\n\r\n").encode("utf-8") + body


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


def _extract_context(request: Request, body_json: dict[str, Any] | None) -> dict[str, Any]:
    context: dict[str, Any] = {"method": request.method, "path": request.url.path}
    if body_json and isinstance(body_json.get("context"), dict):
        context.update(body_json["context"])
    agent_header = request.headers.get("x-agent")
    if isinstance(agent_header, str) and agent_header.strip():
        context["agent"] = agent_header.strip()
    session_header = request.headers.get("x-session")
    if isinstance(session_header, str) and session_header.strip():
        context["session"] = session_header.strip()
    return context


def create_proxy_app(
    policy: dict[str, Any],
    *,
    policy_path: str | None = None,
    backend_url: str = "http://backend",
    backend_app: FastAPI | None = None,
    backend_transport: httpx.AsyncBaseTransport | None = None,
) -> FastAPI:
    """Create a proxy app that evaluates rules before forwarding requests."""
    logger = StructuredLogger("proxy")
    transport = backend_transport
    if transport is None and backend_app is not None:
        transport = httpx.ASGITransport(app=backend_app)
    state_tracker = RateLimitTracker(persist_path=None)
    app_started_at = time.perf_counter()
    store = PolicyStore()
    current_policy = policy
    current_registry = None
    watcher: PolicyWatcher | None = None
    current_policy_hash = "inline"
    event_bus = EventBus()
    metrics = MetricsCollector()
    decisions_log_path = os.getenv("DECISIONS_LOG_PATH", ".orchesis/decisions.jsonl")
    _ = event_bus.subscribe(JsonlEmitter(decisions_log_path))
    _ = event_bus.subscribe(metrics)
    _ = event_bus.subscribe(OTelEmitter(".orchesis/traces.jsonl"))
    webhook_subscriber_ids: list[int] = []
    alert_subscriber_ids: list[int] = []
    alert_notifiers: list[Any] = []
    _ = event_bus.subscribe(
        ForensicsEmitter(
            incidents_path=".orchesis/incidents.jsonl",
            alert_callback=lambda incident: _dispatch_incident_alert(incident),
        )
    )

    def _dispatch_incident_alert(incident: Incident) -> None:
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

    def _sync_webhooks(candidate_policy: dict[str, Any]) -> None:
        nonlocal webhook_subscriber_ids
        for sub_id in webhook_subscriber_ids:
            event_bus.unsubscribe(sub_id)
        webhook_subscriber_ids = []

        webhooks = candidate_policy.get("webhooks")
        if not isinstance(webhooks, list):
            return
        for item in webhooks:
            if not isinstance(item, dict):
                continue
            url = item.get("url")
            if not isinstance(url, str) or not url.strip():
                continue
            events = item.get("events")
            headers = item.get("headers")
            timeout = item.get("timeout_seconds")
            retry = item.get("retry_count")
            secret = item.get("secret")
            config = WebhookConfig(
                url=url.strip(),
                events=events if isinstance(events, list) else ["DENY"],
                headers=headers if isinstance(headers, dict) else {},
                timeout_seconds=float(timeout) if isinstance(timeout, int | float) else 5.0,
                retry_count=int(retry) if isinstance(retry, int) else 2,
                secret=secret if isinstance(secret, str) else None,
            )
            webhook_subscriber_ids.append(event_bus.subscribe(WebhookEmitter(config)))

    def _resolve_registry_for_policy(candidate_policy: dict[str, Any], store_version: Any) -> Any:
        has_identity_config = (
            "agents" in candidate_policy or "default_trust_tier" in candidate_policy
        )
        return store_version.registry if has_identity_config else None

    def _sync_alerts(candidate_policy: dict[str, Any]) -> None:
        nonlocal alert_subscriber_ids
        alert_notifiers.clear()
        for sub_id in alert_subscriber_ids:
            event_bus.unsubscribe(sub_id)
        alert_subscriber_ids = []
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
                    notify_on=slack_cfg.get("notify_on")
                    if isinstance(slack_cfg.get("notify_on"), list)
                    else None,
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

    if policy_path is not None:
        current_version = store.load(policy_path)
        current_policy = current_version.policy
        current_registry = _resolve_registry_for_policy(current_policy, current_version)
        current_policy_hash = current_version.version_id
        _sync_webhooks(current_policy)
        _sync_alerts(current_policy)

        def _on_reload(new_policy: dict[str, Any]) -> None:
            _ = new_policy
            nonlocal current_policy, current_registry, current_policy_hash
            version = store.load(policy_path)
            current_policy = version.policy
            current_registry = _resolve_registry_for_policy(current_policy, version)
            current_policy_hash = version.version_id
            _sync_webhooks(current_policy)
            _sync_alerts(current_policy)

        watcher = PolicyWatcher(policy_path, _on_reload)
        watcher._last_hash = PolicyWatcher(policy_path, lambda _policy: None).current_hash()
    else:
        _sync_webhooks(current_policy)
        _sync_alerts(current_policy)

    @asynccontextmanager
    async def _lifespan(_app: FastAPI):
        try:
            yield
        finally:
            state_tracker.flush()

    app = FastAPI(title="Orchesis Proxy", lifespan=_lifespan)
    app.state.event_bus = event_bus
    app.state.metrics = metrics

    @app.middleware("http")
    async def decision_middleware(request: Request, call_next: Any) -> Response:
        nonlocal current_policy_hash
        trace = TraceContext.from_headers(dict(request.headers))
        if request.url.path in {"/metrics", "/health"}:
            response = await call_next(request)
            response.headers["X-Orchesis-Trace-Id"] = trace.trace_id
            return response

        if watcher is not None:
            old_hash = current_policy_hash
            if watcher.check():
                logger.info(
                    "policy reloaded", old_version=old_hash, new_version=current_policy_hash
                )

        raw_body = await request.body()
        body_json: dict[str, Any] | None = None
        if raw_body:
            try:
                parsed = await request.json()
                if isinstance(parsed, dict):
                    body_json = parsed
            except ValueError:
                body_json = None

        context = _extract_context(request, body_json)
        context["trace_id"] = trace.trace_id
        if trace.parent_span_id:
            context["parent_span_id"] = trace.parent_span_id
        eval_request = {
            "tool": _extract_tool(request, body_json),
            "params": _extract_params(request, body_json),
            "cost": _extract_cost(request, body_json),
            "context": context,
        }
        decision = evaluate(
            eval_request,
            current_policy,
            state=state_tracker,
            emitter=event_bus,
            registry=current_registry,
        )

        if not decision.allowed:
            response = JSONResponse(
                status_code=403,
                content={
                    "allowed": False,
                    "reasons": decision.reasons,
                    "rules_checked": decision.rules_checked,
                },
            )
            response.headers["X-Orchesis-Trace-Id"] = trace.trace_id
            response.headers["X-Orchesis-Decision"] = "DENY"
            return response

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

        response = Response(
            content=forwarded.content,
            status_code=forwarded.status_code,
            media_type=forwarded.headers.get("content-type"),
        )
        response.headers["X-Orchesis-Trace-Id"] = trace.trace_id
        response.headers["X-Orchesis-Decision"] = "ALLOW"
        return response

    @app.get("/metrics")
    def metrics_endpoint() -> Response:
        return Response(content=metrics.prometheus_text(), media_type="text/plain")

    @app.get("/health")
    def health_endpoint() -> dict[str, Any]:
        snapshot = metrics.snapshot()
        total_decisions = 0
        counters = snapshot.get("counters")
        if isinstance(counters, dict):
            for key, value in counters.items():
                if isinstance(key, str) and key.startswith("orchesis_decisions_total|decision="):
                    if isinstance(value, int):
                        total_decisions += value
        return {
            "status": "healthy",
            "version": "0.6.0",
            "policy_version": current_policy_hash,
            "uptime_seconds": int(max(0.0, time.perf_counter() - app_started_at)),
            "total_decisions": total_decisions,
        }

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
    return create_proxy_app(policy=policy, policy_path=policy_path, backend_url=backend_url)


app = build_app_from_env()
