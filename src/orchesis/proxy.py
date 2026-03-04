"""FastAPI proxy layer using Orchesis rule engine."""

import asyncio
from collections import deque
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import logging
import os
import threading
import time
import uuid
from typing import Any
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request as UrlRequest, urlopen
from urllib.error import HTTPError, URLError
from http.server import HTTPServer, BaseHTTPRequestHandler

try:
    import httpx
except ModuleNotFoundError:  # pragma: no cover - optional dependency path
    httpx = None  # type: ignore[assignment]

try:
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse, Response
except ModuleNotFoundError:  # pragma: no cover - optional dependency path
    FastAPI = Any  # type: ignore[assignment]
    Request = Any  # type: ignore[assignment]
    JSONResponse = Any  # type: ignore[assignment]
    Response = Any  # type: ignore[assignment]

from orchesis.auth import AgentAuthenticator, CredentialStore
from orchesis.behavioral import BehavioralDetector, extract_agent_id
from orchesis.cost_tracker import CostTracker
from orchesis.circuit_breaker import CircuitBreaker
from orchesis.credential_injector import CredentialInjector
from orchesis.credential_vault import CredentialNotFoundError, build_vault_from_policy
from orchesis.contrib.pii_detector import PiiDetector
from orchesis.contrib.secret_scanner import SecretScanner
from orchesis.config import PolicyWatcher, load_policy
from orchesis.engine import evaluate
from orchesis.events import EventBus
from orchesis.forensics import Incident
from orchesis.integrations import SlackEmitter, SlackNotifier, TelegramEmitter, TelegramNotifier
from orchesis.integrations.forensics_emitter import ForensicsEmitter
from orchesis.loop_detector import LoopDetector
from orchesis.metrics import MetricsCollector
from orchesis.model_router import ModelRouter
from orchesis.cascade import CascadeDecision, CascadeLevel, CascadeRouter
from orchesis.otel import OTelEmitter, TraceContext
from orchesis.policy_store import PolicyStore
from orchesis.state import RateLimitTracker
from orchesis.structured_log import StructuredLogger
from orchesis.telemetry import JsonlEmitter
from orchesis.webhooks import WebhookConfig, WebhookEmitter
from orchesis.request_parser import ParsedResponse, parse_request, parse_response
from orchesis.recorder import SessionRecord, SessionRecorder
from orchesis.response_handler import ResponseProcessor, SECRET_PATTERNS
from orchesis.flow_xray import FlowAnalyzer, FlowXRayConfig
from orchesis.dashboard import get_dashboard_html
from orchesis.air_export import export_session_to_air
from orchesis import __version__ as ORCHESIS_VERSION
from orchesis.compliance import ComplianceEngine, Framework, Severity

_HTTP_PROXY_LOGGER = logging.getLogger("orchesis.http_proxy")


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
    secrets_detected: int = 0
    secrets_blocked: int = 0
    pii_detected: int = 0
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
                "secrets_detected": self.secrets_detected,
                "secrets_blocked": self.secrets_blocked,
                "pii_detected": self.pii_detected,
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

    def record_detection(self, *, secrets_detected: int = 0, secrets_blocked: int = 0, pii_detected: int = 0) -> None:
        with self._lock:
            self.secrets_detected += max(0, int(secrets_detected))
            self.secrets_blocked += max(0, int(secrets_blocked))
            self.pii_detected += max(0, int(pii_detected))


_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class OrchesisProxy:
    """Asyncio HTTP proxy that can enforce Orchesis policy checks."""

    def __init__(self, engine, config: ProxyConfig, event_bus=None, redactor=None, policy: dict[str, Any] | None = None):
        self._engine = engine
        self._config = config
        self._event_bus = event_bus
        self._redactor = redactor
        self._policy = policy if isinstance(policy, dict) else {}
        self._stats = ProxyStats()
        self._server: asyncio.base_events.Server | None = None
        behavioral_cfg = self._policy.get("behavioral_fingerprint")
        self._behavioral_cfg = behavioral_cfg if isinstance(behavioral_cfg, dict) else {}
        self._behavioral_detector = BehavioralDetector(self._behavioral_cfg)
        recording_cfg = self._policy.get("recording")
        self._recording_cfg = recording_cfg if isinstance(recording_cfg, dict) else {}
        self._recorder = (
            SessionRecorder(
                storage_path=str(self._recording_cfg.get("storage_path", ".orchesis/sessions")),
                compress=bool(self._recording_cfg.get("compress", True)),
                max_file_size_mb=int(self._recording_cfg.get("max_file_size_mb", 10)),
            )
            if bool(self._recording_cfg.get("enabled", False))
            else None
        )
        compliance_cfg = self._policy.get("compliance")
        self._compliance_cfg = compliance_cfg if isinstance(compliance_cfg, dict) else {}
        framework_tokens = self._compliance_cfg.get("frameworks", ["owasp_llm_top10", "nist_ai_rmf"])
        resolved_frameworks: list[Framework] = []
        if isinstance(framework_tokens, list):
            for token in framework_tokens:
                framework = ComplianceEngine._framework_from_alias(token if isinstance(token, str) else None)
                if framework is not None and framework not in resolved_frameworks:
                    resolved_frameworks.append(framework)
        if not resolved_frameworks:
            resolved_frameworks = [Framework.OWASP_LLM_TOP_10, Framework.NIST_AI_RMF]
        self._compliance_engine = ComplianceEngine(
            policy_path="policy.yaml",
            frameworks=resolved_frameworks,
            max_findings=int(self._compliance_cfg.get("max_findings", 10000)),
            enabled=bool(self._compliance_cfg.get("enabled", True)),
        )
        self._compliance_enabled = bool(self._compliance_cfg.get("enabled", True))
        proxy_cfg = self._policy.get("proxy") if isinstance(self._policy.get("proxy"), dict) else {}
        secret_cfg = proxy_cfg.get("secret_scanning") if isinstance(proxy_cfg.get("secret_scanning"), dict) else {}
        pii_cfg = proxy_cfg.get("pii_scanning") if isinstance(proxy_cfg.get("pii_scanning"), dict) else {}
        redaction_cfg = (
            proxy_cfg.get("response_redaction")
            if isinstance(proxy_cfg.get("response_redaction"), dict)
            else {}
        )
        self._scan_requests = bool(proxy_cfg.get("scan_requests", True))
        self._scan_responses = bool(proxy_cfg.get("scan_responses", True))
        self._secret_enabled = bool(secret_cfg.get("enabled", True))
        self._secret_threshold = str(secret_cfg.get("severity_threshold", "high")).lower()
        self._secret_block_on_critical = bool(secret_cfg.get("block_on_critical", False))
        self._pii_enabled = bool(pii_cfg.get("enabled", True))
        self._pii_threshold = str(pii_cfg.get("severity_threshold", "medium")).lower()
        self._pii_block_on_critical = bool(pii_cfg.get("block_on_critical", False))
        self._response_redaction_enabled = bool(redaction_cfg.get("enabled", False))
        self._response_redact_secrets = bool(redaction_cfg.get("redact_secrets", True))
        self._response_redact_pii = bool(redaction_cfg.get("redact_pii", False))
        self._secret_scanner = SecretScanner()
        self._pii_detector = PiiDetector(severity_threshold=self._pii_threshold)
        self._credential_injector: CredentialInjector | None = None
        try:
            credentials_cfg = self._policy.get("credentials")
            if isinstance(credentials_cfg, dict):
                vault = build_vault_from_policy(self._policy)
                self._credential_injector = CredentialInjector(credentials_cfg, vault)
        except Exception:
            self._credential_injector = None

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
            behavior_state_header = "normal"
            anomaly_score_header = ""
            anomaly_dimensions_header = ""

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

            if self._scan_requests and self._secret_enabled and tool_call is not None:
                request_findings = self._scan_request(tool_call[0], tool_call[1])
                critical = [item for item in request_findings if str(item.get("severity", "")).lower() == "critical"]
                if critical and self._secret_block_on_critical:
                    self._stats.record_detection(
                        secrets_detected=len(request_findings),
                        secrets_blocked=len(critical),
                    )
                    writer.write(
                        self._build_deny_response(
                            "credential_leak_in_request",
                            "credential_leak_in_request",
                            "high",
                        )
                    )
                    await writer.drain()
                    decision_label = "DENY"
                    self._emit_event(
                        {
                            "event": "proxy_decision",
                            "decision": "DENY",
                            "rule": "credential_leak_in_request",
                            "reason": "credential_leak_in_request",
                            "path": path,
                            "method": method,
                            "findings": request_findings[:10],
                        }
                    )
                    return

            body_json: dict[str, Any] | None = None
            if body:
                try:
                    loaded = json.loads(body.decode("utf-8"))
                    if isinstance(loaded, dict):
                        body_json = loaded
                except Exception:
                    body_json = None

            if self._behavioral_detector.enabled:
                request_data = {
                    "model": (body_json or {}).get("model", ""),
                    "messages": (body_json or {}).get("messages", []),
                    "tools": (body_json or {}).get("tools", []),
                    "estimated_cost": 0.0,
                    "headers": headers,
                }
                agent_id = extract_agent_id(request_data)
                behavior_decision = self._behavioral_detector.check_request(agent_id, request_data)
                if behavior_decision.action == "block":
                    payload = {
                        "error": "behavioral_anomaly",
                        "anomalies": [asdict(item) for item in behavior_decision.anomalies],
                    }
                    body_block = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                    writer.write(
                        self._build_response_bytes(
                            429,
                            {
                                "content-type": "application/json",
                                "x-orchesis-behavior": "anomaly",
                                "x-orchesis-anomaly-score": str(behavior_decision.anomaly_score),
                                "x-orchesis-anomaly-dimensions": ",".join(
                                    sorted({item.dimension for item in behavior_decision.anomalies})
                                ),
                            },
                            body_block,
                            decision="DENY",
                        )
                    )
                    await writer.drain()
                    decision_label = "DENY"
                    return
                if behavior_decision.action == "learning":
                    behavior_state_header = "learning"
                elif behavior_decision.anomalies:
                    behavior_state_header = "anomaly"
                    anomaly_score_header = str(behavior_decision.anomaly_score)
                    anomaly_dimensions_header = ",".join(
                        sorted({item.dimension for item in behavior_decision.anomalies})
                    )

            if self._credential_injector is not None and tool_call is not None:
                try:
                    injected_call, aliases = self._credential_injector.inject(
                        {"tool_name": tool_call[0], "params": tool_call[1], "headers": headers}
                    )
                except CredentialNotFoundError:
                    writer.write(
                        self._build_deny_response(
                            "credential_injection_failed",
                            "credential_injection_failed",
                            "high",
                        )
                    )
                    await writer.drain()
                    decision_label = "DENY"
                    return
                tool_call = (
                    str(injected_call.get("tool_name", tool_call[0])),
                    dict(injected_call.get("params", tool_call[1])),
                )
                headers = dict(injected_call.get("headers", headers))
                body = self._apply_params_to_body(path, body, tool_call[1])
                if aliases:
                    self._emit_event(
                        {
                            "event": "proxy_credentials_injected",
                            "tool": tool_call[0],
                            "aliases": aliases,
                        }
                    )

            status, resp_headers, resp_body = await self._forward_request(method, path, headers, body)
            if self._behavioral_detector.enabled:
                completion_tokens = 0
                try:
                    decoded = json.loads(resp_body.decode("utf-8"))
                    if isinstance(decoded, dict):
                        usage = decoded.get("usage")
                        if isinstance(usage, dict):
                            completion_tokens = int(
                                usage.get("completion_tokens")
                                or usage.get("output_tokens")
                                or 0
                            )
                except Exception:
                    completion_tokens = 0
                self._behavioral_detector.record_response(
                    extract_agent_id({"headers": headers, "model": (body_json or {}).get("model", "")}),
                    is_error=status >= 400,
                    completion_tokens=completion_tokens,
                )
            if self._config.buffer_responses and tool_call is not None and self._scan_responses:
                scan_result = self._scan_response_findings(tool_call[0], resp_body)
                secrets = scan_result["secrets"]
                pii = scan_result["pii"]
                self._stats.record_detection(
                    secrets_detected=len(secrets),
                    pii_detected=len(pii),
                )
                if self._response_redaction_enabled:
                    resp_body = self._redact_response_body(resp_body)
                    resp_headers = dict(resp_headers)
                    resp_headers["content-length"] = str(len(resp_body))
                if self._secret_block_on_critical and any(
                    str(item.get("severity", "")).lower() == "critical" for item in secrets
                ):
                    resp_body = self._redact_response_body(resp_body, force_secret_redaction=True)
                    self._stats.record_detection(secrets_blocked=1)
                if self._pii_block_on_critical and any(
                    str(item.get("severity", "")).lower() == "critical" for item in pii
                ):
                    resp_body = self._redact_response_body(resp_body, force_pii_redaction=True)
                if secrets or pii:
                    self._emit_event(
                        {
                            "event": "proxy_alert",
                            "decision": "ALERT",
                            "tool": tool_call[0],
                            "path": path,
                            "method": method,
                            "secret_findings": secrets[:10],
                            "pii_findings": pii[:10],
                        }
                    )

            response_bytes = self._build_response_bytes(status, resp_headers, resp_body)
            if self._behavioral_detector.enabled:
                resp_headers = dict(resp_headers)
                resp_headers["x-orchesis-behavior"] = behavior_state_header
                if anomaly_score_header:
                    resp_headers["x-orchesis-anomaly-score"] = anomaly_score_header
                if anomaly_dimensions_header:
                    resp_headers["x-orchesis-anomaly-dimensions"] = anomaly_dimensions_header
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

    def _apply_params_to_body(self, path: str, body: bytes, params: dict[str, Any]) -> bytes:
        if not body:
            return body
        try:
            loaded = json.loads(body.decode("utf-8"))
        except Exception:
            return body
        if not isinstance(loaded, dict):
            return body
        if isinstance(loaded.get("params"), dict):
            loaded["params"] = dict(params)
        elif isinstance(loaded.get("arguments"), dict):
            loaded["arguments"] = dict(params)
        elif isinstance(loaded.get("input"), dict):
            loaded["input"] = dict(params)
        elif loaded.get("method") == "tools/call" and isinstance(loaded.get("params"), dict):
            nested = dict(loaded.get("params"))
            nested["arguments"] = dict(params)
            loaded["params"] = nested
        elif loaded.get("jsonrpc") == "2.0" and isinstance(loaded.get("params"), dict):
            loaded["params"] = dict(params)
        else:
            parts = [item for item in path.split("/") if item]
            if len(parts) >= 2 and parts[0] == "tools":
                for key, value in params.items():
                    loaded[key] = value
        return json.dumps(loaded, ensure_ascii=False).encode("utf-8")

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

    def _scan_request(self, tool_name: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        try:
            findings = self._secret_scanner.scan_dict(params, path="params")
            if self._secret_threshold:
                threshold_rank = _SEVERITY_ORDER.get(self._secret_threshold, 3)
                findings = [
                    item
                    for item in findings
                    if _SEVERITY_ORDER.get(str(item.get("severity", "")).lower(), 0) >= threshold_rank
                ]
            if findings:
                self._emit_event(
                    {
                        "event": "proxy_request_scan",
                        "tool": tool_name,
                        "count": len(findings),
                        "findings": findings[:10],
                    }
                )
        except Exception:
            return []
        return findings

    def _scan_response_findings(self, tool_name: str, response_body: bytes) -> dict[str, list[dict[str, Any]]]:
        secret_findings: list[dict[str, Any]] = []
        pii_findings: list[dict[str, Any]] = []
        try:
            text = response_body.decode("utf-8", errors="ignore")
            if self._secret_enabled:
                secret_findings = self._secret_scanner.scan_text(text)
                if self._secret_threshold:
                    threshold_rank = _SEVERITY_ORDER.get(self._secret_threshold, 3)
                    secret_findings = [
                        item
                        for item in secret_findings
                        if _SEVERITY_ORDER.get(str(item.get("severity", "")).lower(), 0) >= threshold_rank
                    ]
            if self._pii_enabled:
                pii_findings = self._pii_detector.scan_text(text)
            if secret_findings or pii_findings:
                self._emit_event(
                    {
                        "event": "proxy_response_scan",
                        "tool": tool_name,
                        "secret_count": len(secret_findings),
                        "pii_count": len(pii_findings),
                        "secret_findings": secret_findings[:10],
                        "pii_findings": pii_findings[:10],
                    }
                )
        except Exception:
            return {"secrets": [], "pii": []}
        return {"secrets": secret_findings, "pii": pii_findings}

    def _redact_response_body(
        self,
        response_body: bytes,
        *,
        force_secret_redaction: bool = False,
        force_pii_redaction: bool = False,
    ) -> bytes:
        try:
            text = response_body.decode("utf-8", errors="ignore")
        except Exception:
            return response_body
        redact_secrets = self._response_redaction_enabled and self._response_redact_secrets
        redact_pii = self._response_redaction_enabled and self._response_redact_pii
        if force_secret_redaction:
            redact_secrets = True
        if force_pii_redaction:
            redact_pii = True
        if redact_secrets:
            findings = self._secret_scanner.scan_text(text)
            for finding in findings:
                raw_match = finding.get("raw_match")
                pattern = finding.get("pattern")
                if isinstance(raw_match, str) and raw_match:
                    text = text.replace(raw_match, f"[REDACTED-{pattern}]")
        if redact_pii:
            text = self._pii_detector.redact_text(text)
        return text.encode("utf-8")

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

    def _build_response_bytes(
        self, status: int, headers: dict[str, str], body: bytes, *, decision: str = "ALLOW"
    ) -> bytes:
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
        merged["x-orchesis-decision"] = decision
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
    behavioral_detector = BehavioralDetector(
        current_policy.get("behavioral_fingerprint")
        if isinstance(current_policy.get("behavioral_fingerprint"), dict)
        else {}
    )
    recording_cfg = current_policy.get("recording") if isinstance(current_policy.get("recording"), dict) else {}
    recorder = (
        SessionRecorder(
            storage_path=str(recording_cfg.get("storage_path", ".orchesis/sessions")),
            compress=bool(recording_cfg.get("compress", True)),
            max_file_size_mb=int(recording_cfg.get("max_file_size_mb", 10)),
        )
        if bool(recording_cfg.get("enabled", False))
        else None
    )
    current_registry = None
    watcher: PolicyWatcher | None = None
    current_policy_hash = "inline"
    authenticator: AgentAuthenticator | None = None
    auth_mode = "optional"
    credential_injector: CredentialInjector | None = None
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

    def _sync_auth(candidate_policy: dict[str, Any]) -> None:
        nonlocal authenticator, auth_mode
        auth_cfg = candidate_policy.get("authentication")
        if not isinstance(auth_cfg, dict) or not bool(auth_cfg.get("enabled", False)):
            authenticator = None
            auth_mode = "optional"
            return
        mode = str(auth_cfg.get("mode", "enforce")).lower()
        if mode not in {"enforce", "log", "optional"}:
            mode = "enforce"
        skew = auth_cfg.get("max_clock_skew", 300)
        credentials_file = auth_cfg.get("credentials_file", ".orchesis/credentials.yaml")
        store_obj = CredentialStore(str(credentials_file))
        authenticator = AgentAuthenticator(
            credentials=store_obj.load(),
            mode=mode,
            max_clock_skew=int(skew) if isinstance(skew, int | float) else 300,
        )
        auth_mode = mode

    def _sync_credentials(candidate_policy: dict[str, Any]) -> None:
        nonlocal credential_injector
        credentials_cfg = candidate_policy.get("credentials")
        if not isinstance(credentials_cfg, dict):
            credential_injector = None
            return
        try:
            vault = build_vault_from_policy(candidate_policy)
            credential_injector = CredentialInjector(credentials_cfg, vault)
        except Exception:
            credential_injector = None

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
        _sync_auth(current_policy)
        _sync_credentials(current_policy)

        def _on_reload(new_policy: dict[str, Any]) -> None:
            _ = new_policy
            nonlocal current_policy, current_registry, current_policy_hash, behavioral_detector, recorder, recording_cfg
            version = store.load(policy_path)
            current_policy = version.policy
            current_registry = _resolve_registry_for_policy(current_policy, version)
            current_policy_hash = version.version_id
            behavioral_detector = BehavioralDetector(
                current_policy.get("behavioral_fingerprint")
                if isinstance(current_policy.get("behavioral_fingerprint"), dict)
                else {}
            )
            recording_cfg = (
                current_policy.get("recording") if isinstance(current_policy.get("recording"), dict) else {}
            )
            recorder = (
                SessionRecorder(
                    storage_path=str(recording_cfg.get("storage_path", ".orchesis/sessions")),
                    compress=bool(recording_cfg.get("compress", True)),
                    max_file_size_mb=int(recording_cfg.get("max_file_size_mb", 10)),
                )
                if bool(recording_cfg.get("enabled", False))
                else None
            )
            _sync_webhooks(current_policy)
            _sync_alerts(current_policy)
            _sync_auth(current_policy)
            _sync_credentials(current_policy)

        watcher = PolicyWatcher(policy_path, _on_reload)
        watcher._last_hash = PolicyWatcher(policy_path, lambda _policy: None).current_hash()
    else:
        _sync_webhooks(current_policy)
        _sync_alerts(current_policy)
        _sync_auth(current_policy)
        _sync_credentials(current_policy)

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
        request_started = time.perf_counter()
        session_id = (
            request.headers.get("x-session")
            or request.headers.get("x-orchesis-session-id")
            or uuid.uuid4().hex
        )
        request_id = uuid.uuid4().hex
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
        extracted_tool = _extract_tool(request, body_json)
        extracted_params = _extract_params(request, body_json)
        if credential_injector is not None:
            aliases = credential_injector.matching_aliases(extracted_tool)
            if aliases:
                context["credentials_injected"] = aliases
        if authenticator is not None:
            auth_ok, verified_agent_id, auth_reason = authenticator.authenticate_request(
                {"tool": extracted_tool, "params": extracted_params},
                dict(request.headers),
            )
            if not auth_ok:
                if auth_mode == "enforce":
                    response = JSONResponse(
                        status_code=401,
                        content={"error": "unauthorized", "reason": auth_reason},
                    )
                    response.headers["X-Orchesis-Trace-Id"] = trace.trace_id
                    response.headers["X-Orchesis-Decision"] = "DENY"
                    if recorder is not None:
                        response.headers["X-Orchesis-Session-Id"] = session_id
                        response.headers["X-Orchesis-Request-Id"] = request_id
                    return response
                if auth_mode == "log":
                    logger.warn("authentication failed (log mode)", reason=auth_reason)
            elif verified_agent_id:
                context["agent"] = verified_agent_id
        eval_request = {
            "tool": extracted_tool,
            "params": extracted_params,
            "cost": _extract_cost(request, body_json),
            "context": context,
        }
        behavior_state = "normal"
        behavior_score = ""
        behavior_dimensions = ""
        if behavioral_detector.enabled:
            req_data = {
                "model": (body_json or {}).get("model", ""),
                "messages": (body_json or {}).get("messages", []),
                "tools": (body_json or {}).get("tools", []),
                "estimated_cost": float(eval_request["cost"]),
                "headers": dict(request.headers),
            }
            behavior_decision = behavioral_detector.check_request(
                extract_agent_id(req_data), req_data
            )
            if behavior_decision.action == "block":
                response = JSONResponse(
                    status_code=429,
                    content={
                        "error": "behavioral_anomaly",
                        "anomalies": [asdict(item) for item in behavior_decision.anomalies],
                    },
                )
                response.headers["X-Orchesis-Trace-Id"] = trace.trace_id
                response.headers["X-Orchesis-Behavior"] = "anomaly"
                response.headers["X-Orchesis-Anomaly-Score"] = str(behavior_decision.anomaly_score)
                response.headers["X-Orchesis-Anomaly-Dimensions"] = ",".join(
                    sorted({item.dimension for item in behavior_decision.anomalies})
                )
                response.headers["X-Orchesis-Decision"] = "DENY"
                if recorder is not None:
                    response.headers["X-Orchesis-Session-Id"] = session_id
                    response.headers["X-Orchesis-Request-Id"] = request_id
                return response
            if behavior_decision.action == "learning":
                behavior_state = "learning"
            elif behavior_decision.anomalies:
                behavior_state = "anomaly"
                behavior_score = str(behavior_decision.anomaly_score)
                behavior_dimensions = ",".join(
                    sorted({item.dimension for item in behavior_decision.anomalies})
                )
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
            if recorder is not None:
                response.headers["X-Orchesis-Session-Id"] = session_id
                response.headers["X-Orchesis-Request-Id"] = request_id
            return response

        forwarded_headers = {
            key: value for key, value in request.headers.items() if key.lower() != "host"
        }
        if credential_injector is not None:
            try:
                injected, aliases = credential_injector.inject(
                    {"tool_name": extracted_tool, "params": extracted_params, "headers": forwarded_headers}
                )
            except CredentialNotFoundError:
                response = JSONResponse(
                    status_code=403,
                    content={
                        "allowed": False,
                        "reasons": ["credential_injection_failed"],
                        "rules_checked": ["credential_injection"],
                    },
                )
                response.headers["X-Orchesis-Trace-Id"] = trace.trace_id
                response.headers["X-Orchesis-Decision"] = "DENY"
                if recorder is not None:
                    response.headers["X-Orchesis-Session-Id"] = session_id
                    response.headers["X-Orchesis-Request-Id"] = request_id
                return response
            injected_params = injected.get("params") if isinstance(injected.get("params"), dict) else extracted_params
            extracted_params = dict(injected_params)
            forwarded_headers = (
                dict(injected.get("headers"))
                if isinstance(injected.get("headers"), dict)
                else forwarded_headers
            )
            if aliases:
                context["credentials_injected"] = aliases
            if isinstance(body_json, dict):
                if isinstance(body_json.get("params"), dict):
                    body_json["params"] = dict(extracted_params)
                elif isinstance(body_json.get("arguments"), dict):
                    body_json["arguments"] = dict(extracted_params)
                elif isinstance(body_json.get("input"), dict):
                    body_json["input"] = dict(extracted_params)
                elif body_json.get("method") == "tools/call" and isinstance(body_json.get("params"), dict):
                    nested = dict(body_json.get("params"))
                    nested["arguments"] = dict(extracted_params)
                    body_json["params"] = nested
                elif body_json.get("jsonrpc") == "2.0" and isinstance(body_json.get("params"), dict):
                    body_json["params"] = dict(extracted_params)
                raw_body = json.dumps(body_json, ensure_ascii=False).encode("utf-8")

        target_path = request.url.path
        if request.url.query:
            target_path = f"{target_path}?{request.url.query}"

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
        if behavioral_detector.enabled:
            completion_tokens = 0
            try:
                parsed_fwd = forwarded.json()
                if isinstance(parsed_fwd, dict):
                    usage = parsed_fwd.get("usage")
                    if isinstance(usage, dict):
                        completion_tokens = int(
                            usage.get("completion_tokens")
                            or usage.get("output_tokens")
                            or 0
                        )
            except Exception:
                completion_tokens = 0
            behavioral_detector.record_response(
                extract_agent_id({"headers": dict(request.headers), "model": (body_json or {}).get("model", "")}),
                is_error=forwarded.status_code >= 400,
                completion_tokens=completion_tokens,
            )
        response.headers["X-Orchesis-Trace-Id"] = trace.trace_id
        response.headers["X-Orchesis-Decision"] = "ALLOW"
        if recorder is not None:
            response.headers["X-Orchesis-Session-Id"] = session_id
            response.headers["X-Orchesis-Request-Id"] = request_id
        if behavioral_detector.enabled:
            response.headers["X-Orchesis-Behavior"] = behavior_state
            if behavior_score:
                response.headers["X-Orchesis-Anomaly-Score"] = behavior_score
            if behavior_dimensions:
                response.headers["X-Orchesis-Anomaly-Dimensions"] = behavior_dimensions
        if recorder is not None:
            response_obj: dict[str, Any] | None = None
            try:
                parsed_content = json.loads(forwarded.content.decode("utf-8"))
                if isinstance(parsed_content, dict):
                    response_obj = parsed_content
            except Exception:
                response_obj = None
            include_response = bool(recording_cfg.get("include_response_body", True))
            exclude_models = recording_cfg.get("exclude_models", [])
            model_used = str((body_json or {}).get("model", ""))
            if not (isinstance(exclude_models, list) and model_used in exclude_models):
                recorder.record(
                    SessionRecord(
                        request_id=request_id,
                        session_id=session_id,
                        timestamp=time.time(),
                        request=body_json if isinstance(body_json, dict) else {},
                        response=response_obj if include_response else None,
                        status_code=forwarded.status_code,
                        provider="openai",
                        model=model_used,
                        latency_ms=(time.perf_counter() - request_started) * 1000.0,
                        cost=float(eval_request.get("cost", 0.0)),
                        error=None if forwarded.status_code < 400 else f"http_{forwarded.status_code}",
                        metadata={
                            "agent_id": context.get("agent", "default"),
                            "trace_id": trace.trace_id,
                            "behavioral_state": behavior_state,
                            "cascade_level": "",
                            "loop_state": "",
                        },
                    )
                )
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
            "version": "0.7.0",
            "policy_version": current_policy_hash,
            "uptime_seconds": int(max(0.0, time.perf_counter() - app_started_at)),
            "total_decisions": total_decisions,
        }

    @app.get("/stats")
    def stats_endpoint() -> dict[str, Any]:
        payload = {"policy_version": current_policy_hash}
        if recorder is not None:
            payload["recorder"] = recorder.get_stats()
        if behavioral_detector.enabled:
            payload["behavioral_detector"] = behavioral_detector.get_stats()
        return payload

    @app.get("/sessions")
    def sessions_endpoint() -> dict[str, Any]:
        if recorder is None:
            return {"sessions": []}
        return {"sessions": [asdict(item) for item in recorder.list_sessions()]}

    @app.get("/sessions/{session_id}")
    def session_summary_endpoint(session_id: str) -> dict[str, Any]:
        if recorder is None:
            return {"error": "recording_disabled"}
        try:
            summary = recorder.get_session_summary(session_id)
        except FileNotFoundError:
            return {"error": "session_not_found"}
        return {"session": asdict(summary)}

    @app.delete("/sessions/{session_id}")
    def session_delete_endpoint(session_id: str) -> dict[str, Any]:
        if recorder is None:
            return {"deleted": False, "error": "recording_disabled"}
        return {"deleted": recorder.delete_session(session_id), "session_id": session_id}

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


@dataclass
class HTTPProxyConfig:
    """Configuration for stdlib HTTP LLM proxy."""

    host: str = "127.0.0.1"
    port: int = 8100
    timeout: float = 300.0
    cors: bool = True
    upstream: dict[str, str] = field(
        default_factory=lambda: {
            "anthropic": "https://api.anthropic.com",
            "openai": "https://api.openai.com",
        }
    )


@dataclass
class _RequestContext:
    """Mutable state passed between request processing phases."""

    handler: Any  # BaseHTTPRequestHandler
    body: dict[str, Any] = field(default_factory=dict)
    parsed_req: Any = None  # ParsedRequest
    provider: str = ""
    original_model: str = ""
    cascade_decision: Any = None  # CascadeDecision | None
    cascade_level_name: str = "simple"
    cascade_cache_state: str = "miss"
    loop_warning_header: str = ""
    circuit_state_header: str = "closed"
    behavior_header: str = "normal"
    behavior_score_header: str = ""
    behavior_dims_header: str = ""
    behavior_agent_id: str = "default"
    session_id: str = ""
    request_id: str = ""
    session_headers: dict[str, str] = field(default_factory=dict)
    proc_result: dict[str, Any] = field(default_factory=lambda: {"cost": 0.0})
    request_started: float = 0.0
    resp_status: int = 200
    resp_headers: dict[str, str] = field(default_factory=dict)
    resp_body: bytes = b""
    parsed_resp_obj: Any = None  # ParsedResponse | None
    flow_node_id: str = ""


class LLMHTTPProxy:
    """HTTP proxy server for LLM APIs using stdlib HTTPServer."""

    def __init__(
        self,
        *,
        policy_path: str | None = None,
        config: HTTPProxyConfig | None = None,
    ) -> None:
        self._config = config if isinstance(config, HTTPProxyConfig) else HTTPProxyConfig()
        self._policy_path = policy_path
        self._policy: dict[str, Any] = {}
        if isinstance(policy_path, str) and policy_path.strip():
            try:
                self._policy = load_policy(policy_path)
            except Exception:
                self._policy = {}
        budgets = self._policy.get("budgets")
        self._budget_cfg = budgets if isinstance(budgets, dict) else {}
        tool_costs = self._policy.get("tool_costs")
        self._tool_costs = tool_costs if isinstance(tool_costs, dict) else {}
        self._state_tracker = RateLimitTracker(persist_path=None)
        self._cost_tracker = CostTracker(tool_costs=self._tool_costs)
        loop_cfg = self._policy.get("loop_detection")
        self._loop_cfg = loop_cfg if isinstance(loop_cfg, dict) else {}
        self._downgrade_model = str(self._loop_cfg.get("downgrade_model", "claude-haiku-4"))
        self._loop_detector = None
        if bool(self._loop_cfg.get("enabled", False)):
            self._loop_detector = LoopDetector(config=self._loop_cfg)
        circuit_cfg = self._policy.get("circuit_breaker")
        self._circuit_cfg = circuit_cfg if isinstance(circuit_cfg, dict) else {}
        self._circuit_breaker = CircuitBreaker(
            enabled=bool(self._circuit_cfg.get("enabled", False)),
            error_threshold=int(self._circuit_cfg.get("error_threshold", 5)),
            window_seconds=int(self._circuit_cfg.get("window_seconds", 60)),
            cooldown_seconds=int(self._circuit_cfg.get("cooldown_seconds", 30)),
            max_cooldown_seconds=int(self._circuit_cfg.get("max_cooldown_seconds", 300)),
            half_open_max_requests=int(self._circuit_cfg.get("half_open_max_requests", 1)),
            fallback_status=int(self._circuit_cfg.get("fallback_status", 503)),
            fallback_message=str(
                self._circuit_cfg.get(
                    "fallback_message",
                    "Service temporarily unavailable. Circuit breaker is open.",
                )
            ),
        )
        routing_cfg = self._policy.get("model_routing")
        self._routing_cfg = routing_cfg if isinstance(routing_cfg, dict) else {}
        self._router = ModelRouter(self._routing_cfg) if bool(self._routing_cfg.get("enabled", False)) else None
        cascade_cfg = self._policy.get("cascade")
        self._cascade_cfg = cascade_cfg if isinstance(cascade_cfg, dict) else {}
        self._cascade_router = CascadeRouter(self._cascade_cfg) if bool(self._cascade_cfg.get("enabled", False)) else None
        secret_cfg = self._policy.get("secret_scanning")
        if not isinstance(secret_cfg, dict):
            secret_cfg = self._policy.get("secrets") if isinstance(self._policy.get("secrets"), dict) else {}
        self._scan_outbound = bool(secret_cfg.get("scan_outbound", True))
        self._scan_response = bool(secret_cfg.get("scan_response", True))
        self._response_processor = ResponseProcessor(
            cost_tracker=self._cost_tracker,
            secret_patterns=SECRET_PATTERNS,
            scan_secrets=self._scan_response,
        )
        flow_cfg_raw = self._policy.get("flow_xray")
        self._flow_cfg = flow_cfg_raw if isinstance(flow_cfg_raw, dict) else {}
        self._flow_analyzer = (
            FlowAnalyzer(
                FlowXRayConfig(
                    enabled=bool(self._flow_cfg.get("enabled", False)),
                    max_sessions=int(self._flow_cfg.get("max_sessions", 1000)),
                    redundancy_window_seconds=float(self._flow_cfg.get("redundancy_window_seconds", 30.0)),
                    retry_threshold=int(self._flow_cfg.get("retry_threshold", 3)),
                    ping_pong_min_repetitions=int(self._flow_cfg.get("ping_pong_min_repetitions", 3)),
                    token_waste_stddev_threshold=float(self._flow_cfg.get("token_waste_stddev_threshold", 2.0)),
                    latency_spike_threshold=float(self._flow_cfg.get("latency_spike_threshold", 0.5)),
                    suspicious_tool_chains=self._flow_cfg.get("suspicious_tool_chains", []),
                    enable_security_patterns=bool(self._flow_cfg.get("enable_security_patterns", True)),
                    enable_efficiency_patterns=bool(self._flow_cfg.get("enable_efficiency_patterns", True)),
                    enable_performance_patterns=bool(self._flow_cfg.get("enable_performance_patterns", True)),
                )
            )
            if bool(self._flow_cfg.get("enabled", False))
            else None
        )
        behavioral_cfg = self._policy.get("behavioral_fingerprint")
        self._behavioral_cfg = behavioral_cfg if isinstance(behavioral_cfg, dict) else {}
        self._behavioral_detector = BehavioralDetector(self._behavioral_cfg)
        recording_cfg = self._policy.get("recording")
        self._recording_cfg = recording_cfg if isinstance(recording_cfg, dict) else {}
        self._recorder = (
            SessionRecorder(
                storage_path=str(self._recording_cfg.get("storage_path", ".orchesis/sessions")),
                compress=bool(self._recording_cfg.get("compress", True)),
                max_file_size_mb=int(self._recording_cfg.get("max_file_size_mb", 10)),
            )
            if bool(self._recording_cfg.get("enabled", False))
            else None
        )
        compliance_cfg = self._policy.get("compliance")
        self._compliance_cfg = compliance_cfg if isinstance(compliance_cfg, dict) else {}
        framework_tokens = self._compliance_cfg.get("frameworks", ["owasp_llm_top10", "nist_ai_rmf"])
        resolved_frameworks: list[Framework] = []
        if isinstance(framework_tokens, list):
            for token in framework_tokens:
                resolved = ComplianceEngine._framework_from_alias(token if isinstance(token, str) else None)
                if resolved is not None and resolved not in resolved_frameworks:
                    resolved_frameworks.append(resolved)
        if not resolved_frameworks:
            resolved_frameworks = [Framework.OWASP_LLM_TOP_10, Framework.NIST_AI_RMF]
        self._compliance_engine = ComplianceEngine(
            policy_path=self._policy_path or "policy.yaml",
            frameworks=resolved_frameworks,
            max_findings=int(self._compliance_cfg.get("max_findings", 10000)),
            enabled=bool(self._compliance_cfg.get("enabled", True)),
        )
        self._compliance_enabled = bool(self._compliance_cfg.get("enabled", True))
        kill_cfg = self._policy.get("kill_switch")
        self._kill_cfg = kill_cfg if isinstance(kill_cfg, dict) else {}
        self._kill_enabled = bool(self._kill_cfg.get("enabled", False))
        auto_cfg = self._kill_cfg.get("auto_triggers")
        self._kill_auto_cfg = auto_cfg if isinstance(auto_cfg, dict) else {}
        self._resume_token = str(self._kill_cfg.get("resume_token", "orchesis-resume-2024"))
        self._killed = False
        self._kill_reason = ""
        self._kill_time = ""
        self._secret_trigger_hits = 0
        self._loop_trigger_hits = 0
        self._server: HTTPServer | None = None
        self._start_time = time.time()
        self._stats_lock = threading.Lock()
        self._stats = {
            "requests": 0,
            "blocked": 0,
            "allowed": 0,
            "errors": 0,
            "kill_switch_activations": 0,
            "cascade_requests_by_level": {"simple": 0, "medium": 0, "complex": 0},
            "started_at": datetime.now(timezone.utc).isoformat(),
        }
        self._dashboard_events: deque[dict[str, Any]] = deque(maxlen=500)
        self._dashboard_cost_timeline: deque[dict[str, float]] = deque(maxlen=1000)
        self._dashboard_cost_timeline.append(
            {"timestamp": time.time(), "cumulative_cost": float(self._cost_tracker.get_daily_total())}
        )

    @property
    def stats(self) -> dict[str, Any]:
        with self._stats_lock:
            payload = dict(self._stats)
        payload["cost_today"] = round(self._cost_tracker.get_daily_total(), 4)
        payload["cost_by_tool"] = self._cost_tracker.get_tool_costs()
        payload["cascade_savings_today_usd"] = round(self._cost_tracker.get_cascade_savings_today(), 8)
        if self._loop_detector is not None:
            payload["loop_stats"] = self._loop_detector.get_stats()
            payload["loop_detector"] = {
                "exact_detections": payload["loop_stats"].get("exact_detections", 0),
                "fuzzy_detections": payload["loop_stats"].get("fuzzy_detections", 0),
                "total_cost_saved_usd": payload["loop_stats"].get("total_cost_saved_usd", 0.0),
                "active_patterns_count": payload["loop_stats"].get("active_patterns_count", 0),
            }
        payload["circuit_breaker"] = self._circuit_breaker.get_stats()
        if self._cascade_router is not None:
            cascade_stats = self._cascade_router.get_stats()
            payload["cascade_requests_by_level"] = cascade_stats.get("requests_by_level", {})
            payload["cascade_hits_by_level"] = cascade_stats.get("hits_by_level", {})
            payload["cache_hit_rate_percent"] = cascade_stats.get("cache_hit_rate_percent", 0.0)
            payload["cache_entries_count"] = cascade_stats.get("cache_entries_count", 0)
            payload["cache_hit_rate"] = cascade_stats.get("cache_hit_rate_percent", 0.0)
            payload["cascade_savings_today"] = payload["cascade_savings_today_usd"]
        payload["kill_switch"] = {
            "enabled": self._kill_enabled,
            "killed": self._killed,
            "reason": self._kill_reason,
            "killed_at": self._kill_time,
            "secret_trigger_hits": self._secret_trigger_hits,
            "loop_trigger_hits": self._loop_trigger_hits,
        }
        if self._behavioral_detector.enabled:
            payload["behavioral_detector"] = self._behavioral_detector.get_stats()
        if self._recorder is not None:
            payload["recorder"] = self._recorder.get_stats()
        if self._flow_analyzer is not None:
            payload["flow_xray"] = self._flow_analyzer.get_stats()
        if self._compliance_engine is not None:
            payload["compliance"] = self._compliance_engine.get_stats()
        return payload

    @property
    def cost_tracker(self) -> CostTracker:
        return self._cost_tracker

    def start(self, blocking: bool = True) -> threading.Thread | None:
        proxy = self

        class _Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                proxy._handle_post(self)

            def do_GET(self) -> None:  # noqa: N802
                proxy._handle_get(self)

            def do_DELETE(self) -> None:  # noqa: N802
                proxy._handle_delete(self)

            def do_OPTIONS(self) -> None:  # noqa: N802
                self.send_response(200)
                if proxy._config.cors:
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
                    self.send_header("Access-Control-Allow-Headers", "*")
                self.end_headers()

            def log_message(self, fmt: str, *args: Any) -> None:
                _HTTP_PROXY_LOGGER.debug("proxy %s - " + fmt, self.address_string(), *args)

        self._server = HTTPServer((self._config.host, self._config.port), _Handler)
        if blocking:
            try:
                self._server.serve_forever()
            finally:
                self._state_tracker.flush()
            return None
        thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        thread.start()
        return thread

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        self._state_tracker.flush()
        if self._recorder is not None:
            self._recorder.close_all()

    def _inc(self, field: str) -> None:
        with self._stats_lock:
            self._stats[field] = int(self._stats.get(field, 0)) + 1
        if field == "blocked":
            self._add_dashboard_event("blocked", "medium", "Request blocked by runtime guardrail.")
            if self._compliance_enabled:
                self._compliance_engine.map_finding(
                    source_module="engine",
                    source_detail="tool_allowlist",
                    description="Runtime guardrail blocked a request.",
                    severity=Severity.MEDIUM,
                    evidence={"counter": "blocked"},
                )
        elif field == "errors":
            self._add_dashboard_event("error", "high", "Runtime error while processing request.")
            if self._compliance_enabled:
                self._compliance_engine.map_finding(
                    source_module="circuit_breaker",
                    source_detail="automated_response",
                    description="Runtime error recorded by proxy.",
                    severity=Severity.HIGH,
                    evidence={"counter": "errors"},
                )

    def _add_dashboard_event(
        self,
        event_type: str,
        severity: str,
        description: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self._dashboard_events.append(
            {
                "timestamp": time.time(),
                "type": str(event_type),
                "severity": str(severity),
                "description": str(description),
                "metadata": metadata if isinstance(metadata, dict) else {},
            }
        )

    def _build_dashboard_overview(self) -> dict[str, Any]:
        stats = self.stats
        now = time.time()
        recent_events = sorted(self._dashboard_events, key=lambda e: float(e.get("timestamp", 0.0)), reverse=True)
        critical_recent = [
            e
            for e in recent_events
            if (now - float(e.get("timestamp", 0.0))) <= 60.0 and str(e.get("severity", "")).lower() == "critical"
        ]
        blocked_recent = [
            e for e in recent_events if (now - float(e.get("timestamp", 0.0))) <= 300.0 and e.get("type") == "blocked"
        ]
        circuit_state = str(stats.get("circuit_breaker", {}).get("state", "CLOSED")).upper()
        if circuit_state == "OPEN" or critical_recent:
            status = "alert"
        elif blocked_recent:
            status = "monitoring"
        else:
            status = "clear"
        flow_stats = stats.get("flow_xray", {}) if isinstance(stats.get("flow_xray"), dict) else {}
        behavioral_stats = (
            stats.get("behavioral_detector", {}) if isinstance(stats.get("behavioral_detector"), dict) else {}
        )
        active_agents = int(behavioral_stats.get("agents_monitored", 0)) + int(
            behavioral_stats.get("agents_learning", 0)
        )
        circuit_breakers = {
            "default": {
                "state": str(stats.get("circuit_breaker", {}).get("state", "closed")).lower(),
                "failures": int(stats.get("circuit_breaker", {}).get("error_count", 0)),
            }
        }
        daily_limit = self._budget_cfg.get("daily")
        limit_usd = float(daily_limit) if isinstance(daily_limit, int | float) else 0.0
        spent_usd = float(stats.get("cost_today", 0.0))
        budget = {
            "limit_usd": limit_usd,
            "spent_usd": spent_usd,
            "remaining_usd": max(0.0, limit_usd - spent_usd) if limit_usd > 0 else 0.0,
        }
        return {
            "status": status,
            "uptime_seconds": max(0.0, now - self._start_time),
            "total_requests": int(stats.get("requests", 0)),
            "blocked_requests": int(stats.get("blocked", 0)),
            "total_cost_usd": float(stats.get("cost_today", 0.0)),
            "active_agents": active_agents,
            "circuit_breakers": circuit_breakers,
            "budget": budget,
            "recent_events": recent_events[:20],
            "cost_timeline": list(self._dashboard_cost_timeline),
            "flow_xray": flow_stats,
        }

    def _build_dashboard_agents(self) -> dict[str, Any]:
        if not self._behavioral_detector.enabled:
            return {"agents": []}
        agents_payload: list[dict[str, Any]] = []
        with self._behavioral_detector._lock:  # noqa: SLF001 - internal read for dashboard endpoint
            agent_ids = list(self._behavioral_detector._agents.keys())  # noqa: SLF001
        for agent_id in agent_ids:
            profile = self._behavioral_detector.get_agent_profile(agent_id)
            if not isinstance(profile, dict):
                continue
            dims = profile.get("dimensions", {}) if isinstance(profile.get("dimensions"), dict) else {}
            prompt_mean = float(dims.get("prompt_tokens", {}).get("mean", 0.0)) if isinstance(
                dims.get("prompt_tokens"), dict
            ) else 0.0
            completion_mean = float(dims.get("completion_tokens", {}).get("mean", 0.0)) if isinstance(
                dims.get("completion_tokens"), dict
            ) else 0.0
            anomaly_score = min(
                1.0,
                max(
                    0.0,
                    float(dims.get("error_rate", {}).get("mean", 0.0)) if isinstance(dims.get("error_rate"), dict) else 0.0,
                ),
            )
            agents_payload.append(
                {
                    "agent_id": agent_id,
                    "state": str(profile.get("state", "monitoring")),
                    "total_requests": int(profile.get("total_requests", 0)),
                    "avg_tokens": round(prompt_mean + completion_mean, 4),
                    "anomaly_score": round(anomaly_score, 6),
                    "tools_used": sorted(list((profile.get("tool_distribution") or {}).keys()))
                    if isinstance(profile.get("tool_distribution"), dict)
                    else [],
                    "last_seen": str(profile.get("last_seen", "")),
                    "request_frequency": float(dims.get("request_frequency", {}).get("mean", 0.0))
                    if isinstance(dims.get("request_frequency"), dict)
                    else 0.0,
                    "anomaly_scores": {"error_rate": anomaly_score},
                }
            )
        agents_payload.sort(key=lambda item: float(item.get("total_requests", 0)), reverse=True)
        return {"agents": agents_payload}

    def _handle_session_export(
        self,
        handler: BaseHTTPRequestHandler,
        session_id: str,
        query_params: dict[str, list[str]],
    ) -> None:
        if self._recorder is None:
            self._send_json(handler, 404, {"error": "recording_not_enabled"})
            return
        if not session_id:
            self._send_json(handler, 400, {"error": "session_id_required"})
            return
        content_level = str((query_params.get("content_level") or ["structure"])[0]).strip().lower() or "structure"
        format_name = str((query_params.get("format") or ["air"])[0]).strip().lower() or "air"
        download = str((query_params.get("download") or ["false"])[0]).strip().lower() == "true"
        if format_name != "air":
            self._send_json(handler, 400, {"error": "unsupported_format", "format": format_name})
            return
        try:
            doc = export_session_to_air(
                session_id=session_id,
                recorder=self._recorder,
                flow_analyzer=self._flow_analyzer,
                behavioral_detector=self._behavioral_detector if self._behavioral_detector.enabled else None,
                compliance_engine=self._compliance_engine if self._compliance_enabled else None,
                content_level=content_level,
                version=ORCHESIS_VERSION,
            )
        except ValueError as exc:
            self._send_json(handler, 400, {"error": "invalid_content_level", "message": str(exc)})
            return
        if "error" in doc:
            self._send_json(handler, 404, doc)
            return
        if download:
            self._send_json(
                handler,
                200,
                doc,
                extra_headers={
                    "Content-Disposition": f'attachment; filename="session_{session_id}.air"'
                },
            )
            return
        self._send_json(handler, 200, doc)

    def _handle_get(self, handler: BaseHTTPRequestHandler) -> None:
        parsed = urlsplit(handler.path)
        path = parsed.path
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        if path in {"/dashboard", "/dashboard/"}:
            payload = get_dashboard_html().encode("utf-8")
            handler.send_response(200)
            handler.send_header("Content-Type", "text/html; charset=utf-8")
            handler.send_header("Content-Length", str(len(payload)))
            if self._config.cors:
                handler.send_header("Access-Control-Allow-Origin", "*")
            handler.end_headers()
            handler.wfile.write(payload)
            return
        if path in {"/", "/health"}:
            self._send_json(
                handler,
                200,
                {
                    "status": "ok",
                    "proxy": f"{self._config.host}:{self._config.port}",
                    "policy": self._policy_path or "none",
                    "stats": self.stats,
                    "model_routing": self._router is not None,
                    "loop_detection": self._loop_detector is not None,
                    "killed": self._killed,
                    "kill_reason": self._kill_reason,
                    "killed_at": self._kill_time,
                },
            )
            return
        if path == "/stats":
            self._send_json(handler, 200, self.stats)
            return
        if path == "/api/dashboard/overview":
            self._send_json(handler, 200, self._build_dashboard_overview())
            return
        if path == "/api/dashboard/agents":
            self._send_json(handler, 200, self._build_dashboard_agents())
            return
        if path in {"/api/sessions", "/sessions"} and self._recorder is not None:
            sessions = [asdict(item) for item in self._recorder.list_sessions()]
            self._send_json(handler, 200, {"sessions": sessions})
            return
        if path.startswith("/api/sessions/") and path.endswith("/export"):
            session_id = path[len("/api/sessions/") : -len("/export")].strip("/")
            self._handle_session_export(handler, session_id, query_params)
            return
        if (path.startswith("/sessions/") or path.startswith("/api/sessions/")) and self._recorder is not None:
            session_id = (
                path.split("/api/sessions/", 1)[1].strip()
                if path.startswith("/api/sessions/")
                else path.split("/sessions/", 1)[1].strip()
            )
            if not session_id:
                self._send_json(handler, 400, {"error": "session_id_required"})
                return
            try:
                summary = self._recorder.get_session_summary(session_id)
            except FileNotFoundError:
                self._send_json(handler, 404, {"error": "session_not_found"})
                return
            self._send_json(handler, 200, {"session": asdict(summary)})
            return
        if path == "/api/flow/sessions":
            if self._flow_analyzer is None:
                self._send_json(handler, 200, {"sessions": []})
                return
            self._send_json(handler, 200, {"sessions": self._flow_analyzer.list_sessions()})
            return
        if path.startswith("/api/flow/analyze/"):
            if self._flow_analyzer is None:
                self._send_json(handler, 404, {"error": "Session not found"})
                return
            session_id = path.split("/api/flow/analyze/", 1)[1].strip()
            analysis = self._flow_analyzer.analyze_session(session_id)
            if analysis is None:
                self._send_json(handler, 404, {"error": "Session not found"})
                return
            self._send_json(handler, 200, analysis.to_dict())
            return
        if path.startswith("/api/flow/graph/"):
            if self._flow_analyzer is None:
                self._send_json(handler, 404, {"error": "Session not found"})
                return
            session_id = path.split("/api/flow/graph/", 1)[1].strip()
            graph_json = self._flow_analyzer.export_graph_json(session_id)
            if not graph_json:
                self._send_json(handler, 404, {"error": "Session not found"})
                return
            self._send_json(handler, 200, json.loads(graph_json))
            return
        if path == "/api/flow/patterns":
            if self._flow_analyzer is None:
                self._send_json(handler, 200, {"sessions_tracked": 0, "pattern_counts": {}})
                return
            self._send_json(handler, 200, self._flow_analyzer.get_stats())
            return
        if path == "/api/compliance/summary":
            self._send_json(handler, 200, self._compliance_engine.get_summary())
            return
        if path == "/api/compliance/coverage":
            reports: dict[str, Any] = {}
            for framework in self._compliance_engine._frameworks:  # noqa: SLF001
                reports[framework.value] = self._compliance_engine.get_coverage_report(framework)
            self._send_json(handler, 200, {"frameworks": reports})
            return
        if path.startswith("/api/compliance/coverage/"):
            framework_token = path.split("/api/compliance/coverage/", 1)[1].strip().lower()
            framework = ComplianceEngine._framework_from_alias(framework_token)
            if framework is None:
                self._send_json(handler, 404, {"error": "framework_not_found"})
                return
            self._send_json(handler, 200, self._compliance_engine.get_coverage_report(framework))
            return
        if path == "/api/compliance/findings":
            framework = ComplianceEngine._framework_from_alias((query_params.get("framework") or [None])[0])
            severity_token = (query_params.get("severity") or [None])[0]
            sev = None
            if isinstance(severity_token, str) and severity_token.strip():
                try:
                    sev = Severity(severity_token.strip().lower())
                except Exception:
                    sev = None
            limit_raw = (query_params.get("limit") or ["100"])[0]
            try:
                limit = int(limit_raw)
            except Exception:
                limit = 100
            findings = self._compliance_engine.get_findings(framework=framework, severity=sev, limit=limit)
            self._send_json(
                handler,
                200,
                {
                    "findings": [
                        {
                            **asdict(item),
                            "severity": item.severity.value,
                        }
                        for item in findings
                    ]
                },
            )
            return
        if path == "/api/compliance/report":
            fmt = str((query_params.get("format") or ["json"])[0]).strip().lower()
            report = self._compliance_engine.export_report(format=fmt)
            if isinstance(report, str):
                payload = report.encode("utf-8")
                handler.send_response(200)
                handler.send_header("Content-Type", "text/markdown; charset=utf-8")
                handler.send_header("Content-Length", str(len(payload)))
                if self._config.cors:
                    handler.send_header("Access-Control-Allow-Origin", "*")
                handler.end_headers()
                handler.wfile.write(payload)
                return
            self._send_json(handler, 200, report)
            return
        self._send_json(handler, 404, {"error": "Not found"})

    def _phase_parse(self, ctx: _RequestContext) -> bool:
        length = int(ctx.handler.headers.get("Content-Length", "0") or "0")
        raw_body = ctx.handler.rfile.read(max(0, length))
        try:
            body = json.loads(raw_body.decode("utf-8"))
        except Exception:
            self._send_json(ctx.handler, 400, {"error": "Invalid JSON in request body"})
            return False
        if not isinstance(body, dict):
            self._send_json(ctx.handler, 400, {"error": "Request body must be a JSON object"})
            return False
        ctx.body = body
        ctx.parsed_req = parse_request(body, ctx.handler.path)
        ctx.original_model = ctx.parsed_req.model or str(body.get("model", ""))
        return True

    def _phase_cascade(self, ctx: _RequestContext) -> bool:
        if self._cascade_router is None:
            return True
        task_id = ctx.body.get("task_id")
        cascade_context = {"task_id": task_id} if isinstance(task_id, str) and task_id else {}
        pre_level = self._cascade_router.classify(ctx.parsed_req, context=cascade_context)
        pre_level_name = self._cascade_router.level_name(pre_level)
        pre_model = ctx.parsed_req.model or str(
            self._cascade_cfg.get("levels", {}).get(pre_level_name, {}).get("model", "")
        )
        cache_key = self._cascade_router.make_cache_key(ctx.parsed_req, pre_model or "")
        cached_payload = self._cascade_router.get_cache(cache_key, pre_level)
        if cached_payload is not None:
            ctx.handler.send_response(200)
            ctx.handler.send_header("Content-Type", "application/json")
            ctx.handler.send_header("Content-Length", str(len(cached_payload)))
            ctx.handler.send_header("X-Orchesis-Cost", "0.0")
            ctx.handler.send_header("X-Orchesis-Daily-Total", str(round(self._cost_tracker.get_daily_total(), 4)))
            ctx.handler.send_header("X-Orchesis-Cascade-Level", pre_level_name)
            ctx.handler.send_header("X-Orchesis-Cascade-Model", pre_model or "")
            ctx.handler.send_header("X-Orchesis-Cache", "hit")
            if self._recorder is not None:
                ctx.handler.send_header("X-Orchesis-Session-Id", ctx.session_id)
                ctx.handler.send_header("X-Orchesis-Request-Id", ctx.request_id)
            if self._config.cors:
                ctx.handler.send_header("Access-Control-Allow-Origin", "*")
            ctx.handler.end_headers()
            ctx.handler.wfile.write(cached_payload)
            self._inc("allowed")
            cached_obj: dict[str, Any] | None = None
            try:
                decoded_cached = json.loads(cached_payload.decode("utf-8"))
                if isinstance(decoded_cached, dict):
                    cached_obj = decoded_cached
            except Exception:
                cached_obj = None
            self._record_session(
                request_id=ctx.request_id,
                session_id=ctx.session_id,
                request_body=ctx.body,
                response_body=cached_obj,
                status_code=200,
                provider=ctx.parsed_req.provider,
                model=str(ctx.body.get("model", "")),
                latency_ms=(time.perf_counter() - ctx.request_started) * 1000.0,
                cost=0.0,
                error=None,
                metadata={
                    "agent_id": ctx.behavior_agent_id,
                    "behavioral_state": ctx.behavior_header,
                    "cascade_level": pre_level_name,
                    "loop_state": ctx.loop_warning_header,
                },
            )
            return False
        ctx.cascade_decision = self._cascade_router.route(ctx.parsed_req, context=cascade_context)
        ctx.cascade_level_name = self._cascade_router.level_name(ctx.cascade_decision.cascade_level)
        ctx.cascade_cache_state = "miss"
        if ctx.cascade_decision.model:
            ctx.body["model"] = ctx.cascade_decision.model
        if ctx.cascade_decision.max_tokens > 0:
            ctx.body["max_tokens"] = ctx.cascade_decision.max_tokens
        return True

    def _phase_flow_xray_record(self, ctx: _RequestContext) -> bool:
        if self._flow_analyzer is None:
            return True
        tool_names: list[str] = []
        tools_raw = ctx.body.get("tools")
        if isinstance(tools_raw, list):
            for item in tools_raw:
                if isinstance(item, dict):
                    name = item.get("name")
                    if isinstance(name, str) and name:
                        tool_names.append(name)
                elif isinstance(item, str) and item:
                    tool_names.append(item)
        flow_session = ctx.session_id or "default"
        ctx.flow_node_id = self._flow_analyzer.record_request(
            session_id=flow_session,
            model=str(ctx.body.get("model", ctx.original_model)),
            messages=ctx.body.get("messages", []) if isinstance(ctx.body.get("messages"), list) else [],
            tools=tool_names,
        )
        return True

    def _phase_circuit_breaker(self, ctx: _RequestContext) -> bool:
        if not self._circuit_breaker.should_allow():
            self._inc("blocked")
            fallback = {
                "error": {
                    "type": "circuit_open",
                    "message": self._circuit_breaker.fallback_message,
                }
            }
            payload_fb = json.dumps(fallback, ensure_ascii=False).encode("utf-8")
            ctx.handler.send_response(self._circuit_breaker.fallback_status)
            ctx.handler.send_header("Content-Type", "application/json")
            ctx.handler.send_header("Content-Length", str(len(payload_fb)))
            ctx.handler.send_header("X-Orchesis-Circuit", "open")
            if self._config.cors:
                ctx.handler.send_header("Access-Control-Allow-Origin", "*")
            ctx.handler.end_headers()
            ctx.handler.wfile.write(payload_fb)
            return False
        ctx.circuit_state_header = self._circuit_breaker.get_state().lower().replace("_", "-")
        return True

    def _phase_loop_detection(self, ctx: _RequestContext) -> bool:
        if self._loop_detector is None:
            return True
        loop_decision = self._loop_detector.check_request(
            {
                "model": ctx.body.get("model", ctx.parsed_req.model),
                "messages": ctx.parsed_req.messages,
                "tool_calls": ctx.parsed_req.tool_calls,
                "content_text": ctx.parsed_req.content_text,
            }
        )
        if loop_decision.action == "block":
            self._loop_trigger_hits += 1
            if self._kill_enabled and self._should_kill_for_loops():
                self._activate_kill_switch("auto-kill: loop threshold reached")
                self._inc("blocked")
                self._send_json(
                    ctx.handler,
                    503,
                    {
                        "error": {
                            "type": "kill_switch",
                            "message": self._kill_reason,
                            "killed_at": self._kill_time,
                        }
                    },
                )
                return False
            self._inc("blocked")
            payload_lb = {
                "error": {
                    "type": "loop_detected",
                    "message": loop_decision.reason or "Fuzzy loop threshold exceeded",
                }
            }
            body_lb = json.dumps(payload_lb, ensure_ascii=False).encode("utf-8")
            ctx.handler.send_response(429)
            ctx.handler.send_header("Content-Type", "application/json")
            ctx.handler.send_header("Content-Length", str(len(body_lb)))
            ctx.handler.send_header("X-Orchesis-Loop-Blocked", loop_decision.reason or "Fuzzy loop threshold exceeded")
            ctx.handler.send_header("X-Orchesis-Loop-Saved", f"${loop_decision.estimated_cost_saved:.2f}")
            ctx.handler.send_header("X-Orchesis-Circuit", ctx.circuit_state_header)
            if self._config.cors:
                ctx.handler.send_header("Access-Control-Allow-Origin", "*")
            ctx.handler.end_headers()
            ctx.handler.wfile.write(body_lb)
            return False
        if loop_decision.action in {"warn", "downgrade_model"}:
            ctx.loop_warning_header = loop_decision.reason or "Loop warning"
            if loop_decision.action == "downgrade_model":
                ctx.body["model"] = self._downgrade_model
        return True

    def _phase_behavioral(self, ctx: _RequestContext) -> bool:
        if not self._behavioral_detector.enabled:
            return True
        behavior_data = {
            "model": ctx.body.get("model", ctx.parsed_req.model),
            "messages": ctx.parsed_req.messages,
            "tools": ctx.parsed_req.tool_calls,
            "estimated_cost": float(ctx.proc_result.get("cost", 0.0)),
            "headers": {k: v for k, v in ctx.handler.headers.items()},
        }
        ctx.behavior_agent_id = extract_agent_id(behavior_data)
        behavior_decision = self._behavioral_detector.check_request(ctx.behavior_agent_id, behavior_data)
        if behavior_decision.action == "block":
            self._inc("blocked")
            self._send_json(
                ctx.handler,
                429,
                {
                    "error": "behavioral_anomaly",
                    "anomalies": [asdict(item) for item in behavior_decision.anomalies],
                },
                extra_headers=ctx.session_headers,
            )
            self._record_session(
                request_id=ctx.request_id,
                session_id=ctx.session_id,
                request_body=ctx.body,
                response_body=None,
                status_code=429,
                provider=ctx.parsed_req.provider,
                model=str(ctx.body.get("model", "")),
                latency_ms=(time.perf_counter() - ctx.request_started) * 1000.0,
                cost=float(ctx.proc_result.get("cost", 0.0)),
                error="behavioral_anomaly",
                metadata={
                    "agent_id": ctx.behavior_agent_id,
                    "behavioral_state": "anomaly",
                    "cascade_level": ctx.cascade_level_name,
                    "loop_state": ctx.loop_warning_header,
                },
            )
            return False
        if behavior_decision.action == "learning":
            ctx.behavior_header = "learning"
        elif behavior_decision.anomalies:
            ctx.behavior_header = "anomaly"
            ctx.behavior_score_header = str(behavior_decision.anomaly_score)
            ctx.behavior_dims_header = ",".join(sorted({item.dimension for item in behavior_decision.anomalies}))
        return True

    def _phase_budget(self, ctx: _RequestContext) -> bool:
        _ = ctx
        if self._budget_cfg:
            budget_status = self._cost_tracker.check_budget(self._budget_cfg)
            if self._kill_enabled and self._should_kill_for_cost(budget_status):
                self._activate_kill_switch("auto-kill: emergency budget multiplier exceeded")
                self._inc("blocked")
                self._send_json(
                    ctx.handler,
                    503,
                    {
                        "error": {
                            "type": "kill_switch",
                            "message": self._kill_reason,
                            "killed_at": self._kill_time,
                        }
                    },
                )
                return False
            if bool(budget_status.get("over_budget", False)):
                self._inc("blocked")
                self._send_json(
                    ctx.handler,
                    429,
                    {
                        "error": {
                            "type": "budget_exceeded",
                            "message": f"Daily budget exceeded. Spent ${budget_status.get('daily_spent', 0):.4f}",
                        }
                    },
                )
                return False
        return True

    def _phase_policy(self, ctx: _RequestContext) -> bool:
        for call in ctx.parsed_req.tool_calls:
            eval_request = {
                "tool": call.name,
                "params": call.params if isinstance(call.params, dict) else {},
                "context": {"path": ctx.handler.path, "provider": ctx.parsed_req.provider},
            }
            decision = evaluate(eval_request, self._policy, state=self._state_tracker)
            if not decision.allowed:
                self._inc("blocked")
                reason = decision.reasons[0] if decision.reasons else "blocked_by_policy"
                self._send_json(
                    ctx.handler,
                    403,
                    {"error": {"type": "policy_violation", "message": f"Tool '{call.name}' blocked: {reason}"}},
                )
                return False
        return True

    def _phase_model_router(self, ctx: _RequestContext) -> bool:
        if self._router is not None and ctx.parsed_req.content_text:
            route = self._router.route(
                ctx.parsed_req.content_text,
                tool_name=ctx.parsed_req.tool_calls[0].name if ctx.parsed_req.tool_calls else None,
            )
            routed_model = route.get("model")
            if isinstance(routed_model, str) and routed_model and routed_model != ctx.parsed_req.model:
                ctx.body["model"] = routed_model
        return True

    def _phase_secrets(self, ctx: _RequestContext) -> bool:
        if self._scan_outbound and ctx.parsed_req.content_text:
            for pattern, secret_type in SECRET_PATTERNS:
                if pattern.search(ctx.parsed_req.content_text):
                    self._secret_trigger_hits += 1
                    if self._kill_enabled and self._should_kill_for_secrets():
                        self._activate_kill_switch("auto-kill: secrets detection threshold reached")
                        self._inc("blocked")
                        self._send_json(
                            ctx.handler,
                            503,
                            {
                                "error": {
                                    "type": "kill_switch",
                                    "message": self._kill_reason,
                                    "killed_at": self._kill_time,
                                }
                            },
                        )
                        return False
                    self._inc("blocked")
                    self._send_json(
                        ctx.handler,
                        403,
                        {
                            "error": {
                                "type": "secret_detected",
                                "message": f"Request contains potential {secret_type}",
                            }
                        },
                    )
                    return False
        return True

    def _phase_upstream(self, ctx: _RequestContext) -> bool:
        ctx.provider = self._detect_provider(ctx.parsed_req.provider, ctx.handler.headers)
        upstream_base = self._get_upstream(ctx.provider, ctx.handler.headers)
        upstream_url = f"{upstream_base.rstrip('/')}{ctx.handler.path}"
        payload = json.dumps(ctx.body, ensure_ascii=False).encode("utf-8")
        upstream_headers = self._build_forward_headers(ctx.handler.headers, payload)
        req = UrlRequest(upstream_url, data=payload, headers=upstream_headers, method="POST")
        ctx.resp_status = 200
        ctx.resp_headers = {}
        ctx.resp_body = b""
        try:
            with urlopen(req, timeout=self._config.timeout) as upstream_resp:
                ctx.resp_status = int(getattr(upstream_resp, "status", 200))
                ctx.resp_headers = dict(upstream_resp.headers.items())
                ctx.resp_body = upstream_resp.read()
        except HTTPError as error:
            ctx.resp_status = int(error.code)
            ctx.resp_headers = dict(error.headers.items()) if error.headers is not None else {}
            ctx.resp_body = error.read()
        except (URLError, OSError) as error:
            self._circuit_breaker.record_failure()
            self._inc("errors")
            self._send_json(
                ctx.handler,
                502,
                {"error": {"type": "upstream_error", "message": f"Failed to connect to upstream: {error}"}},
            )
            return False
        return True

    def _phase_post_upstream(self, ctx: _RequestContext) -> bool:
        ctx.parsed_resp_obj = None
        try:
            decoded = json.loads(ctx.resp_body.decode("utf-8"))
            if isinstance(decoded, dict):
                parsed_resp = parse_response(decoded, ctx.provider)
                ctx.parsed_resp_obj = parsed_resp
                ctx.proc_result = self._response_processor.process(parsed_resp)
                if not ctx.proc_result.get("allowed", True):
                    self._inc("blocked")
                    self._send_json(
                        ctx.handler,
                        403,
                        {
                            "error": {
                                "type": "secret_detected_in_response",
                                "message": ctx.proc_result.get("reason", "response contains secrets"),
                            }
                        },
                    )
                    return False
        except Exception:
            ctx.proc_result = {"cost": 0.0}
        if 200 <= ctx.resp_status < 300:
            self._circuit_breaker.record_success()
        elif ctx.resp_status >= 500:
            self._circuit_breaker.record_failure()
        if (
            self._cascade_router is not None
            and ctx.cascade_decision is not None
            and self._cascade_router.should_escalate(ctx.resp_status, ctx.parsed_resp_obj)
            and ctx.cascade_decision.cascade_level < CascadeLevel.COMPLEX
        ):
            escalated_decision = self._cascade_router.escalate(ctx.cascade_decision)
            if escalated_decision.model:
                ctx.body["model"] = escalated_decision.model
            if escalated_decision.max_tokens > 0:
                ctx.body["max_tokens"] = escalated_decision.max_tokens
            upstream_base = self._get_upstream(ctx.provider, ctx.handler.headers)
            upstream_url = f"{upstream_base.rstrip('/')}{ctx.handler.path}"
            payload_retry = json.dumps(ctx.body, ensure_ascii=False).encode("utf-8")
            req_retry = UrlRequest(
                upstream_url,
                data=payload_retry,
                headers=self._build_forward_headers(ctx.handler.headers, payload_retry),
                method="POST",
            )
            try:
                with urlopen(req_retry, timeout=self._config.timeout) as upstream_retry:
                    ctx.resp_status = int(getattr(upstream_retry, "status", 200))
                    ctx.resp_headers = dict(upstream_retry.headers.items())
                    ctx.resp_body = upstream_retry.read()
            except HTTPError as error:
                ctx.resp_status = int(error.code)
                ctx.resp_headers = dict(error.headers.items()) if error.headers is not None else {}
                ctx.resp_body = error.read()
            ctx.cascade_decision = escalated_decision
            ctx.cascade_level_name = self._cascade_router.level_name(ctx.cascade_decision.cascade_level)
            try:
                decoded_retry = json.loads(ctx.resp_body.decode("utf-8"))
                if isinstance(decoded_retry, dict):
                    parsed_resp_retry = parse_response(decoded_retry, ctx.provider)
                    ctx.parsed_resp_obj = parsed_resp_retry
                    ctx.proc_result = self._response_processor.process(parsed_resp_retry)
            except Exception:
                pass
        if self._cascade_router is not None and ctx.cascade_decision is not None and ctx.parsed_resp_obj is not None:
            token_sum = int(getattr(ctx.parsed_resp_obj, "input_tokens", 0)) + int(
                getattr(ctx.parsed_resp_obj, "output_tokens", 0)
            )
            self._cost_tracker.record_cascade_savings(
                original_model=ctx.original_model or ctx.cascade_decision.model,
                actual_model=ctx.cascade_decision.model,
                tokens=token_sum,
            )
            if 200 <= ctx.resp_status < 300:
                self._cascade_router.record_result(ctx.cascade_decision, ctx.parsed_resp_obj)
                self._cascade_router.cache_response(ctx.cascade_decision, ctx.resp_body)
        if self._behavioral_detector.enabled:
            completion_tokens = 0
            if ctx.parsed_resp_obj is not None:
                completion_tokens = int(ctx.parsed_resp_obj.output_tokens)
            self._behavioral_detector.record_response(
                ctx.behavior_agent_id,
                is_error=ctx.resp_status >= 400,
                completion_tokens=completion_tokens,
            )
        if self._flow_analyzer is not None and ctx.flow_node_id:
            tool_calls_for_flow: list[dict[str, Any]] = []
            if ctx.parsed_resp_obj is not None:
                for tool_call in getattr(ctx.parsed_resp_obj, "tool_calls", []):
                    name = getattr(tool_call, "name", "")
                    params = getattr(tool_call, "params", {})
                    if isinstance(name, str) and name:
                        tool_calls_for_flow.append(
                            {
                                "name": name,
                                "input": params if isinstance(params, dict) else {},
                            }
                        )
            self._flow_analyzer.record_response(
                session_id=ctx.session_id or "default",
                node_id=ctx.flow_node_id,
                tokens_in=int(getattr(ctx.parsed_resp_obj, "input_tokens", 0)) if ctx.parsed_resp_obj is not None else 0,
                tokens_out=int(getattr(ctx.parsed_resp_obj, "output_tokens", 0)) if ctx.parsed_resp_obj is not None else 0,
                cost_usd=float(ctx.proc_result.get("cost", 0.0)),
                latency_ms=(time.perf_counter() - ctx.request_started) * 1000.0,
                status="ok" if ctx.resp_status < 400 else "error",
                tool_calls=tool_calls_for_flow,
            )
        return True

    def _phase_send_response(self, ctx: _RequestContext) -> None:
        ctx.handler.send_response(ctx.resp_status)
        self._copy_upstream_headers(ctx.handler, ctx.resp_headers, len(ctx.resp_body))
        ctx.handler.send_header("X-Orchesis-Cost", str(round(float(ctx.proc_result.get("cost", 0.0)), 6)))
        ctx.handler.send_header("X-Orchesis-Daily-Total", str(round(self._cost_tracker.get_daily_total(), 4)))
        ctx.handler.send_header("X-Orchesis-Cascade-Level", ctx.cascade_level_name)
        ctx.handler.send_header("X-Orchesis-Cascade-Model", str(ctx.body.get("model", ctx.original_model)))
        ctx.handler.send_header("X-Orchesis-Cache", ctx.cascade_cache_state)
        ctx.handler.send_header("X-Orchesis-Circuit", self._circuit_breaker.get_state().lower().replace("_", "-"))
        if self._recorder is not None:
            ctx.handler.send_header("X-Orchesis-Session-Id", ctx.session_id)
            ctx.handler.send_header("X-Orchesis-Request-Id", ctx.request_id)
        if ctx.loop_warning_header:
            ctx.handler.send_header("X-Orchesis-Loop-Warning", ctx.loop_warning_header)
        if self._behavioral_detector.enabled:
            ctx.handler.send_header("X-Orchesis-Behavior", ctx.behavior_header)
            if ctx.behavior_score_header:
                ctx.handler.send_header("X-Orchesis-Anomaly-Score", ctx.behavior_score_header)
            if ctx.behavior_dims_header:
                ctx.handler.send_header("X-Orchesis-Anomaly-Dimensions", ctx.behavior_dims_header)
        if self._config.cors:
            ctx.handler.send_header("Access-Control-Allow-Origin", "*")
        ctx.handler.end_headers()
        ctx.handler.wfile.write(ctx.resp_body)
        self._inc("allowed")
        self._dashboard_cost_timeline.append(
            {
                "timestamp": time.time(),
                "cumulative_cost": float(self._cost_tracker.get_daily_total()),
            }
        )
        if ctx.resp_status >= 400:
            sev = "critical" if ctx.resp_status >= 500 else "high"
            self._add_dashboard_event(
                "upstream_response",
                sev,
                f"Upstream returned HTTP {ctx.resp_status}.",
            )
        response_obj: dict[str, Any] | None = None
        try:
            parsed_obj = json.loads(ctx.resp_body.decode("utf-8"))
            if isinstance(parsed_obj, dict):
                response_obj = parsed_obj
        except Exception:
            response_obj = None
        self._record_session(
            request_id=ctx.request_id,
            session_id=ctx.session_id,
            request_body=ctx.body,
            response_body=response_obj,
            status_code=ctx.resp_status,
            provider=ctx.provider,
            model=str(ctx.body.get("model", ctx.original_model)),
            latency_ms=(time.perf_counter() - ctx.request_started) * 1000.0,
            cost=float(ctx.proc_result.get("cost", 0.0)),
            error=None if ctx.resp_status < 400 else f"http_{ctx.resp_status}",
            metadata={
                "agent_id": ctx.behavior_agent_id,
                "behavioral_state": ctx.behavior_header,
                "cascade_level": ctx.cascade_level_name,
                "loop_state": ctx.loop_warning_header,
            },
        )

    def _handle_post(self, handler: BaseHTTPRequestHandler) -> None:
        self._inc("requests")
        ctx = _RequestContext(
            handler=handler,
            request_started=time.perf_counter(),
            circuit_state_header=self._circuit_breaker.get_state().lower().replace("_", "-"),
            session_id=self._resolve_session_id(handler.headers) if self._recorder is not None else "",
            request_id=uuid.uuid4().hex if self._recorder is not None else "",
        )
        ctx.session_headers = (
            {"X-Orchesis-Session-Id": ctx.session_id, "X-Orchesis-Request-Id": ctx.request_id}
            if self._recorder is not None
            else {}
        )
        try:
            if handler.path == "/kill":
                self._handle_kill(handler)
                return
            if handler.path == "/resume":
                self._handle_resume(handler)
                return
            if self._killed:
                self._inc("blocked")
                self._send_json(
                    handler,
                    503,
                    {
                        "error": {
                            "type": "kill_switch",
                            "message": self._kill_reason or "Emergency kill switch is active",
                            "killed_at": self._kill_time,
                        }
                    },
                )
                return
            if not self._phase_parse(ctx):
                return
            if not self._phase_flow_xray_record(ctx):
                return
            if not self._phase_cascade(ctx):
                return
            if not self._phase_circuit_breaker(ctx):
                return
            if not self._phase_loop_detection(ctx):
                return
            if not self._phase_behavioral(ctx):
                return
            if not self._phase_budget(ctx):
                return
            if not self._phase_policy(ctx):
                return
            if not self._phase_model_router(ctx):
                return
            if not self._phase_secrets(ctx):
                return
            if not self._phase_upstream(ctx):
                return
            if not self._phase_post_upstream(ctx):
                return
            self._phase_send_response(ctx)
        except Exception as error:  # noqa: BLE001
            _HTTP_PROXY_LOGGER.exception("proxy runtime error")
            self._inc("errors")
            self._send_json(
                handler,
                500,
                {"error": {"type": "proxy_error", "message": str(error)}},
                extra_headers=ctx.session_headers,
            )

    def _handle_kill(self, handler: BaseHTTPRequestHandler) -> None:
        payload = self._read_json_body(handler)
        reason = "manual emergency shutdown"
        if isinstance(payload, dict):
            raw_reason = payload.get("reason")
            if isinstance(raw_reason, str) and raw_reason.strip():
                reason = raw_reason.strip()
        self._activate_kill_switch(reason)
        self._send_json(
            handler,
            200,
            {"status": "killed", "reason": self._kill_reason, "killed_at": self._kill_time},
        )

    def _handle_delete(self, handler: BaseHTTPRequestHandler) -> None:
        if handler.path.startswith("/sessions/") and self._recorder is not None:
            session_id = handler.path.split("/sessions/", 1)[1].strip()
            if not session_id:
                self._send_json(handler, 400, {"error": "session_id_required"})
                return
            deleted = self._recorder.delete_session(session_id)
            if deleted:
                self._send_json(handler, 200, {"deleted": True, "session_id": session_id})
                return
            self._send_json(handler, 404, {"deleted": False, "error": "session_not_found"})
            return
        self._send_json(handler, 404, {"error": "Not found"})

    def _handle_resume(self, handler: BaseHTTPRequestHandler) -> None:
        payload = self._read_json_body(handler)
        token = ""
        if isinstance(payload, dict):
            raw_token = payload.get("token")
            if isinstance(raw_token, str):
                token = raw_token
        if token != self._resume_token:
            self._send_json(
                handler,
                403,
                {"error": {"type": "invalid_resume_token", "message": "Resume token is invalid"}},
            )
            return
        self._killed = False
        self._kill_reason = ""
        self._kill_time = ""
        self._secret_trigger_hits = 0
        self._loop_trigger_hits = 0
        self._send_json(handler, 200, {"status": "resumed"})

    def _activate_kill_switch(self, reason: str) -> None:
        self._killed = True
        self._kill_reason = reason
        self._kill_time = datetime.now(timezone.utc).isoformat()
        self._inc("kill_switch_activations")

    def _read_json_body(self, handler: BaseHTTPRequestHandler) -> dict[str, Any] | None:
        try:
            length = int(handler.headers.get("Content-Length", "0") or "0")
        except Exception:
            return None
        if length <= 0:
            return None
        try:
            body = handler.rfile.read(length)
            loaded = json.loads(body.decode("utf-8"))
            if isinstance(loaded, dict):
                return loaded
        except Exception:
            return None
        return None

    def _should_kill_for_cost(self, budget_status: dict[str, Any]) -> bool:
        multiplier_raw = self._kill_auto_cfg.get("cost_multiplier", 5)
        multiplier = float(multiplier_raw) if isinstance(multiplier_raw, int | float) else 5.0
        daily_budget = self._budget_cfg.get("daily")
        if not isinstance(daily_budget, int | float) or daily_budget <= 0:
            return False
        spent = budget_status.get("daily_spent", 0.0)
        safe_spent = float(spent) if isinstance(spent, int | float) else 0.0
        return safe_spent >= float(daily_budget) * multiplier

    def _should_kill_for_secrets(self) -> bool:
        threshold_raw = self._kill_auto_cfg.get("secrets_threshold", 3)
        threshold = int(threshold_raw) if isinstance(threshold_raw, int | float) else 3
        return self._secret_trigger_hits >= max(1, threshold)

    def _should_kill_for_loops(self) -> bool:
        threshold_raw = self._kill_auto_cfg.get("loops_threshold", 5)
        threshold = int(threshold_raw) if isinstance(threshold_raw, int | float) else 5
        return self._loop_trigger_hits >= max(1, threshold)

    @staticmethod
    def _resolve_session_id(headers: Any) -> str:
        sid = headers.get("X-Session") or headers.get("x-session")
        if not isinstance(sid, str) or not sid.strip():
            sid = headers.get("X-Orchesis-Session-Id") or headers.get("x-orchesis-session-id")
        if isinstance(sid, str) and sid.strip():
            return sid.strip()
        return uuid.uuid4().hex

    def _record_session(
        self,
        *,
        request_id: str,
        session_id: str,
        request_body: dict[str, Any],
        response_body: dict[str, Any] | None,
        status_code: int,
        provider: str,
        model: str,
        latency_ms: float,
        cost: float,
        error: str | None,
        metadata: dict[str, Any],
    ) -> None:
        if self._recorder is None:
            return
        exclude = self._recording_cfg.get("exclude_models", [])
        if isinstance(exclude, list) and model in exclude:
            return
        include_response = bool(self._recording_cfg.get("include_response_body", True))
        record = SessionRecord(
            request_id=request_id,
            session_id=session_id,
            timestamp=time.time(),
            request=request_body,
            response=response_body if include_response else None,
            status_code=int(status_code),
            provider=provider,
            model=model,
            latency_ms=float(latency_ms),
            cost=float(cost),
            error=error,
            metadata=metadata,
        )
        self._recorder.record(record)

    def _build_forward_headers(self, source: Any, payload: bytes) -> dict[str, str]:
        headers: dict[str, str] = {"Content-Type": "application/json", "Content-Length": str(len(payload))}
        pass_headers = {
            "authorization",
            "x-api-key",
            "anthropic-version",
            "anthropic-beta",
            "openai-organization",
            "openai-project",
        }
        for key in source.keys():
            lowered = str(key).lower()
            if lowered in pass_headers:
                value = source.get(key)
                if isinstance(value, str):
                    headers[str(key)] = value
        return headers

    @staticmethod
    def _copy_upstream_headers(handler: BaseHTTPRequestHandler, headers: dict[str, str], body_len: int) -> None:
        skip = {"transfer-encoding", "connection", "content-length"}
        for key, value in headers.items():
            if str(key).lower() in skip:
                continue
            handler.send_header(str(key), str(value))
        handler.send_header("Content-Length", str(body_len))

    def _get_upstream(self, provider: str, headers: Any) -> str:
        custom = headers.get("X-Orchesis-Upstream")
        if isinstance(custom, str) and custom.strip():
            return custom.strip().rstrip("/")
        return self._config.upstream.get(provider, self._config.upstream.get("openai", "https://api.openai.com"))

    @staticmethod
    def _detect_provider(parsed_provider: str, headers: Any) -> str:
        anthropic_header = headers.get("x-api-key") or headers.get("Anthropic-Version")
        if anthropic_header:
            return "anthropic"
        auth = headers.get("Authorization")
        if isinstance(auth, str) and auth.startswith("Bearer "):
            return "openai"
        return parsed_provider if parsed_provider in {"anthropic", "openai"} else "openai"

    def _send_json(
        self,
        handler: BaseHTTPRequestHandler,
        status: int,
        payload: dict[str, Any],
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(body)))
        if isinstance(extra_headers, dict):
            for key, value in extra_headers.items():
                handler.send_header(str(key), str(value))
        if self._config.cors:
            handler.send_header("Access-Control-Allow-Origin", "*")
        handler.end_headers()
        handler.wfile.write(body)
