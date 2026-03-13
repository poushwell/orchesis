"""FastAPI proxy layer using Orchesis rule engine."""

import asyncio
import concurrent.futures
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
import http.client
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
from orchesis.alerting import AlertConfig, AlertEvent, AlertManager, AlertSeverity
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
from orchesis.loop_detector import ContentLoopDetector, LoopDetector
from orchesis.metrics import MetricsCollector
from orchesis.model_router import ModelRouter
from orchesis.cascade import CascadeDecision, CascadeLevel, CascadeRouter
from orchesis.otel import OTelEmitter, ProxySpanEmitter, TraceContext
from orchesis.otel_export import OTLPExportConfig, OTLPSpanExporter
from orchesis.policy_store import PolicyStore
from orchesis.state import RateLimitTracker
from orchesis.structured_log import StructuredLogger
from orchesis.telemetry import JsonlEmitter
from orchesis.webhooks import WebhookConfig, WebhookEmitter
from orchesis.request_parser import ParsedResponse, parse_request, parse_response
from orchesis.recorder import SessionRecord, SessionRecorder
from orchesis.response_handler import ResponseProcessor, SECRET_PATTERNS
from orchesis.session_risk import RiskSignal, SessionRiskAccumulator
from orchesis.flow_xray import FlowAnalyzer, FlowXRayConfig
from orchesis.ars import AgentReliabilityScore
from orchesis.adaptive_detector import AdaptiveDetector
from orchesis.community import CommunityClient
from orchesis.mast_detectors import MASTDetectors
from orchesis.message_chain import validate_tool_chain
from orchesis.context_optimizer import ContextOptimizer
from orchesis.auto_healer import AutoHealer
from orchesis.thompson_router import ThompsonRouter
from orchesis.agent_discovery import AgentDiscovery
from orchesis.tool_policy import ToolPolicyEngine
from orchesis.cost_velocity import CostVelocity
from orchesis.dashboard import get_dashboard_html
from orchesis.air_export import export_session_to_air
from orchesis import __version__ as ORCHESIS_VERSION
from orchesis.compliance import ComplianceEngine, Framework, Severity
from orchesis.connection_pool import ConnectionPool, PoolConfig, PooledConnection
from orchesis.experiment import ExperimentConfig, ExperimentManager
from orchesis.context_engine import ContextConfig, ContextEngine
from orchesis.threat_intel import ThreatIntelConfig, ThreatMatcher
from orchesis.semantic_cache import SemanticCache, SemanticCacheConfig
from orchesis.spend_rate import SpendRateDetector, SpendWindow

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


class PooledThreadHTTPServer(HTTPServer):
    """HTTPServer with bounded worker pool."""

    def __init__(self, server_address: tuple[str, int], request_handler_class: Any, max_workers: int = 200):
        super().__init__(server_address, request_handler_class)
        self._pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=max(1, int(max_workers)),
            thread_name_prefix="orchesis-worker",
        )

    def process_request(self, request: Any, client_address: Any) -> None:
        self._pool.submit(self.process_request_thread, request, client_address)

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)

    def server_close(self) -> None:
        super().server_close()
        self._pool.shutdown(wait=True, cancel_futures=False)


_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class ProxyComponents:
    """Shared policy-driven component instances used by both proxy classes."""

    behavioral_detector: BehavioralDetector
    recorder: SessionRecorder | None
    context_engine: ContextEngine | None
    threat_matcher: ThreatMatcher | None
    semantic_cache: SemanticCache | None
    compliance_engine: ComplianceEngine
    flow_tracker: FlowAnalyzer | None


def _resolve_compliance_frameworks(compliance_cfg: dict[str, Any]) -> list[Framework]:
    tokens = compliance_cfg.get("frameworks", ["owasp_llm_top10", "nist_ai_rmf"])
    resolved: list[Framework] = []
    if isinstance(tokens, list):
        for token in tokens:
            framework = ComplianceEngine._framework_from_alias(token if isinstance(token, str) else None)
            if framework is not None and framework not in resolved:
                resolved.append(framework)
    if not resolved:
        resolved = [Framework.OWASP_LLM_TOP_10, Framework.NIST_AI_RMF]
    return resolved


def _init_components(policy: dict[str, Any], *, policy_path: str = "policy.yaml") -> ProxyComponents:
    """Initialize shared proxy components from policy configuration."""
    behavioral_cfg = policy.get("behavioral_fingerprint")
    behavioral_cfg = behavioral_cfg if isinstance(behavioral_cfg, dict) else {}
    behavioral_detector = BehavioralDetector(behavioral_cfg)

    recording_cfg = policy.get("recording")
    recording_cfg = recording_cfg if isinstance(recording_cfg, dict) else {}
    recorder = (
        SessionRecorder(
            storage_path=str(recording_cfg.get("storage_path", ".orchesis/sessions")),
            compress=bool(recording_cfg.get("compress", True)),
            max_file_size_mb=int(recording_cfg.get("max_file_size_mb", 10)),
        )
        if bool(recording_cfg.get("enabled", False))
        else None
    )

    context_engine: ContextEngine | None = None
    context_cfg = policy.get("context_engine")
    if isinstance(context_cfg, dict) and bool(context_cfg.get("enabled", False)):
        cfg = ContextConfig(
            enabled=True,
            strategies=list(context_cfg.get("strategies", ["dedup", "trim_tool_results", "trim_system_dups"])),
            max_context_tokens=int(context_cfg.get("max_context_tokens", 0)),
            token_budget_reserve=int(context_cfg.get("token_budget_reserve", 4096)),
            sliding_window_size=int(context_cfg.get("sliding_window_size", 0)),
            preserve_system=bool(context_cfg.get("preserve_system", True)),
            max_tool_result_tokens=int(context_cfg.get("max_tool_result_tokens", 2000)),
            dedup_window=int(context_cfg.get("dedup_window", 50)),
            track_savings=bool(context_cfg.get("track_savings", True)),
        )
        context_engine = ContextEngine(cfg)

    threat_matcher: ThreatMatcher | None = None
    threat_cfg = policy.get("threat_intel")
    if isinstance(threat_cfg, dict) and bool(threat_cfg.get("enabled", False)):
        default_severity = {
            "critical": "block",
            "high": "warn",
            "medium": "log",
            "low": "log",
            "info": "log",
        }
        policy_sev = threat_cfg.get("severity_actions")
        if isinstance(policy_sev, dict):
            default_severity = {**default_severity, **policy_sev}
        ti_cfg = ThreatIntelConfig(
            enabled=True,
            default_action=str(threat_cfg.get("default_action", "warn")),
            severity_actions=default_severity,
            custom_signatures=list(threat_cfg.get("custom_signatures", [])),
            disabled_threats=list(threat_cfg.get("disabled_threats", [])),
            max_matches_per_request=int(threat_cfg.get("max_matches_per_request", 10)),
        )
        threat_matcher = ThreatMatcher(ti_cfg)

    semantic_cache: SemanticCache | None = None
    semantic_cfg = policy.get("semantic_cache")
    if isinstance(semantic_cfg, dict) and bool(semantic_cfg.get("enabled", False)):
        sc_cfg = SemanticCacheConfig(
            enabled=True,
            max_entries=int(semantic_cfg.get("max_entries", 2000)),
            ttl_seconds=float(semantic_cfg.get("ttl_seconds", 600)),
            simhash_threshold=int(semantic_cfg.get("simhash_threshold", 8)),
            jaccard_threshold=float(semantic_cfg.get("jaccard_threshold", 0.6)),
            min_content_length=int(semantic_cfg.get("min_content_length", 20)),
            max_content_length=int(semantic_cfg.get("max_content_length", 50000)),
            cacheable_models=list(semantic_cfg.get("cacheable_models", [])),
            exclude_tool_calls=bool(semantic_cfg.get("exclude_tool_calls", True)),
            track_savings=bool(semantic_cfg.get("track_savings", True)),
        )
        semantic_cache = SemanticCache(sc_cfg)

    flow_cfg = policy.get("flow_xray")
    flow_cfg = flow_cfg if isinstance(flow_cfg, dict) else {}
    flow_tracker: FlowAnalyzer | None = (
        FlowAnalyzer(
            FlowXRayConfig(
                enabled=bool(flow_cfg.get("enabled", False)),
                max_sessions=int(flow_cfg.get("max_sessions", 1000)),
                redundancy_window_seconds=float(flow_cfg.get("redundancy_window_seconds", 30.0)),
                retry_threshold=int(flow_cfg.get("retry_threshold", 3)),
                ping_pong_min_repetitions=int(flow_cfg.get("ping_pong_min_repetitions", 3)),
                token_waste_stddev_threshold=float(flow_cfg.get("token_waste_stddev_threshold", 2.0)),
                latency_spike_threshold=float(flow_cfg.get("latency_spike_threshold", 0.5)),
                suspicious_tool_chains=flow_cfg.get("suspicious_tool_chains", []),
                enable_security_patterns=bool(flow_cfg.get("enable_security_patterns", True)),
                enable_efficiency_patterns=bool(flow_cfg.get("enable_efficiency_patterns", True)),
                enable_performance_patterns=bool(flow_cfg.get("enable_performance_patterns", True)),
            )
        )
        if bool(flow_cfg.get("enabled", False))
        else None
    )

    compliance_cfg = policy.get("compliance")
    compliance_cfg = compliance_cfg if isinstance(compliance_cfg, dict) else {}
    compliance_engine = ComplianceEngine(
        policy_path=policy_path or "policy.yaml",
        frameworks=_resolve_compliance_frameworks(compliance_cfg),
        max_findings=int(compliance_cfg.get("max_findings", 10000)),
        enabled=bool(compliance_cfg.get("enabled", True)),
    )

    return ProxyComponents(
        behavioral_detector=behavioral_detector,
        recorder=recorder,
        context_engine=context_engine,
        threat_matcher=threat_matcher,
        semantic_cache=semantic_cache,
        compliance_engine=compliance_engine,
        flow_tracker=flow_tracker,
    )


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
        recording_cfg = self._policy.get("recording")
        self._recording_cfg = recording_cfg if isinstance(recording_cfg, dict) else {}
        compliance_cfg = self._policy.get("compliance")
        self._compliance_cfg = compliance_cfg if isinstance(compliance_cfg, dict) else {}
        flow_cfg = self._policy.get("flow_xray")
        self._flow_cfg = flow_cfg if isinstance(flow_cfg, dict) else {}
        components = _init_components(self._policy, policy_path="policy.yaml")
        self._behavioral_detector = components.behavioral_detector
        self._recorder = components.recorder
        self._context_engine = components.context_engine
        self._threat_matcher = components.threat_matcher
        self._semantic_cache = components.semantic_cache
        self._compliance_engine = components.compliance_engine
        self._flow_tracker = components.flow_tracker
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
            "version": "0.1.0",
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
    is_streaming: bool = False
    streaming_events: list[str] = field(default_factory=list)
    streaming_text: str = ""
    streaming_chunks: int = 0
    experiment_id: str = ""
    variant_name: str = ""
    was_escalated: bool = False
    was_loop_detected: bool = False
    context_tokens_saved: int = 0
    context_strategies: list[str] = field(default_factory=list)
    threat_matches: list[Any] = field(default_factory=list)
    from_semantic_cache: bool = False
    trace_ctx: Any = None  # TraceContext when otel enabled
    root_span: Any = None  # SpanData when otel enabled
    semantic_cache_type: str = ""  # "exact" or "semantic"
    heartbeat_detected: bool = False
    content_loop_count: int = 0
    spend_rate_per_min: float = 0.0
    request_saved_usd: float = 0.0
    adaptive_detection_result: Any = None
    mast_request_findings: list[Any] = field(default_factory=list)
    was_auto_healed: bool = False
    healing_pre_score: float = 0.0
    thompson_category: str = ""
    thompson_selected_model: str = ""


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
        proxy_engine_cfg = self._policy.get("proxy")
        self._proxy_engine_cfg = proxy_engine_cfg if isinstance(proxy_engine_cfg, dict) else {}
        self._max_workers = int(self._proxy_engine_cfg.get("max_workers", 200))
        if self._max_workers <= 0:
            self._max_workers = 200
        pool_cfg_raw = self._proxy_engine_cfg.get("connection_pool", {})
        pool_cfg = pool_cfg_raw if isinstance(pool_cfg_raw, dict) else {}
        self._connection_pool = ConnectionPool(
            PoolConfig(
                max_connections_per_host=int(pool_cfg.get("max_per_host", 10)),
                max_total_connections=int(pool_cfg.get("max_total", 50)),
                idle_timeout=float(pool_cfg.get("idle_timeout", 60.0)),
                connection_timeout=float(pool_cfg.get("connection_timeout", self._config.timeout)),
                retry_on_connection_error=bool(pool_cfg.get("retry_on_connection_error", True)),
                max_retries=int(pool_cfg.get("max_retries", 2)),
            )
        )
        streaming_cfg_raw = self._proxy_engine_cfg.get("streaming", {})
        streaming_cfg = streaming_cfg_raw if isinstance(streaming_cfg_raw, dict) else {}
        self._streaming_enabled = bool(streaming_cfg.get("enabled", True))
        self._streaming_buffer_size = int(streaming_cfg.get("buffer_size", 4096))
        if self._streaming_buffer_size <= 0:
            self._streaming_buffer_size = 4096
        self._streaming_max_accumulated_events = int(streaming_cfg.get("max_accumulated_events", 10000))
        if self._streaming_max_accumulated_events <= 0:
            self._streaming_max_accumulated_events = 10000
        self._streaming_count = 0
        self._streaming_chunks_total = 0
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
        self._content_loop_detector: ContentLoopDetector | None = None
        content_loop_cfg = self._loop_cfg.get("content_loop")
        if isinstance(content_loop_cfg, dict) and bool(content_loop_cfg.get("enabled", False)):
            self._content_loop_detector = ContentLoopDetector(
                window_seconds=int(content_loop_cfg.get("window_seconds", 300)),
                max_identical=int(content_loop_cfg.get("max_identical", 5)),
                cooldown_seconds=int(content_loop_cfg.get("cooldown_seconds", 300)),
                hash_prefix_len=int(content_loop_cfg.get("hash_prefix_len", 256)),
            )
        spend_rate_cfg_raw = self._budget_cfg.get("spend_rate")
        self._spend_rate_cfg = spend_rate_cfg_raw if isinstance(spend_rate_cfg_raw, dict) else {}
        self._spend_rate_detector: SpendRateDetector | None = None
        if bool(self._spend_rate_cfg.get("enabled", False)):
            windows_cfg = self._spend_rate_cfg.get("windows")
            windows: list[SpendWindow] = []
            if isinstance(windows_cfg, list):
                for item in windows_cfg:
                    if not isinstance(item, dict):
                        continue
                    seconds = item.get("seconds")
                    max_spend = item.get("max_spend")
                    if not isinstance(seconds, int | float) or not isinstance(max_spend, int | float):
                        continue
                    if int(seconds) <= 0:
                        continue
                    windows.append(SpendWindow(window_seconds=int(seconds), max_spend=float(max_spend)))
            self._spend_rate_detector = SpendRateDetector(
                windows=windows or None,
                spike_multiplier=float(self._spend_rate_cfg.get("spike_multiplier", 5.0)),
                heartbeat_cost_threshold=float(self._spend_rate_cfg.get("heartbeat_cost_threshold", 0.10)),
                pause_seconds=int(self._spend_rate_cfg.get("pause_seconds", 300)),
            )
        self._estimated_avg_request_cost_usd = 0.05
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
        exp_cfg_raw = self._policy.get("experiments")
        task_cfg_raw = self._policy.get("task_tracking")
        exp_cfg = exp_cfg_raw if isinstance(exp_cfg_raw, dict) else {}
        task_cfg = task_cfg_raw if isinstance(task_cfg_raw, dict) else {}
        self._experiment_manager: ExperimentManager | None = None
        if bool(exp_cfg.get("enabled", False)) or bool(task_cfg.get("enabled", False)):
            cfg = ExperimentConfig(
                max_experiments=int(exp_cfg.get("max_experiments", 10)),
                default_min_sample_size=int(exp_cfg.get("default_min_sample_size", 30)),
                auto_stop_on_significance=bool(exp_cfg.get("auto_stop_on_significance", True)),
                significance_threshold=float(exp_cfg.get("significance_threshold", 0.95)),
                max_tracked_sessions=int(task_cfg.get("max_tracked_sessions", 5000)),
                idle_timeout_seconds=float(task_cfg.get("idle_timeout_seconds", 300)),
                min_turns_for_success=int(task_cfg.get("min_turns_for_success", 1)),
                consecutive_errors_threshold=int(task_cfg.get("consecutive_errors_threshold", 3)),
            )
            self._experiment_manager = ExperimentManager(cfg)
        behavioral_cfg = self._policy.get("behavioral_fingerprint")
        self._behavioral_cfg = behavioral_cfg if isinstance(behavioral_cfg, dict) else {}
        recording_cfg = self._policy.get("recording")
        self._recording_cfg = recording_cfg if isinstance(recording_cfg, dict) else {}
        compliance_cfg = self._policy.get("compliance")
        self._compliance_cfg = compliance_cfg if isinstance(compliance_cfg, dict) else {}
        components = _init_components(self._policy, policy_path=self._policy_path or "policy.yaml")
        self._behavioral_detector = components.behavioral_detector
        self._recorder = components.recorder
        self._context_engine = components.context_engine
        self._threat_matcher = components.threat_matcher
        self._semantic_cache = components.semantic_cache
        self._flow_analyzer = components.flow_tracker
        self._compliance_engine = components.compliance_engine
        otel_cfg = self._policy.get("otel_export")
        self._otlp_exporter = None
        self._span_emitter = None
        if isinstance(otel_cfg, dict) and bool(otel_cfg.get("enabled", False)):
            export_cfg = OTLPExportConfig(
                enabled=True,
                endpoint=str(otel_cfg.get("endpoint", "http://localhost:4318")),
                traces_path=str(otel_cfg.get("traces_path", "/v1/traces")),
                headers=dict(otel_cfg.get("headers", {})),
                batch_size=int(otel_cfg.get("batch_size", 50)),
                flush_interval_seconds=float(otel_cfg.get("flush_interval_seconds", 5.0)),
                max_queue_size=int(otel_cfg.get("max_queue_size", 2000)),
                resource_attributes={
                    "service.name": str(otel_cfg.get("service_name", "orchesis-proxy")),
                    "service.version": "0.8.0",
                    **(otel_cfg.get("resource_attributes") or {}),
                },
            )
            self._otlp_exporter = OTLPSpanExporter(export_cfg)
            self._otlp_exporter.start()
            self._span_emitter = ProxySpanEmitter(
                jsonl_path=".orchesis/traces.jsonl",
                otlp_exporter=self._otlp_exporter,
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
        self._alert_manager: AlertManager | None = None
        alerts_cfg = self._policy.get("alerts")
        if isinstance(alerts_cfg, dict):
            alert_cfg = AlertConfig.from_policy_dict(alerts_cfg)
            self._alert_manager = AlertManager(alert_cfg)
        session_risk_cfg = self._policy.get("session_risk")
        self._session_risk: SessionRiskAccumulator | None = None
        if isinstance(session_risk_cfg, dict) and bool(session_risk_cfg.get("enabled", False)):
            self._session_risk = SessionRiskAccumulator(
                warn_threshold=float(session_risk_cfg.get("warn_threshold", 30.0)),
                block_threshold=float(session_risk_cfg.get("block_threshold", 60.0)),
                decay_half_life_seconds=float(session_risk_cfg.get("decay_half_life_seconds", 300.0)),
                max_signals_per_session=int(session_risk_cfg.get("max_signals_per_session", 100)),
                session_ttl_seconds=float(session_risk_cfg.get("session_ttl_seconds", 3600.0)),
                category_diversity_bonus=float(session_risk_cfg.get("category_diversity_bonus", 10.0)),
                enabled=True,
            )
        ars_cfg = self._policy.get("ars")
        self._ars: AgentReliabilityScore | None = None
        if isinstance(ars_cfg, dict) and bool(ars_cfg.get("enabled", False)):
            self._ars = AgentReliabilityScore(
                weights=ars_cfg.get("weights") if isinstance(ars_cfg.get("weights"), dict) else None,
                latency_baseline_ms=float(ars_cfg.get("latency_baseline_ms", 2000.0)),
                enabled=True,
            )
        self._telemetry_collector = None
        telemetry_cfg = self._policy.get("telemetry_export")
        if isinstance(telemetry_cfg, dict) and bool(telemetry_cfg.get("enabled", False)):
            try:
                from orchesis.telemetry_export import TelemetryCollector

                self._telemetry_collector = TelemetryCollector(
                    max_records=int(telemetry_cfg.get("max_records", 100_000)),
                    auto_export_path=(
                        str(telemetry_cfg.get("auto_export_path"))
                        if isinstance(telemetry_cfg.get("auto_export_path"), str)
                        and telemetry_cfg.get("auto_export_path")
                        else None
                    ),
                    auto_export_interval=float(telemetry_cfg.get("auto_export_interval", 300.0)),
                    enabled=True,
                )
            except Exception:
                self._telemetry_collector = None
        self._community: CommunityClient | None = None
        community_cfg = self._policy.get("community")
        if isinstance(community_cfg, dict) and bool(community_cfg.get("enabled", False)):
            try:
                self._community = CommunityClient(community_cfg)
                self._community.start()
            except Exception:
                self._community = None
        adaptive_cfg = self._policy.get("adaptive_detection")
        self._adaptive_detector: AdaptiveDetector | None = None
        if isinstance(adaptive_cfg, dict) and bool(adaptive_cfg.get("enabled", False)):
            self._adaptive_detector = AdaptiveDetector(adaptive_cfg)
        context_opt_cfg = self._policy.get("context_optimizer")
        self._context_optimizer: ContextOptimizer | None = None
        if isinstance(context_opt_cfg, dict) and bool(context_opt_cfg.get("enabled", False)):
            self._context_optimizer = ContextOptimizer(context_opt_cfg)
        mast_cfg = self._policy.get("mast")
        self._mast: MASTDetectors | None = None
        if isinstance(mast_cfg, dict) and bool(mast_cfg.get("enabled", False)):
            self._mast = MASTDetectors(mast_cfg)
        auto_healing_cfg = self._policy.get("auto_healing")
        self._auto_healer: AutoHealer | None = None
        if isinstance(auto_healing_cfg, dict) and bool(auto_healing_cfg.get("enabled", False)):
            self._auto_healer = AutoHealer(auto_healing_cfg)
        thompson_cfg = self._policy.get("thompson_router")
        self._thompson: ThompsonRouter | None = None
        if isinstance(thompson_cfg, dict) and bool(thompson_cfg.get("enabled", False)):
            self._thompson = ThompsonRouter(thompson_cfg)
        self._agent_discovery = AgentDiscovery(self._policy.get("agent_discovery"))
        self._tool_policy: ToolPolicyEngine | None = None
        tools_cfg_raw = self._policy.get("capabilities", {})
        tools_cfg = tools_cfg_raw.get("tools") if isinstance(tools_cfg_raw, dict) else {}
        if isinstance(tools_cfg, dict) and (
            isinstance(tools_cfg.get("rules"), dict) or isinstance(tools_cfg.get("allowed"), list)
        ):
            self._tool_policy = ToolPolicyEngine(tools_cfg)
        self._cost_velocity = CostVelocity()
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
        if self._content_loop_detector is not None:
            payload["content_loop"] = self._content_loop_detector.stats
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
        if self._experiment_manager is not None:
            exps = self._experiment_manager.list_experiments()
            running = sum(1 for e in exps if e.get("status") == "running")
            total_assignments = sum(
                sum(v.get("requests", 0) for v in e.get("variants", []))
                for e in exps
            )
            task_stats = self._experiment_manager._task_tracker.get_stats()
            payload["experiments"] = {
                "active": running,
                "total": len(exps),
                "total_assignments": total_assignments,
            }
            payload["task_tracking"] = task_stats
        if self._compliance_engine is not None:
            payload["compliance"] = self._compliance_engine.get_stats()
        if self._context_engine is not None:
            payload["context_engine"] = self._context_engine.get_stats()
        if self._threat_matcher is not None:
            payload["threat_intel"] = self._threat_matcher.get_stats()
        if self._semantic_cache is not None:
            payload["semantic_cache"] = self._semantic_cache.get_stats()
        if self._spend_rate_detector is not None:
            payload["spend_rate"] = self._spend_rate_detector.stats
        thread_queue = 0
        if isinstance(self._server, PooledThreadHTTPServer):
            try:
                thread_queue = int(self._server._pool._work_queue.qsize())  # noqa: SLF001
            except Exception:
                thread_queue = 0
        if self._otlp_exporter is not None:
            payload["otel_export"] = self._otlp_exporter.get_stats()
        if self._alert_manager is not None:
            payload["alerts"] = self._alert_manager.stats
        if self._session_risk is not None:
            payload["session_risk"] = self._session_risk.stats
        if self._ars is not None:
            payload["ars"] = self._ars.stats
        if self._adaptive_detector is not None:
            payload["adaptive_detection"] = self._adaptive_detector.get_stats()
        if self._mast is not None:
            payload["mast"] = self._mast.get_stats()
        if self._context_optimizer is not None:
            payload["context_optimizer"] = self._context_optimizer.get_stats()
        if self._auto_healer is not None:
            payload["auto_healing"] = self._auto_healer.get_stats()
        if self._thompson is not None:
            payload["thompson_router"] = self._thompson.get_model_stats()
        if self._agent_discovery is not None and self._agent_discovery.enabled:
            payload["agent_discovery"] = self._agent_discovery.get_stats()
        if self._tool_policy is not None:
            payload["tool_policy"] = self._tool_policy.get_tool_stats()
        payload["cost_velocity"] = self._cost_velocity.get_stats()
        if self._community is not None:
            payload["community"] = self._community.get_status()
        payload["proxy_engine"] = {
            "thread_pool": {
                "max_workers": int(self._max_workers),
                "active_threads": thread_queue,
            },
            "connection_pool": self._connection_pool.get_stats(),
            "streaming": {
                "enabled": self._streaming_enabled,
                "total_streamed_requests": int(self._streaming_count),
                "total_streamed_chunks": int(self._streaming_chunks_total),
            },
        }
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

        self._server = PooledThreadHTTPServer(
            (self._config.host, self._config.port),
            _Handler,
            max_workers=self._max_workers,
        )
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
        self._connection_pool.close_all()
        if self._recorder is not None:
            self._recorder.close_all()
        if self._otlp_exporter is not None:
            self._otlp_exporter.stop()
        if self._alert_manager is not None:
            self._alert_manager.stop()
        if self._telemetry_collector is not None:
            self._telemetry_collector.stop()
        if self._community is not None:
            self._community.stop()
        if self._thompson is not None:
            self._thompson.stop()

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
            "cost_velocity": self._cost_velocity.get_stats(),
            "fleet_health": self._fleet_health_grade(),
            "money_saved_usd": self._estimate_money_saved(),
            "circuit_breakers": circuit_breakers,
            "budget": budget,
            "recent_events": recent_events[:20],
            "cost_timeline": list(self._dashboard_cost_timeline),
            "flow_xray": flow_stats,
            "connection_pool": stats.get("proxy_engine", {}).get("connection_pool", {}),
            "savings": self._build_savings_payload(),
        }

    def _fleet_health_grade(self) -> str:
        if self._agent_discovery is None or not self._agent_discovery.enabled:
            return "A"
        profiles = self._agent_discovery.get_all_agents()
        if not profiles:
            return "A"
        rank = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}
        worst = "A"
        for item in profiles:
            grade = str(item.ars_grade or "").upper()
            if grade not in rank:
                continue
            if rank[grade] > rank[worst]:
                worst = grade
        return worst

    def _estimate_money_saved(self) -> float:
        stats = self.stats
        cache_tokens = 0.0
        context_tokens = 0.0
        sem = stats.get("semantic_cache", {})
        if isinstance(sem, dict):
            cache_tokens = float(sem.get("total_tokens_saved", 0.0) or 0.0)
        context_opt = stats.get("context_optimizer", {})
        if isinstance(context_opt, dict):
            original = float(context_opt.get("total_original_tokens", 0.0) or 0.0)
            optimized = float(context_opt.get("total_optimized_tokens", 0.0) or 0.0)
            context_tokens = max(0.0, original - optimized)
        return round((cache_tokens + context_tokens) * 0.000003, 6)

    def _build_savings_payload(self) -> dict[str, Any]:
        stats = self.stats
        semantic_stats = stats.get("semantic_cache", {}) if isinstance(stats.get("semantic_cache"), dict) else {}
        cache_savings = float(semantic_stats.get("total_cost_saved_usd", 0.0))
        cache_hits = int(semantic_stats.get("exact_hits", 0)) + int(semantic_stats.get("semantic_hits", 0))
        cascade_savings = float(self._cost_tracker.get_cascade_savings_today())
        cascade_stats = stats.get("cascade_requests_by_level", {})
        cascaded_requests = 0
        if isinstance(cascade_stats, dict):
            cascaded_requests = int(
                cascade_stats.get("trivial", 0)
                + cascade_stats.get("simple", 0)
                + cascade_stats.get("medium", 0)
                + cascade_stats.get("complex", 0)
            )
        loop_blocked = 0
        if self._content_loop_detector is not None:
            loop_blocked = int(self._content_loop_detector.stats.get("blocked", 0))
        loop_savings = float(loop_blocked * self._estimated_avg_request_cost_usd)
        total_savings = cache_savings + cascade_savings + loop_savings
        return {
            "cache_savings": round(cache_savings, 6),
            "cascade_savings": round(cascade_savings, 6),
            "loop_savings": round(loop_savings, 6),
            "total_savings": round(total_savings, 6),
            "details": {
                "cache_hits": cache_hits,
                "cascaded_requests": cascaded_requests,
                "loops_blocked": loop_blocked,
            },
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
            handler.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
            handler.send_header("Pragma", "no-cache")
            handler.send_header("Expires", "0")
            if self._config.cors:
                handler.send_header("Access-Control-Allow-Origin", "*")
            handler.end_headers()
            handler.wfile.write(payload)
            return
        if path == "/favicon.ico":
            handler.send_response(204)
            handler.send_header("Content-Length", "0")
            if self._config.cors:
                handler.send_header("Access-Control-Allow-Origin", "*")
            handler.end_headers()
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
        if path in {"/stats", "/api/v1/stats"}:
            self._send_json(handler, 200, self.stats)
            return
        if path == "/api/v1/telemetry/stats":
            if self._telemetry_collector is None:
                self._send_json(handler, 200, {"enabled": False})
                return
            self._send_json(handler, 200, self._telemetry_collector.stats)
            return
        if path == "/api/v1/telemetry/export":
            if self._telemetry_collector is None:
                self._send_json(handler, 200, {"enabled": False})
                return
            last_raw = (query_params.get("last") or ["0"])[0]
            try:
                last_n = max(0, int(last_raw))
            except Exception:
                last_n = 0
            fmt = str((query_params.get("format") or ["json"])[0]).strip().lower()
            records = self._telemetry_collector.get_records(last_n=last_n)
            if fmt == "jsonl":
                lines = "\n".join(json.dumps(item, default=str) for item in records)
                payload = lines.encode("utf-8")
                handler.send_response(200)
                handler.send_header("Content-Type", "application/x-ndjson")
                handler.send_header("Content-Length", str(len(payload)))
                if self._config.cors:
                    handler.send_header("Access-Control-Allow-Origin", "*")
                handler.end_headers()
                handler.wfile.write(payload)
                return
            self._send_json(handler, 200, {"records": records, "count": len(records)})
            return
        if path == "/api/v1/alerts":
            payload = (
                {"enabled": self._alert_manager.enabled, "stats": self._alert_manager.stats}
                if self._alert_manager is not None
                else {"enabled": False, "stats": {"sent": 0, "dropped_rate_limit": 0, "dropped_severity": 0, "errors": 0}}
            )
            self._send_json(handler, 200, payload)
            return
        if path == "/api/v1/detection":
            if self._adaptive_detector is None:
                self._send_json(handler, 200, {"enabled": False})
                return
            self._send_json(handler, 200, self._adaptive_detector.get_all_agents())
            return
        if path.startswith("/api/v1/detection/"):
            agent_id = path.split("/api/v1/detection/", 1)[1].strip("/")
            if self._adaptive_detector is None:
                self._send_json(handler, 200, {"enabled": False})
                return
            self._send_json(handler, 200, self._adaptive_detector.get_agent_status(agent_id))
            return
        if path == "/api/v1/community":
            if self._community is None:
                self._send_json(handler, 200, {"enabled": False})
                return
            self._send_json(handler, 200, asdict(self._community.get_stats()))
            return
        if path.startswith("/api/v1/mast/"):
            agent_id = path.split("/api/v1/mast/", 1)[1].strip("/")
            if self._mast is None:
                self._send_json(handler, 200, {"enabled": False})
                return
            self._send_json(handler, 200, self._mast.get_agent_compliance(agent_id))
            return
        if path.startswith("/api/v1/healing/"):
            agent_id = path.split("/api/v1/healing/", 1)[1].strip("/")
            if self._auto_healer is None:
                self._send_json(handler, 200, {"enabled": False})
                return
            self._send_json(handler, 200, self._auto_healer.get_agent_healing_history(agent_id))
            return
        if path == "/api/v1/agents":
            if self._agent_discovery is None or not self._agent_discovery.enabled:
                self._send_json(handler, 200, {"enabled": False})
                return
            self._send_json(handler, 200, [asdict(item) for item in self._agent_discovery.get_all_agents()])
            return
        if path == "/api/v1/agents/summary":
            if self._agent_discovery is None or not self._agent_discovery.enabled:
                self._send_json(handler, 200, {"enabled": False})
                return
            self._send_json(handler, 200, self._agent_discovery.get_summary())
            return
        if path.startswith("/api/v1/agents/"):
            agent_id = path.split("/api/v1/agents/", 1)[1].strip("/")
            if self._agent_discovery is None or not self._agent_discovery.enabled:
                self._send_json(handler, 200, {"enabled": False})
                return
            profile = self._agent_discovery.get_agent(agent_id)
            if profile is None:
                self._send_json(handler, 200, {"found": False, "agent_id": agent_id})
                return
            self._send_json(handler, 200, asdict(profile))
            return
        if path == "/api/v1/tools":
            if self._tool_policy is None:
                self._send_json(handler, 200, {"enabled": False})
                return
            self._send_json(handler, 200, self._tool_policy.get_tool_stats())
            return
        if path == "/api/v1/tools/blocked":
            if self._tool_policy is None:
                self._send_json(handler, 200, {"enabled": False})
                return
            self._send_json(handler, 200, self._tool_policy.get_blocked_attempts())
            return
        if path == "/api/v1/approvals":
            if self._tool_policy is None:
                self._send_json(handler, 200, {"enabled": False})
                return
            self._send_json(
                handler,
                200,
                {
                    "pending": self._tool_policy.approval_queue.get_pending(),
                    "stats": self._tool_policy.approval_queue.get_stats(),
                },
            )
            return
        if path == "/api/v1/router":
            if self._thompson is None:
                self._send_json(handler, 200, {"enabled": False})
                return
            self._send_json(
                handler,
                200,
                {
                    "enabled": True,
                    "model_stats": self._thompson.get_model_stats(),
                    "report": self._thompson.get_routing_report(),
                },
            )
            return
        if path == "/api/v1/router/recommend":
            if self._thompson is None:
                self._send_json(handler, 200, {"enabled": False})
                return
            self._send_json(handler, 200, self._thompson.get_recommendation())
            return
        if path.startswith("/api/v1/session-risk/"):
            session_id = path.split("/api/v1/session-risk/", 1)[1].strip("/")
            if self._session_risk is None:
                self._send_json(handler, 200, {"error": "session_risk not enabled"})
                return
            state = self._session_risk.get_session_state(session_id)
            self._send_json(handler, 200, state or {"error": "session not found"})
            return
        if path == "/api/v1/ars":
            if self._ars is None:
                self._send_json(handler, 200, {"enabled": False})
                return
            results = self._ars.compute_all()
            self._send_json(
                handler,
                200,
                {
                    "agents": [
                        {
                            "agent_id": item.agent_id,
                            "score": item.score,
                            "grade": item.grade,
                            "components": item.components,
                            "sample_size": item.sample_size,
                            "confidence": item.confidence,
                        }
                        for item in results
                    ]
                },
            )
            return
        if path.startswith("/api/v1/ars/"):
            agent_id = path.split("/api/v1/ars/", 1)[1].strip("/")
            if self._ars is None:
                self._send_json(handler, 200, {"enabled": False})
                return
            result = self._ars.compute(agent_id)
            if result is None:
                self._send_json(handler, 200, {"error": "agent not found"})
                return
            self._send_json(
                handler,
                200,
                {
                    "agent_id": result.agent_id,
                    "score": result.score,
                    "grade": result.grade,
                    "components": result.components,
                    "sample_size": result.sample_size,
                    "confidence": result.confidence,
                },
            )
            return
        if path == "/api/v1/savings":
            self._send_json(handler, 200, self._build_savings_payload())
            return
        if path == "/api/threats" or path == "/api/threats/":
            if self._threat_matcher is None:
                self._send_json(handler, 200, {"threats": []})
                return
            category = (query_params.get("category") or [""])[0]
            severity = (query_params.get("severity") or [""])[0]
            threats = self._threat_matcher.list_threats(
                category=str(category) if category else "",
                severity=str(severity) if severity else "",
            )
            self._send_json(handler, 200, {"threats": threats})
            return
        if path.startswith("/api/threats/") and path != "/api/threats/stats":
            threat_id = path.split("/api/threats/", 1)[1].strip("/")
            if self._threat_matcher is None:
                self._send_json(handler, 404, {"error": "threat_intel_not_enabled"})
                return
            sig = self._threat_matcher.get_threat(threat_id)
            if sig is None:
                self._send_json(handler, 404, {"error": "threat_not_found", "threat_id": threat_id})
                return
            self._send_json(
                handler,
                200,
                {
                    "threat_id": sig.threat_id,
                    "name": sig.name,
                    "category": sig.category.value,
                    "severity": sig.severity.value,
                    "description": sig.description,
                    "detection": sig.detection,
                    "mitigation": sig.mitigation,
                    "owasp_ref": sig.owasp_ref,
                    "mitre_ref": sig.mitre_ref,
                    "references": list(sig.references),
                },
            )
            return
        if path == "/api/threats/stats":
            if self._threat_matcher is None:
                self._send_json(handler, 200, {"enabled": False})
                return
            self._send_json(handler, 200, self._threat_matcher.get_stats())
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
        if path == "/api/experiments" and self._experiment_manager is not None:
            self._send_json(handler, 200, {"experiments": self._experiment_manager.list_experiments()})
            return
        if path.startswith("/api/experiments/") and path.endswith("/results") and self._experiment_manager is not None:
            parts = path.split("/")
            exp_id = parts[3] if len(parts) > 3 else ""
            if exp_id:
                try:
                    result = self._experiment_manager.get_results(exp_id)
                    self._send_json(handler, 200, result.to_dict())
                except ValueError:
                    self._send_json(handler, 404, {"error": "experiment_not_found"})
            else:
                self._send_json(handler, 404, {"error": "experiment_id_required"})
            return
        if path.startswith("/api/experiments/") and path.endswith("/live") and self._experiment_manager is not None:
            parts = path.split("/")
            exp_id = parts[3] if len(parts) > 3 else ""
            if exp_id:
                stats = self._experiment_manager.get_live_stats(exp_id)
                self._send_json(handler, 200, stats)
            else:
                self._send_json(handler, 404, {"error": "experiment_id_required"})
            return
        if path == "/api/tasks/outcomes" and self._experiment_manager is not None:
            outcomes = self._experiment_manager._task_tracker.get_outcome_distribution()
            self._send_json(handler, 200, outcomes)
            return
        if path == "/api/tasks/correlations" and self._experiment_manager is not None:
            correlations = self._experiment_manager._task_tracker.get_correlations()
            self._send_json(handler, 200, correlations)
            return
        if path.startswith("/api/tasks/sessions/") and self._experiment_manager is not None:
            session_id = path.split("/api/tasks/sessions/", 1)[1].strip()
            if session_id:
                state = self._experiment_manager._task_tracker.get_session_state(session_id)
                if state:
                    sess_dict = asdict(state)
                    if hasattr(state.outcome, "value"):
                        sess_dict["outcome"] = state.outcome.value
                    self._send_json(handler, 200, {"session": sess_dict})
                else:
                    self._send_json(handler, 404, {"error": "session_not_found"})
            else:
                self._send_json(handler, 400, {"error": "session_id_required"})
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

    def _run_phase_span(
        self,
        ctx: _RequestContext,
        phase_name: str,
        phase_fn: Any,
        extra_attrs: dict[str, str | int | float | bool] | None = None,
    ) -> bool:
        """Run a phase and optionally emit a span. Returns phase result."""
        if self._span_emitter is None or ctx.trace_ctx is None:
            return phase_fn(ctx)
        parent_id = ctx.root_span.span_id if ctx.root_span else None
        span = self._span_emitter.create_phase_span(phase_name, ctx.trace_ctx, parent_id or "")
        try:
            ok = phase_fn(ctx)
            attrs = dict(extra_attrs or {})
            if phase_name == "cascade":
                attrs["orchesis.cascade_level"] = getattr(ctx, "cascade_level_name", "") or ""
                attrs["orchesis.cache_hit"] = getattr(ctx, "cascade_cache_state", "") == "hit"
            elif phase_name == "threat_intel":
                attrs["orchesis.threat_detected"] = bool(getattr(ctx, "threat_matches", []))
                matches = getattr(ctx, "threat_matches", []) or []
                attrs["orchesis.threat_ids"] = ",".join(getattr(m, "threat_id", str(m)) for m in matches[:5])[:200]
            elif phase_name == "loop_detection":
                attrs["orchesis.loop_detected"] = getattr(ctx, "was_loop_detected", False)
            elif phase_name == "context":
                attrs["orchesis.context_tokens_saved"] = getattr(ctx, "context_tokens_saved", 0)
            elif phase_name == "post_upstream" and getattr(ctx, "from_semantic_cache", False):
                attrs["orchesis.cache_hit"] = True
                attrs["orchesis.cache_type"] = "semantic"
            self._span_emitter.end_span(span, status="OK" if ok else "ERROR", attributes=attrs)
            return ok
        except Exception:
            self._span_emitter.end_span(span, status="ERROR")
            raise

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
        parsed_session_id = (
            ctx.handler.headers.get("x-openclaw-session")
            or ctx.handler.headers.get("x-session-id")
            or ctx.handler.headers.get("x-request-id")
            or "unknown"
        )
        if isinstance(parsed_session_id, str):
            ctx.proc_result["session_id"] = parsed_session_id.strip() or "unknown"
            if not ctx.session_id:
                ctx.session_id = parsed_session_id.strip() or "unknown"
        return True

    def _phase_experiment(self, ctx: _RequestContext) -> bool:
        """Assign A/B variant and override model if needed."""
        if not self._experiment_manager:
            return True
        session_id = ctx.session_id or "default"
        agent_id = (
            ctx.handler.headers.get("X-Orchesis-Agent")
            or ctx.handler.headers.get("x-orchesis-agent")
            or ctx.behavior_agent_id
            or "default"
        )
        model = str(ctx.body.get("model", ""))
        tools_raw = ctx.body.get("tools", [])
        tools = []
        if isinstance(tools_raw, list):
            for t in tools_raw:
                if isinstance(t, dict):
                    name = t.get("name", "")
                    if isinstance(name, str) and name:
                        tools.append(name)
                elif isinstance(t, str) and t:
                    tools.append(t)
        assignment = self._experiment_manager.assign_variant(
            session_id=session_id,
            agent_id=agent_id,
            model=model,
            tools=tools,
        )
        if assignment:
            ctx.experiment_id = assignment.experiment_id
            ctx.variant_name = assignment.variant_name
            if assignment.model_override:
                ctx.body["model"] = assignment.model_override
                if not ctx.original_model:
                    ctx.original_model = model
            ctx.session_headers["X-Orchesis-Experiment"] = assignment.experiment_id
            ctx.session_headers["X-Orchesis-Variant"] = assignment.variant_name
        return True

    def _apply_cascade_token_limit(self, body: dict[str, Any], cascade_max_tokens: int) -> None:
        if cascade_max_tokens <= 0:
            return
        respect_client_tokens = bool(self._cascade_cfg.get("respect_client_tokens", False))
        has_max_completion = "max_completion_tokens" in body
        has_max_tokens = "max_tokens" in body
        # Prevent OpenAI validation collisions.
        if has_max_completion and has_max_tokens:
            body.pop("max_tokens", None)
            has_max_tokens = False
        if respect_client_tokens and (has_max_completion or has_max_tokens):
            return
        if has_max_completion:
            body["max_completion_tokens"] = cascade_max_tokens
            return
        if has_max_tokens:
            body["max_tokens"] = cascade_max_tokens
            return
        body["max_tokens"] = cascade_max_tokens

    @staticmethod
    def _apply_threat_context_adjustments(messages: list[Any], matches: list[Any]) -> None:
        has_tool_results = any(
            isinstance(msg, dict) and str(msg.get("role", "")).strip().lower() == "tool"
            for msg in messages
        )
        if not has_tool_results or not matches:
            return
        downgrade_ids = {"ORCH-TA-002", "ORCH-TA-005"}
        for match in matches:
            threat_id = str(getattr(match, "threat_id", "") or "").upper()
            if threat_id not in downgrade_ids:
                continue
            try:
                current = float(getattr(match, "confidence", 0.0) or 0.0)
            except Exception:
                current = 0.0
            adjusted = max(0.0, min(1.0, current * 0.5))
            try:
                match.confidence = adjusted
            except Exception:
                pass
            try:
                action = str(getattr(match, "action", "")).lower()
                if action == "block" and adjusted < 0.7:
                    match.action = "warn"
            except Exception:
                continue

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
            # Run loop checks before serving cascade cache hits; otherwise repeated
            # cached prompts bypass loop warnings/blocks and never appear in dashboard events.
            if not self._phase_loop_detection(ctx):
                return False
            session_value = str(ctx.session_id or ctx.proc_result.get("session_id", "unknown"))
            ctx.handler.send_response(200)
            ctx.handler.send_header("Content-Type", "application/json")
            ctx.handler.send_header("Content-Length", str(len(cached_payload)))
            ctx.handler.send_header("X-Orchesis-Cost", "0.0")
            ctx.handler.send_header(
                "X-Orchesis-Cost-Velocity",
                str(round(float(self._cost_velocity.current_rate_per_hour()), 6)),
            )
            ctx.handler.send_header("X-Orchesis-Daily-Total", str(round(self._cost_tracker.get_daily_total(), 4)))
            daily_budget = self._budget_cfg.get("daily")
            if isinstance(daily_budget, int | float):
                ctx.handler.send_header("X-Orchesis-Daily-Budget", f"{float(daily_budget):.4f}")
            ctx.handler.send_header("X-Orchesis-Saved", "0.0000")
            ctx.handler.send_header("X-Orchesis-Session", session_value)
            ctx.handler.send_header("X-Orchesis-Cascade-Level", pre_level_name)
            ctx.handler.send_header("X-Orchesis-Cascade-Model", pre_model or "")
            ctx.handler.send_header("X-Orchesis-Cache", "hit")
            if ctx.loop_warning_header:
                ctx.handler.send_header("X-Orchesis-Loop-Warning", ctx.loop_warning_header)
            ctx.handler.send_header("X-Orchesis-Spend-Rate", f"{ctx.spend_rate_per_min:.4f}")
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
            self._apply_cascade_token_limit(ctx.body, int(ctx.cascade_decision.max_tokens))
        messages = ctx.body.get("messages")
        if isinstance(messages, list):
            ctx.body["messages"] = validate_tool_chain(messages)
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
            ctx.resp_status = int(self._circuit_breaker.fallback_status)
            ctx.handler.send_response(self._circuit_breaker.fallback_status)
            ctx.handler.send_header("Content-Type", "application/json")
            ctx.handler.send_header("Content-Length", str(len(payload_fb)))
            ctx.handler.send_header("X-Orchesis-Circuit", "open")
            if self._config.cors:
                ctx.handler.send_header("Access-Control-Allow-Origin", "*")
            ctx.handler.end_headers()
            ctx.handler.wfile.write(payload_fb)
            if self._alert_manager:
                self._alert_manager.alert(AlertEvent(severity=AlertSeverity.WARNING, event_type="circuit_open", title="Circuit breaker open", details=self._circuit_breaker.fallback_message, session_id=ctx.session_id))
            return False
        ctx.circuit_state_header = self._circuit_breaker.get_state().lower().replace("_", "-")
        return True

    def _phase_loop_detection(self, ctx: _RequestContext) -> bool:
        if self._loop_detector is None:
            loop_decision = None
        else:
            loop_decision = self._loop_detector.check_request(
                {
                    "model": ctx.body.get("model", ctx.parsed_req.model),
                    "messages": ctx.parsed_req.messages,
                    "tool_calls": ctx.parsed_req.tool_calls,
                    "content_text": ctx.parsed_req.content_text,
                }
            )
        if loop_decision is not None:
            if loop_decision.action == "block":
                self._loop_trigger_hits += 1
                reason_text = loop_decision.reason or "Loop threshold exceeded"
                self._add_dashboard_event(
                    "loop_detected",
                    "high",
                    f"Loop blocked: {reason_text}",
                    metadata={"action": "block", "session_id": ctx.session_id},
                )
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
                ctx.resp_status = 429
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
                ctx.was_loop_detected = True
                self._add_dashboard_event(
                    "loop_warning",
                    "medium",
                    f"Loop warning: {ctx.loop_warning_header}",
                    metadata={"action": loop_decision.action, "session_id": ctx.session_id},
                )
                if loop_decision.action == "downgrade_model":
                    ctx.body["model"] = self._downgrade_model
        if self._content_loop_detector is not None and isinstance(ctx.parsed_req.messages, list) and ctx.parsed_req.messages:
            last_msg = ctx.parsed_req.messages[-1]
            if isinstance(last_msg, dict) and str(last_msg.get("role", "")).lower() == "user":
                content = last_msg.get("content", "")
                if isinstance(content, str) and len(content) > 10:
                    session_id = (
                        ctx.handler.headers.get("x-openclaw-session")
                        or ctx.handler.headers.get("x-session-id")
                        or ctx.proc_result.get("session_id", "default")
                    )
                    result = self._content_loop_detector.check(content, str(session_id))
                    ctx.content_loop_count = int(result.get("count", 0))
                    if result.get("action") == "block":
                        self._loop_trigger_hits += 1
                        self._inc("blocked")
                        retry_after = int(result.get("retry_after", 300))
                        self._cost_tracker.record_loop_prevented_savings(self._estimated_avg_request_cost_usd)
                        self._send_json(
                            ctx.handler,
                            429,
                            {
                                "error": {
                                    "type": "content_loop_detected",
                                    "message": (
                                        f"Loop detected: {result.get('count', 0)} identical messages in "
                                        f"{result.get('window_seconds', 0)}s."
                                    ),
                                    "retry_after": retry_after,
                                }
                            },
                            extra_headers={
                                "Retry-After": str(max(1, retry_after)),
                                "X-Orchesis-Loop-Count": str(int(result.get("count", 0))),
                            },
                        )
                        if self._alert_manager:
                            self._alert_manager.alert(AlertEvent(severity=AlertSeverity.CRITICAL, event_type="loop_detected", title="Content loop blocked", details=f"{result.get('count', 0)} identical messages in {result.get('window_seconds', 0)}s", session_id=str(session_id)))
                        return False
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
                if self._alert_manager:
                    self._alert_manager.alert(AlertEvent(severity=AlertSeverity.CRITICAL, event_type="budget_exceeded", title="Budget exceeded", details=f"Daily budget exceeded. Spent ${budget_status.get('daily_spent', 0):.4f}", session_id=ctx.session_id))
                return False
        if self._spend_rate_detector is not None:
            # Spend-rate check: eventually consistent. We check rate BEFORE the upstream
            # call (cost unknown yet) and record actual spend AFTER response. Between
            # check and record, concurrent requests may alter the rate. This is by design:
            # we prefer allowing a borderline request over blocking pre-emptively with
            # unknown cost. The next request will see the updated rate.
            rate_result = self._spend_rate_detector.check()
            ctx.spend_rate_per_min = float(rate_result.current_rate)
            if not rate_result.allowed:
                retry_after = int(max(1.0, rate_result.cooldown_until - time.monotonic()))
                self._send_json(
                    ctx.handler,
                    429,
                    {
                        "error": {
                            "type": "spend_rate_exceeded",
                            "message": (
                                f"Spending too fast: ${rate_result.window_spend:.2f} in {rate_result.reason}. "
                                "Paused until rate normalizes."
                            ),
                            "retry_after": retry_after,
                        }
                    },
                    extra_headers={"Retry-After": str(retry_after)},
                )
                if self._alert_manager:
                    self._alert_manager.alert(AlertEvent(severity=AlertSeverity.WARNING, event_type="spend_rate_exceeded", title="Spend rate exceeded", details=f"Spending too fast: ${rate_result.window_spend:.2f} in {rate_result.reason}", session_id=ctx.session_id))
                return False
        return True

    def _phase_adaptive_detection(self, ctx: _RequestContext) -> bool:
        if self._adaptive_detector is None:
            return True
        agent_id = str(ctx.behavior_agent_id or extract_agent_id(ctx.handler.headers) or "default")
        request_data = {
            "messages": ctx.body.get("messages", []),
            "model": str(ctx.body.get("model", "")),
            "tools": ctx.body.get("tools", []),
            "timestamp": time.time(),
            "tokens": int(ctx.body.get("max_completion_tokens", ctx.body.get("max_tokens", 0)) or 0),
        }
        detection = self._adaptive_detector.check(agent_id, request_data)
        ctx.adaptive_detection_result = detection
        ctx.proc_result["adaptive_anomaly_score"] = float(detection.anomaly_score)
        ctx.proc_result["adaptive_risk_level"] = detection.risk_level
        ctx.proc_result["adaptive_action"] = detection.recommended_action
        ctx.proc_result["adaptive_detection_anomalous"] = bool(detection.is_anomalous)
        ctx.proc_result["adaptive_drift_type"] = str(detection.drift_type)
        ctx.session_headers["X-Orchesis-Anomaly-Score"] = str(int(detection.anomaly_score))
        ctx.session_headers["X-Orchesis-Risk-Level"] = detection.risk_level
        if self._agent_discovery is not None and self._agent_discovery.enabled:
            ars_grade = None
            ars_score = None
            if self._ars is not None:
                ars_result_now = self._ars.compute(agent_id)
                if ars_result_now is not None:
                    ars_grade = ars_result_now.grade
                    ars_score = ars_result_now.score
            self._agent_discovery.record_detection(
                agent_id=agent_id,
                anomaly_score=float(detection.anomaly_score),
                mast_findings=0,
                risk_level=detection.risk_level,
                ars_grade=ars_grade,
                ars_score=ars_score,
                is_cron=bool(ctx.heartbeat_detected),
                status="blocked" if detection.recommended_action == "block" else None,
            )
        if detection.is_anomalous and self._session_risk is not None:
            self._session_risk.record_signal(
                str(ctx.session_id or "unknown"),
                RiskSignal(
                    category="adaptive_anomaly",
                    confidence=max(0.0, min(1.0, detection.anomaly_score / 100.0)),
                    severity="high" if detection.anomaly_score >= 70 else "medium",
                    source="adaptive_detection",
                    description=f"{detection.risk_level}:{detection.drift_type}",
                ),
            )
        if detection.recommended_action == "block":
            self._inc("blocked")
            self._send_json(
                ctx.handler,
                429,
                {
                    "error": {
                        "type": "adaptive_detection_block",
                        "message": (
                            f"Anomaly score {detection.anomaly_score:.0f} exceeds "
                            "critical threshold"
                        ),
                    }
                },
                extra_headers={
                    "X-Orchesis-Anomaly-Score": str(int(detection.anomaly_score)),
                    "X-Orchesis-Risk-Level": detection.risk_level,
                },
            )
            return False
        if detection.recommended_action == "warn":
            _HTTP_PROXY_LOGGER.warning(
                "adaptive detection warning agent=%s score=%.2f level=%s",
                agent_id,
                detection.anomaly_score,
                detection.risk_level,
            )
        if self._community is not None and detection.anomaly_score >= self._community.min_anomaly_score:
            ars_snapshot: dict[str, Any] | None = None
            if self._ars is not None:
                ars_result = self._ars.compute(agent_id)
                if ars_result is not None:
                    ars_snapshot = {"grade": ars_result.grade, "score": ars_result.score}
            telemetry_snapshot = {
                "input_tokens": int(ctx.proc_result.get("input_tokens", 0) or 0),
                "output_tokens": int(ctx.proc_result.get("output_tokens", 0) or 0),
                "model_used": str(ctx.body.get("model", "")),
                "total_ms": (time.perf_counter() - float(ctx.request_started or 0.0)) * 1000.0,
                "cache_hit": bool(ctx.from_semantic_cache),
            }
            self._community.record_detection(
                detection_result=detection,
                telemetry_record=telemetry_snapshot,
                ars_data=ars_snapshot,
                request_meta={"model": str(ctx.body.get("model", "")), "agent_type": str(agent_id or "unknown")},
            )
        return True

    def _phase_mast_request(self, ctx: _RequestContext) -> bool:
        if self._mast is None:
            return True
        agent_id = str(ctx.behavior_agent_id or "default")
        findings = self._mast.check_request(
            agent_id,
            {
                **ctx.body,
                "session_id": ctx.session_id,
                "request_id": ctx.request_id,
            },
            context={
                "policy": self._policy,
                "approved_tools": (
                    self._policy.get("capabilities", {}).get("tools", {}).get("allowed", [])
                    if isinstance(self._policy.get("capabilities", {}), dict)
                    else []
                ),
                "approved_models": (
                    self._policy.get("models", {}).get("allowed", [])
                    if isinstance(self._policy.get("models", {}), dict)
                    else []
                ),
                "token_budget": {"max_tokens": int(ctx.body.get("max_completion_tokens", ctx.body.get("max_tokens", 0)) or 0)},
                "session_id": ctx.session_id,
                "tool_metadata_present": True,
            },
        )
        if findings:
            ctx.proc_result["mast_findings"] = [asdict(item) for item in findings]
            ctx.mast_request_findings = list(findings)
            if self._agent_discovery is not None and self._agent_discovery.enabled:
                severity_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
                worst = "low"
                for item in findings:
                    if severity_rank.get(item.severity, 0) > severity_rank.get(worst, 0):
                        worst = item.severity
                self._agent_discovery.record_detection(
                    agent_id=agent_id,
                    anomaly_score=100.0 if worst in {"high", "critical"} else 1.0,
                    mast_findings=len(findings),
                    risk_level=worst,
                    is_cron=bool(ctx.heartbeat_detected),
                    status="blocked" if worst == "critical" else None,
                )
        for finding in findings:
            if finding.severity == "critical":
                if self._auto_healer is not None and self._auto_healer.enabled:
                    continue
                self._inc("blocked")
                self._send_json(
                    ctx.handler,
                    403,
                    {
                        "error": {
                            "type": f"mast_{finding.failure_mode.lower()}",
                            "message": finding.description,
                        }
                    },
                )
                return False
            if finding.severity == "high":
                ctx.session_headers[f"X-Orchesis-MAST-{finding.failure_mode}"] = finding.description[:180]
        return True

    def _phase_auto_healing(self, ctx: _RequestContext) -> bool:
        if self._auto_healer is None or not self._auto_healer.enabled:
            return True
        agent_id = str(ctx.behavior_agent_id or extract_agent_id(ctx.handler.headers) or "default")
        if not self._auto_healer.rate_limiter.check(agent_id):
            if self._agent_discovery is not None and self._agent_discovery.enabled:
                self._agent_discovery.record_detection(
                    agent_id=agent_id,
                    anomaly_score=50.0,
                    risk_level="high",
                    status="rate_limited",
                )
            self._inc("blocked")
            self._send_json(
                ctx.handler,
                429,
                {
                    "error": {
                        "type": "agent_rate_limited",
                        "message": "Agent temporarily rate-limited due to anomalous behavior",
                    }
                },
            )
            return False
        detection = ctx.adaptive_detection_result
        mast_findings = ctx.mast_request_findings
        has_detection_issue = bool(detection is not None and bool(getattr(detection, "is_anomalous", False)))
        has_mast_issue = bool(mast_findings)
        if not has_detection_issue and not has_mast_issue:
            return True
        pre_score = float(getattr(detection, "anomaly_score", 0.0) if detection is not None else 0.0)
        modified_request, healing_result = self._auto_healer.heal(
            detection_result=detection,
            mast_findings=mast_findings,
            request_data=ctx.body,
            agent_id=agent_id,
            context={"policy": self._policy},
        )
        if healing_result.actions_taken:
            ctx.body = modified_request
            ctx.was_auto_healed = True
            ctx.healing_pre_score = pre_score
            ctx.proc_result["auto_healing"] = asdict(healing_result)
            ctx.session_headers["X-Orchesis-Healed"] = "true"
            ctx.session_headers["X-Orchesis-Healing-Actions"] = ",".join(
                [item.action_type for item in healing_result.actions_taken]
            )
        return True

    def _phase_threat_intel(self, ctx: _RequestContext) -> bool:
        """Scan request against threat intelligence database."""
        matches: list[Any] = []
        if self._threat_matcher is not None and self._threat_matcher.enabled:
            messages = ctx.body.get("messages", [])
            if not isinstance(messages, list):
                messages = []
            tools = [
                str(t.get("name", ""))
                for t in ctx.body.get("tools", [])
                if isinstance(t, dict) and t.get("name")
            ]
            parsed = ctx.parsed_req
            tool_calls: list[dict[str, Any]] = []
            if parsed and hasattr(parsed, "tool_calls"):
                for tc in parsed.tool_calls:
                    name = getattr(tc, "name", None) or (tc.get("name") if isinstance(tc, dict) else "")
                    inp = getattr(tc, "params", None) or getattr(tc, "input", None)
                    if inp is None and isinstance(tc, dict):
                        inp = tc.get("input", tc.get("params", {}))
                    tool_calls.append({"name": str(name) if name else "", "input": inp or {}})
            model = str(ctx.body.get("model", ""))
            headers_dict: dict[str, str] = {}
            if hasattr(ctx.handler, "headers"):
                h = ctx.handler.headers
                if hasattr(h, "items"):
                    headers_dict = dict(h)
                elif hasattr(h, "keys"):
                    headers_dict = {k: h.get(k, "") for k in h.keys()}
            matches = self._threat_matcher.scan_request(
                messages=messages,
                tools=tools,
                tool_calls=tool_calls,
                model=model,
                headers=headers_dict or None,
            )
            self._apply_threat_context_adjustments(messages, matches)
            if self._community is not None:
                try:
                    community_sigs = self._community.get_community_signatures()
                    ctx.proc_result["community_signatures_checked"] = len(community_sigs)
                except Exception:
                    ctx.proc_result["community_signatures_checked"] = 0
            if matches:
                ctx.threat_matches = matches
                if self._session_risk:
                    session_id = str(ctx.session_id or ctx.proc_result.get("session_id", "unknown"))
                    for match in matches:
                        self._session_risk.record_signal(
                            session_id,
                            RiskSignal(
                                category=str(getattr(match, "category", "unknown")),
                                confidence=float(getattr(match, "confidence", 0.0)),
                                severity=str(getattr(match, "severity", "low")),
                                source="threat_intel",
                                description=f"{getattr(match, 'name', 'threat')}: {str(getattr(match, 'description', ''))[:100]}",
                            ),
                        )
        for match in matches:
            if match.action == "block":
                self._inc("blocked")
                self._send_json(
                    ctx.handler,
                    403,
                    {
                        "error": "threat_detected",
                        "threat_id": match.threat_id,
                        "name": match.name,
                        "severity": match.severity,
                        "description": match.description,
                        "mitigation": match.mitigation,
                    },
                )
                if self._alert_manager:
                    self._alert_manager.alert(AlertEvent(severity=AlertSeverity.CRITICAL, event_type="threat_blocked", title="Threat blocked", details=f"{match.name} ({match.threat_id})", session_id=ctx.session_id))
                return False
        if matches:
            threat_ids = ",".join(m.threat_id for m in matches)
            ctx.session_headers["X-Orchesis-Threat-Detected"] = threat_ids
            ctx.session_headers["X-Orchesis-Threat-Severity"] = matches[0].severity

        if self._session_risk:
            session_id = str(ctx.session_id or ctx.proc_result.get("session_id", "unknown"))
            assessment = self._session_risk.evaluate(session_id)
            ctx.proc_result["session_risk_score"] = assessment.composite_score
            ctx.proc_result["session_risk_level"] = assessment.escalation_level
            if assessment.composite_score > 0:
                ctx.session_headers["X-Orchesis-Session-Risk"] = f"{assessment.composite_score:.1f}"
                ctx.session_headers["X-Orchesis-Session-Risk-Level"] = assessment.escalation_level
            if assessment.action == "block":
                self._inc("blocked")
                self._send_json(
                    ctx.handler,
                    429,
                    {
                        "error": {
                            "type": "session_risk_exceeded",
                            "message": assessment.reason,
                            "score": assessment.composite_score,
                            "categories": assessment.unique_categories,
                            "signals": assessment.total_signals,
                        }
                    },
                )
                if self._alert_manager:
                    self._alert_manager.alert(
                        AlertEvent(
                            severity=AlertSeverity.CRITICAL,
                            event_type="session_risk_block",
                            title="Session risk threshold exceeded",
                            details=assessment.reason,
                            session_id=session_id,
                        )
                    )
                return False
        return True

    def _phase_policy(self, ctx: _RequestContext) -> bool:
        approval_id = str(
            ctx.handler.headers.get("X-Orchesis-Approval-Id")
            or ctx.body.get("approval_id")
            or ""
        )
        for call in ctx.parsed_req.tool_calls:
            if self._tool_policy is not None:
                tp_decision = self._tool_policy.evaluate(
                    tool_name=call.name,
                    agent_id=str(ctx.behavior_agent_id or "default"),
                    tool_args=call.params if isinstance(call.params, dict) else {},
                    session_id=str(ctx.session_id or "default"),
                    request_id=str(ctx.request_id or ""),
                    approval_id=approval_id,
                )
                if tp_decision.action == "block":
                    self._inc("blocked")
                    self._send_json(
                        ctx.handler,
                        403,
                        {
                            "error": {
                                "type": "tool_policy_block",
                                "message": f"Tool '{call.name}' blocked: {tp_decision.reason}",
                            }
                        },
                    )
                    return False
                if tp_decision.action == "approve":
                    self._send_json(
                        ctx.handler,
                        202,
                        {
                            "status": "pending_approval",
                            "approval_id": tp_decision.approval_id,
                            "tool_name": call.name,
                            "reason": tp_decision.reason,
                        },
                    )
                    return False
                if tp_decision.action == "warn":
                    ctx.session_headers["X-Orchesis-Tool-Warn"] = f"{call.name}:{tp_decision.reason[:120]}"
                self._tool_policy.record_usage(
                    tool_name=call.name,
                    agent_id=str(ctx.behavior_agent_id or "default"),
                    session_id=str(ctx.session_id or "default"),
                )
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
        if self._spend_rate_detector is not None and self._spend_rate_detector.is_heartbeat_request(ctx.body):
            ctx.heartbeat_detected = True
            ctx.proc_result["cascade_tier"] = "cheapest"
            heartbeat_models = self._routing_cfg.get("heartbeat_models", {})
            provider = ctx.parsed_req.provider or "openai"
            cheapest = (
                heartbeat_models.get(provider)
                or heartbeat_models.get("default")
                or "gpt-4o-mini"
            )
            if isinstance(cheapest, str) and cheapest and cheapest != ctx.body.get("model"):
                ctx.body["model"] = cheapest
            ctx.session_headers["X-Orchesis-Heartbeat"] = "true"
        if self._router is not None and ctx.parsed_req.content_text:
            route = self._router.route(
                ctx.parsed_req.content_text,
                tool_name=ctx.parsed_req.tool_calls[0].name if ctx.parsed_req.tool_calls else None,
            )
            routed_model = route.get("model")
            if isinstance(routed_model, str) and routed_model and routed_model != ctx.parsed_req.model:
                ctx.body["model"] = routed_model
        if self._thompson is not None:
            failed_models_raw = ctx.proc_result.get("failed_models", [])
            failed_models = failed_models_raw if isinstance(failed_models_raw, list) else []
            category = self._thompson.classify_request(
                request_data=ctx.body,
                agent_id=str(ctx.behavior_agent_id or "default"),
            )
            decision = self._thompson.select_model(
                request_data=ctx.body,
                agent_id=str(ctx.behavior_agent_id or "default"),
                excluded_models=failed_models,
            )
            if isinstance(decision.selected_model, str) and decision.selected_model:
                ctx.body["model"] = decision.selected_model
                ctx.thompson_selected_model = decision.selected_model
            ctx.thompson_category = category
            ctx.session_headers["X-Orchesis-Router-Model"] = decision.selected_model
            ctx.session_headers["X-Orchesis-Router-Reason"] = decision.reason
            ctx.proc_result["thompson_router"] = {
                "category": category,
                "selected_model": decision.selected_model,
                "reason": decision.reason,
                "confidence": float(decision.confidence),
                "sampled_scores": dict(decision.sampled_scores),
            }
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

    def _phase_context(self, ctx: _RequestContext) -> bool:
        """Optimize context window before sending to LLM."""
        if self._context_optimizer is not None:
            messages = ctx.body.get("messages")
            if isinstance(messages, list):
                optimized_messages, opt_result = self._context_optimizer.optimize(
                    messages=messages,
                    model=str(ctx.body.get("model", "")),
                    tools=ctx.body.get("tools"),
                    agent_id=str(ctx.behavior_agent_id or "default"),
                )
                ctx.body["messages"] = optimized_messages
                ctx.proc_result["context_savings_percent"] = float(opt_result.savings_percent)
                ctx.proc_result["context_original_tokens"] = int(opt_result.original_tokens)
                ctx.proc_result["context_optimized_tokens"] = int(opt_result.optimized_tokens)
                ctx.proc_result["context_optimizations_applied"] = list(opt_result.optimizations_applied)
        if self._context_engine is None or not self._context_engine.enabled:
            return True
        messages = ctx.body.get("messages")
        if not isinstance(messages, list) or not messages:
            return True
        max_tokens = int(
            ctx.body.get("max_completion_tokens", ctx.body.get("max_tokens", 0)) or 0
        )
        model = str(ctx.body.get("model", ""))
        result = self._context_engine.optimize(
            messages=messages,
            model=model,
            max_tokens=max_tokens,
        )
        ctx.body["messages"] = validate_tool_chain(result.messages)
        if result.tokens_saved > 0:
            ctx.session_headers["X-Orchesis-Context-Tokens-Saved"] = str(result.tokens_saved)
            ctx.session_headers["X-Orchesis-Context-Strategies"] = ",".join(result.strategies_applied)
        ctx.context_tokens_saved = result.tokens_saved
        ctx.context_strategies = result.strategies_applied
        return True

    def _is_streaming_request(self, ctx: _RequestContext) -> bool:
        return bool(self._streaming_enabled and isinstance(ctx.body, dict) and ctx.body.get("stream") is True)

    @staticmethod
    def _extract_text_delta(event_str: str) -> str:
        for line in event_str.split("\n"):
            if not line.startswith("data: "):
                continue
            data_str = line[6:].strip()
            if data_str == "[DONE]":
                return ""
            try:
                data = json.loads(data_str)
            except Exception:
                continue
            if isinstance(data, dict):
                if data.get("type") == "content_block_delta":
                    delta = data.get("delta", {})
                    if isinstance(delta, dict) and delta.get("type") == "text_delta":
                        text = delta.get("text", "")
                        return str(text) if isinstance(text, str) else ""
                choices = data.get("choices", [])
                if isinstance(choices, list) and choices:
                    first = choices[0]
                    if isinstance(first, dict):
                        delta = first.get("delta", {})
                        if isinstance(delta, dict):
                            content = delta.get("content", "")
                            return str(content) if isinstance(content, str) else ""
        return ""

    @staticmethod
    def _send_chunk(handler: BaseHTTPRequestHandler, data: bytes) -> None:
        chunk = data if isinstance(data, bytes) else b""
        header = f"{len(chunk):x}\r\n".encode("utf-8")
        handler.wfile.write(header)
        handler.wfile.write(chunk)
        handler.wfile.write(b"\r\n")
        handler.wfile.flush()

    @staticmethod
    def _build_synthetic_response(events: list[str], text_parts: list[str], ctx: _RequestContext) -> str:
        full_text = "".join(text_parts)
        synthetic: dict[str, Any] = {
            "id": str(ctx.body.get("id", "synthetic_stream")),
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": full_text}],
            "model": str(ctx.body.get("model", ctx.original_model)),
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 0, "output_tokens": 0},
            "_orchesis_streaming": True,
            "_orchesis_chunks": len(events),
        }
        for event_str in reversed(events):
            if "message_delta" not in event_str and "\"usage\"" not in event_str:
                continue
            for line in event_str.split("\n"):
                if not line.startswith("data: "):
                    continue
                try:
                    data = json.loads(line[6:])
                except Exception:
                    continue
                if isinstance(data, dict):
                    usage = data.get("usage", {})
                    if isinstance(usage, dict) and usage:
                        synthetic["usage"] = usage
                        return json.dumps(synthetic, ensure_ascii=False)
        return json.dumps(synthetic, ensure_ascii=False)

    @staticmethod
    def _compose_target_path(parsed_url: Any) -> str:
        base_path = parsed_url.path if isinstance(parsed_url.path, str) and parsed_url.path else "/"
        if isinstance(parsed_url.query, str) and parsed_url.query:
            return f"{base_path}?{parsed_url.query}"
        return base_path

    def _request_upstream_once(
        self,
        *,
        upstream_url: str,
        payload: bytes,
        headers: dict[str, str],
        stream_response: bool,
        ctx: _RequestContext,
    ) -> tuple[int, dict[str, str], bytes]:
        parsed = urlsplit(upstream_url)
        host = parsed.hostname or ""
        if not host:
            raise URLError("invalid upstream host")
        use_ssl = parsed.scheme.lower() == "https"
        port = parsed.port or (443 if use_ssl else 80)
        target_path = self._compose_target_path(parsed)
        pooled_conn = self._connection_pool.acquire(host=host, port=port, use_ssl=use_ssl)
        error = False
        try:
            pooled_conn.conn.request("POST", target_path, body=payload, headers=headers)
            response = pooled_conn.conn.getresponse()
            status = int(getattr(response, "status", 200))
            resp_headers = {str(k): str(v) for k, v in response.getheaders()}
            if stream_response and status == 200:
                self._handle_streaming_response(ctx, response, pooled_conn, resp_headers)
                return status, resp_headers, ctx.resp_body
            body = response.read()
            return status, resp_headers, body
        except Exception:
            error = True
            raise
        finally:
            if not stream_response:
                self._connection_pool.release(pooled_conn, error=error)

    def _handle_streaming_response(
        self,
        ctx: _RequestContext,
        upstream_response: http.client.HTTPResponse,
        pooled_conn: PooledConnection,
        response_headers: dict[str, str],
    ) -> None:
        ctx.handler.send_response(int(getattr(upstream_response, "status", 200)))
        skip = {"transfer-encoding", "connection", "content-length"}
        for key, value in response_headers.items():
            if key.lower() in skip:
                continue
            ctx.handler.send_header(key, value)
        ctx.handler.send_header("Transfer-Encoding", "chunked")
        ctx.handler.send_header("X-Orchesis-Cost", str(round(float(ctx.proc_result.get("cost", 0.0)), 6)))
        ctx.handler.send_header(
            "X-Orchesis-Cost-Velocity",
            str(round(float(self._cost_velocity.current_rate_per_hour()), 6)),
        )
        ctx.handler.send_header("X-Orchesis-Daily-Total", str(round(self._cost_tracker.get_daily_total(), 4)))
        daily_budget = self._budget_cfg.get("daily")
        if isinstance(daily_budget, int | float):
            ctx.handler.send_header("X-Orchesis-Daily-Budget", f"{float(daily_budget):.4f}")
        ctx.handler.send_header("X-Orchesis-Saved", f"{float(ctx.request_saved_usd):.4f}")
        ctx.handler.send_header("X-Orchesis-Session", str(ctx.session_id or ctx.proc_result.get("session_id", "unknown")))
        if ctx.heartbeat_detected:
            ctx.handler.send_header("X-Orchesis-Heartbeat", "true")
        if ctx.content_loop_count > 1:
            ctx.handler.send_header("X-Orchesis-Loop-Count", str(ctx.content_loop_count))
        ctx.handler.send_header("X-Orchesis-Spend-Rate", f"{ctx.spend_rate_per_min:.4f}")
        ctx.handler.send_header("X-Orchesis-Circuit", self._circuit_breaker.get_state().lower().replace("_", "-"))
        if self._recorder is not None:
            ctx.handler.send_header("X-Orchesis-Session-Id", ctx.session_id)
            ctx.handler.send_header("X-Orchesis-Request-Id", ctx.request_id)
        if self._config.cors:
            ctx.handler.send_header("Access-Control-Allow-Origin", "*")
        ctx.handler.end_headers()
        events: list[str] = []
        texts: list[str] = []
        chunks = 0
        buffer = b""
        had_error = False
        try:
            while True:
                chunk = upstream_response.read(self._streaming_buffer_size)
                if not chunk:
                    break
                self._send_chunk(ctx.handler, chunk)
                chunks += 1
                buffer += chunk
                while b"\n\n" in buffer and len(events) < self._streaming_max_accumulated_events:
                    event_data, buffer = buffer.split(b"\n\n", 1)
                    event_str = event_data.decode("utf-8", errors="replace")
                    events.append(event_str)
                    delta = self._extract_text_delta(event_str)
                    if delta:
                        texts.append(delta)
            self._send_chunk(ctx.handler, b"")
        except (ConnectionAbortedError, BrokenPipeError, OSError):
            had_error = True
        finally:
            self._connection_pool.release(pooled_conn, error=had_error)
        ctx.is_streaming = True
        ctx.streaming_events = events
        ctx.streaming_text = "".join(texts)
        ctx.streaming_chunks = chunks
        self._streaming_count += 1
        self._streaming_chunks_total += chunks
        synthetic = self._build_synthetic_response(events, texts, ctx)
        ctx.resp_body = synthetic.encode("utf-8")

    def _phase_upstream(self, ctx: _RequestContext) -> bool:
        ctx.provider = self._detect_provider(ctx.parsed_req.provider, ctx.handler.headers)
        if (
            self._semantic_cache is not None
            and self._semantic_cache.enabled
            and not self._is_streaming_request(ctx)
        ):
            messages = ctx.body.get("messages", [])
            if isinstance(messages, list) and messages:
                ctx.body["messages"] = validate_tool_chain(messages)
                messages = ctx.body["messages"]
                model = str(ctx.body.get("model", ""))
                tools = [
                    str(t.get("name", ""))
                    for t in ctx.body.get("tools", [])
                    if isinstance(t, dict) and t.get("name")
                ]
                cache_result = self._semantic_cache.lookup(messages, model, tools or None)
                if cache_result.hit:
                    ctx.resp_body = cache_result.response_body
                    ctx.resp_status = 200
                    ctx.resp_headers = {}
                    ctx.from_semantic_cache = True
                    # Keep request history protocol-safe for downstream/session handling.
                    ctx.body["messages"] = validate_tool_chain(messages)
                    ctx.session_headers["X-Orchesis-Cache"] = cache_result.match_type
                    ctx.session_headers["X-Orchesis-Cache-Similarity"] = f"{cache_result.similarity:.2f}"
                    return True
        messages = ctx.body.get("messages", [])
        if isinstance(messages, list):
            ctx.body["messages"] = validate_tool_chain(messages)
        upstream_base = self._get_upstream(ctx.provider, ctx.handler.headers)
        upstream_url = f"{upstream_base.rstrip('/')}{ctx.handler.path}"
        payload = json.dumps(ctx.body, ensure_ascii=False).encode("utf-8")
        upstream_headers = self._build_forward_headers(ctx.handler.headers, payload)
        ctx.resp_status = 200
        ctx.resp_headers = {}
        ctx.resp_body = b""
        stream_response = self._is_streaming_request(ctx)
        retries = self._connection_pool._config.max_retries if self._connection_pool._config.retry_on_connection_error else 0  # noqa: SLF001
        for attempt in range(max(0, retries) + 1):
            try:
                status, resp_headers, resp_body = self._request_upstream_once(
                    upstream_url=upstream_url,
                    payload=payload,
                    headers=upstream_headers,
                    stream_response=stream_response,
                    ctx=ctx,
                )
                ctx.resp_status = status
                ctx.resp_headers = resp_headers
                ctx.resp_body = resp_body
                return True
            except Exception as error:
                if attempt >= retries:
                    self._circuit_breaker.record_failure()
                    self._inc("errors")
                    self._send_json(
                        ctx.handler,
                        502,
                        {"error": {"type": "upstream_error", "message": f"Failed to connect to upstream: {error}"}},
                    )
                    return False
        return False

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
            ctx.was_escalated = True
            escalated_decision = self._cascade_router.escalate(ctx.cascade_decision)
            if escalated_decision.model:
                ctx.body["model"] = escalated_decision.model
            if escalated_decision.max_tokens > 0:
                self._apply_cascade_token_limit(ctx.body, int(escalated_decision.max_tokens))
            retry_messages = ctx.body.get("messages")
            if isinstance(retry_messages, list):
                ctx.body["messages"] = validate_tool_chain(retry_messages)
            upstream_base = self._get_upstream(ctx.provider, ctx.handler.headers)
            upstream_url = f"{upstream_base.rstrip('/')}{ctx.handler.path}"
            payload_retry = json.dumps(ctx.body, ensure_ascii=False).encode("utf-8")
            retry_headers = self._build_forward_headers(ctx.handler.headers, payload_retry)
            try:
                status, resp_headers, resp_body = self._request_upstream_once(
                    upstream_url=upstream_url,
                    payload=payload_retry,
                    headers=retry_headers,
                    stream_response=False,
                    ctx=ctx,
                )
                ctx.resp_status = status
                ctx.resp_headers = resp_headers
                ctx.resp_body = resp_body
            except Exception as error:
                ctx.resp_status = 502
                ctx.resp_headers = {}
                ctx.resp_body = json.dumps(
                    {"error": {"type": "upstream_error", "message": f"Failed to connect to upstream: {error}"}},
                    ensure_ascii=False,
                ).encode("utf-8")
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
        if self._mast is not None:
            mast_response_payload: dict[str, Any] = {}
            try:
                decoded_resp = json.loads(ctx.resp_body.decode("utf-8")) if ctx.resp_body else {}
                if isinstance(decoded_resp, dict):
                    mast_response_payload = decoded_resp
            except Exception:
                mast_response_payload = {}
            mast_resp_findings = self._mast.check_response(
                str(ctx.behavior_agent_id or "default"),
                mast_response_payload,
                ctx.body,
            )
            if mast_resp_findings:
                existing = ctx.proc_result.get("mast_findings")
                if not isinstance(existing, list):
                    existing = []
                existing.extend(asdict(item) for item in mast_resp_findings)
                ctx.proc_result["mast_findings"] = existing
                for item in mast_resp_findings:
                    if item.severity == "critical":
                        self._inc("blocked")
                        self._send_json(
                            ctx.handler,
                            403,
                            {
                                "error": {
                                    "type": f"mast_{item.failure_mode.lower()}",
                                    "message": item.description,
                                }
                            },
                        )
                        return False
        if (
            self._auto_healer is not None
            and self._adaptive_detector is not None
            and ctx.was_auto_healed
        ):
            post_payload: dict[str, Any] = {
                "messages": [],
                "model": str(ctx.body.get("model", "")),
                "tools": [],
            }
            try:
                decoded_post = json.loads(ctx.resp_body.decode("utf-8")) if ctx.resp_body else {}
                if isinstance(decoded_post, dict):
                    post_text = ""
                    if isinstance(decoded_post.get("content"), str):
                        post_text = str(decoded_post.get("content", ""))
                    elif isinstance(decoded_post.get("output_text"), str):
                        post_text = str(decoded_post.get("output_text", ""))
                    else:
                        choices = decoded_post.get("choices")
                        if isinstance(choices, list) and choices and isinstance(choices[0], dict):
                            message = choices[0].get("message")
                            if isinstance(message, dict) and isinstance(message.get("content"), str):
                                post_text = str(message.get("content", ""))
                    if post_text:
                        post_payload["messages"] = [{"role": "assistant", "content": post_text}]
                post_det = self._adaptive_detector.check(
                    str(ctx.behavior_agent_id or "default"),
                    post_payload,
                )
                healed_ok = self._auto_healer.verify_healing(
                    str(ctx.behavior_agent_id or "default"),
                    pre_healing_score=float(ctx.healing_pre_score),
                    post_healing_score=float(post_det.anomaly_score),
                )
                ctx.proc_result["auto_healing_verified"] = bool(healed_ok)
                ctx.proc_result["auto_healing_post_score"] = float(post_det.anomaly_score)
            except Exception:
                pass
        if self._cascade_router is not None and ctx.cascade_decision is not None and ctx.parsed_resp_obj is not None:
            token_sum = int(getattr(ctx.parsed_resp_obj, "input_tokens", 0)) + int(
                getattr(ctx.parsed_resp_obj, "output_tokens", 0)
            )
            cascade_saved = self._cost_tracker.record_cascade_savings(
                original_model=ctx.original_model or ctx.cascade_decision.model,
                actual_model=ctx.cascade_decision.model,
                tokens=token_sum,
            )
            ctx.request_saved_usd += float(cascade_saved)
            if 200 <= ctx.resp_status < 300:
                self._cascade_router.record_result(ctx.cascade_decision, ctx.parsed_resp_obj)
                self._cascade_router.cache_response(ctx.cascade_decision, ctx.resp_body)
        if self._thompson is not None:
            used_model = str(ctx.body.get("model", "") or ctx.thompson_selected_model or "")
            category = ctx.thompson_category or self._thompson.classify_request(
                request_data=ctx.body,
                agent_id=str(ctx.behavior_agent_id or "default"),
            )
            parsed = ctx.parsed_resp_obj
            input_tokens = int(getattr(parsed, "input_tokens", 0)) if parsed is not None else 0
            output_tokens = int(getattr(parsed, "output_tokens", 0)) if parsed is not None else 0
            latency_ms = (time.perf_counter() - float(ctx.request_started or 0.0)) * 1000.0
            success = bool(ctx.resp_status < 400 and ctx.proc_result.get("allowed", True))
            error_type = ""
            if not success:
                if ctx.resp_status == 429:
                    error_type = "rate_limit"
                elif ctx.resp_status >= 500:
                    error_type = "upstream_error"
                else:
                    stop_reason = str(getattr(parsed, "stop_reason", "") or "").lower() if parsed is not None else ""
                    if stop_reason in {"length", "max_tokens"}:
                        error_type = "context_length"
            mast_findings = ctx.proc_result.get("mast_findings", [])
            has_injection = False
            if isinstance(mast_findings, list):
                for item in mast_findings:
                    if isinstance(item, dict) and str(item.get("failure_mode", "")).upper() == "FM-3.1":
                        has_injection = True
                        break
            outcome = {
                "model": used_model,
                "success": success,
                "latency_ms": float(latency_ms),
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "cost_usd": float(ctx.proc_result.get("cost", 0.0) or 0.0),
                "loop_detected": bool(ctx.was_loop_detected),
                "injection_detected": has_injection,
                "error_type": error_type,
            }
            outcome["quality_score"] = self._thompson.compute_quality_score(
                outcome=outcome,
                detection_result=ctx.adaptive_detection_result,
            )
            if used_model:
                self._thompson.record_outcome(
                    model=used_model,
                    category=category,
                    outcome=outcome,
                )
        if self._agent_discovery is not None and self._agent_discovery.enabled:
            tools_used: list[str] = []
            for tool_call in getattr(ctx.parsed_req, "tool_calls", []):
                name = getattr(tool_call, "name", "")
                if isinstance(name, str) and name:
                    tools_used.append(name)
            parsed = ctx.parsed_resp_obj
            total_tokens = 0
            if parsed is not None:
                total_tokens = int(getattr(parsed, "input_tokens", 0)) + int(getattr(parsed, "output_tokens", 0))
            self._agent_discovery.record_request(
                agent_id=str(ctx.behavior_agent_id or "default"),
                request_data={"session_id": ctx.session_id, "model": str(ctx.body.get("model", ""))},
                model=str(ctx.body.get("model", "")),
                tokens=total_tokens,
                cost=float(ctx.proc_result.get("cost", 0.0) or 0.0),
                latency_ms=(time.perf_counter() - float(ctx.request_started or 0.0)) * 1000.0,
                tools=tools_used,
            )
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
        if self._experiment_manager:
            if ctx.experiment_id and ctx.variant_name:
                tokens_in = int(getattr(ctx.parsed_resp_obj, "input_tokens", 0)) if ctx.parsed_resp_obj else 0
                tokens_out = int(getattr(ctx.parsed_resp_obj, "output_tokens", 0)) if ctx.parsed_resp_obj else 0
                tool_count = len(getattr(ctx.parsed_resp_obj, "tool_calls", [])) if ctx.parsed_resp_obj else 0
                self._experiment_manager.record_request(
                    experiment_id=ctx.experiment_id,
                    variant_name=ctx.variant_name,
                    cost_usd=float(ctx.proc_result.get("cost", 0.0)),
                    latency_ms=(time.perf_counter() - ctx.request_started) * 1000.0,
                    tokens=tokens_in + tokens_out,
                    tool_calls=tool_count,
                    is_error=ctx.resp_status >= 400,
                    turns=1,
                )
            session_id = ctx.session_id or "default"
            stop_reason = ""
            if ctx.parsed_resp_obj is not None:
                stop_reason = str(getattr(ctx.parsed_resp_obj, "stop_reason", "") or "")
            self._experiment_manager._task_tracker.record_turn(
                session_id=session_id,
                model=str(ctx.body.get("model", ctx.original_model)),
                tokens_in=int(getattr(ctx.parsed_resp_obj, "input_tokens", 0)) if ctx.parsed_resp_obj else 0,
                tokens_out=int(getattr(ctx.parsed_resp_obj, "output_tokens", 0)) if ctx.parsed_resp_obj else 0,
                cost_usd=float(ctx.proc_result.get("cost", 0.0)),
                latency_ms=(time.perf_counter() - ctx.request_started) * 1000.0,
                tool_calls=len(getattr(ctx.parsed_resp_obj, "tool_calls", [])) if ctx.parsed_resp_obj else 0,
                stop_reason=stop_reason,
                is_error=ctx.resp_status >= 400,
                was_escalated=ctx.was_escalated,
                was_loop_detected=ctx.was_loop_detected,
                experiment_id=ctx.experiment_id,
                variant_name=ctx.variant_name,
            )
            should_finalize = False
            if stop_reason == "end_turn":
                should_finalize = True
            elif ctx.was_loop_detected:
                should_finalize = True
            elif ctx.resp_status >= 400:
                state = self._experiment_manager._task_tracker.get_session_state(session_id)
                if state and state.consecutive_errors >= self._experiment_manager._task_tracker._config.consecutive_errors_threshold:
                    should_finalize = True

            if should_finalize:
                outcome = self._experiment_manager._task_tracker.finalize_session(session_id)
                if ctx.experiment_id and ctx.variant_name:
                    self._experiment_manager.record_task_outcome(ctx.experiment_id, ctx.variant_name, outcome)
        cost_value = float(ctx.proc_result.get("cost", 0.0)) if isinstance(ctx.proc_result, dict) else 0.0
        if cost_value > 0.0:
            self._cost_velocity.record(cost_value)
        if self._spend_rate_detector is not None and cost_value > 0.0:
            # Record actual cost from upstream response. This updates the spend-rate
            # detector for future checks. See budget phase comment on eventual consistency.
            self._spend_rate_detector.record_spend(cost_value)
            spend_state = self._spend_rate_detector.check()
            ctx.spend_rate_per_min = float(spend_state.current_rate)
        if self._spend_rate_detector is not None and self._spend_rate_detector.is_heartbeat_cost_high(ctx.body, cost_value):
            ctx.session_headers["X-Orchesis-Heartbeat-Costly"] = "true"
        if (
            self._semantic_cache is not None
            and ctx.resp_status == 200
            and not ctx.from_semantic_cache
            and not ctx.is_streaming
        ):
            messages = ctx.body.get("messages", [])
            if isinstance(messages, list) and messages:
                model = str(ctx.body.get("model", ""))
                tools = [
                    str(t.get("name", ""))
                    for t in ctx.body.get("tools", [])
                    if isinstance(t, dict) and t.get("name")
                ]
                tokens = 0
                if ctx.parsed_resp_obj is not None:
                    tokens = int(getattr(ctx.parsed_resp_obj, "input_tokens", 0) or 0) + int(
                        getattr(ctx.parsed_resp_obj, "output_tokens", 0) or 0
                    )
                cost = float(ctx.proc_result.get("cost", 0.0))
                self._semantic_cache.store(messages, model, tools or None, ctx.resp_body, tokens, cost)
        return True

    def _finalize_response_recording(self, ctx: _RequestContext) -> None:
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

    def _phase_send_response(self, ctx: _RequestContext) -> None:
        if isinstance(ctx.proc_result, dict):
            ctx.proc_result.setdefault("status_code", int(ctx.resp_status))
            if ctx.resp_status >= 400 and not ctx.proc_result.get("error_type"):
                ctx.proc_result["error_type"] = f"http_{ctx.resp_status}"
            ctx.proc_result.setdefault("blocked", bool(ctx.resp_status >= 400))
            ctx.proc_result.setdefault("request_id", str(ctx.request_id or ""))
            ctx.proc_result.setdefault("session_id", str(ctx.session_id or "unknown"))
            ctx.proc_result.setdefault("agent_id", str(ctx.behavior_agent_id or ""))
            ctx.proc_result.setdefault("model", str(ctx.original_model or ctx.body.get("model", "")))
            ctx.proc_result.setdefault("model_used", str(ctx.body.get("model", ctx.original_model)))
            ctx.proc_result.setdefault("cache_hit", bool(ctx.from_semantic_cache))
            ctx.proc_result.setdefault("cache_type", "semantic" if ctx.from_semantic_cache else "miss")
            ctx.proc_result.setdefault("loop_detected", bool(ctx.was_loop_detected))
            ctx.proc_result.setdefault("loop_count", int(ctx.content_loop_count))
            ctx.proc_result.setdefault("heartbeat_detected", bool(ctx.heartbeat_detected))
            ctx.proc_result.setdefault("spend_rate_5min", float(ctx.spend_rate_per_min))
            ctx.proc_result.setdefault("cascaded", bool(ctx.was_escalated))
            ctx.proc_result.setdefault("cascade_reason", "escalated" if ctx.was_escalated else "")
        if not ctx.is_streaming:
            ctx.handler.send_response(ctx.resp_status)
            self._copy_upstream_headers(ctx.handler, ctx.resp_headers, len(ctx.resp_body))
            ctx.handler.send_header("X-Orchesis-Cost", str(round(float(ctx.proc_result.get("cost", 0.0)), 6)))
            ctx.handler.send_header(
                "X-Orchesis-Cost-Velocity",
                str(round(float(self._cost_velocity.current_rate_per_hour()), 6)),
            )
            ctx.handler.send_header("X-Orchesis-Daily-Total", str(round(self._cost_tracker.get_daily_total(), 4)))
            daily_budget = self._budget_cfg.get("daily")
            if isinstance(daily_budget, int | float):
                ctx.handler.send_header("X-Orchesis-Daily-Budget", f"{float(daily_budget):.4f}")
            ctx.handler.send_header("X-Orchesis-Saved", f"{float(ctx.request_saved_usd):.4f}")
            ctx.handler.send_header("X-Orchesis-Session", str(ctx.session_id or ctx.proc_result.get("session_id", "unknown")))
            ctx.handler.send_header("X-Orchesis-Cascade-Level", ctx.cascade_level_name)
            ctx.handler.send_header("X-Orchesis-Cascade-Model", str(ctx.body.get("model", ctx.original_model)))
            if ctx.from_semantic_cache:
                ctx.handler.send_header("X-Orchesis-Cache", ctx.session_headers.get("X-Orchesis-Cache", "semantic"))
                ctx.handler.send_header("X-Orchesis-Cache-Similarity", ctx.session_headers.get("X-Orchesis-Cache-Similarity", "1.00"))
            else:
                ctx.handler.send_header("X-Orchesis-Cache", ctx.cascade_cache_state)
            ctx.handler.send_header("X-Orchesis-Circuit", self._circuit_breaker.get_state().lower().replace("_", "-"))
            if self._recorder is not None:
                ctx.handler.send_header("X-Orchesis-Session-Id", ctx.session_id)
                ctx.handler.send_header("X-Orchesis-Request-Id", ctx.request_id)
            if ctx.experiment_id:
                ctx.handler.send_header("X-Orchesis-Experiment", ctx.experiment_id)
            if ctx.variant_name:
                ctx.handler.send_header("X-Orchesis-Variant", ctx.variant_name)
            if ctx.loop_warning_header:
                ctx.handler.send_header("X-Orchesis-Loop-Warning", ctx.loop_warning_header)
            if ctx.content_loop_count > 1:
                ctx.handler.send_header("X-Orchesis-Loop-Count", str(ctx.content_loop_count))
            if ctx.heartbeat_detected:
                ctx.handler.send_header("X-Orchesis-Heartbeat", "true")
            ctx.handler.send_header("X-Orchesis-Spend-Rate", f"{ctx.spend_rate_per_min:.4f}")
            if ctx.context_tokens_saved > 0:
                ctx.handler.send_header("X-Orchesis-Context-Tokens-Saved", str(ctx.context_tokens_saved))
                ctx.handler.send_header("X-Orchesis-Context-Strategies", ",".join(ctx.context_strategies))
            if ctx.threat_matches:
                ctx.handler.send_header("X-Orchesis-Threat-Detected", ",".join(m.threat_id for m in ctx.threat_matches))
                ctx.handler.send_header("X-Orchesis-Threat-Severity", ctx.threat_matches[0].severity)
            if self._session_risk is not None:
                score = float(ctx.proc_result.get("session_risk_score", 0.0))
                if score > 0:
                    ctx.handler.send_header("X-Orchesis-Session-Risk", f"{score:.1f}")
            if self._behavioral_detector.enabled:
                ctx.handler.send_header("X-Orchesis-Behavior", ctx.behavior_header)
                if ctx.behavior_score_header:
                    ctx.handler.send_header("X-Orchesis-Anomaly-Score", ctx.behavior_score_header)
                if ctx.behavior_dims_header:
                    ctx.handler.send_header("X-Orchesis-Anomaly-Dimensions", ctx.behavior_dims_header)
            adaptive_score = float(ctx.proc_result.get("adaptive_anomaly_score", 0.0) or 0.0)
            if self._adaptive_detector is not None and adaptive_score > 0.0:
                ctx.handler.send_header("X-Orchesis-Adaptive-Score", f"{adaptive_score:.1f}")
                ctx.handler.send_header(
                    "X-Orchesis-Adaptive-Risk-Level",
                    str(ctx.proc_result.get("adaptive_risk_level", "low")),
                )
            if self._config.cors:
                ctx.handler.send_header("Access-Control-Allow-Origin", "*")
            ctx.handler.end_headers()
            self._finalize_response_recording(ctx)
            ctx.handler.wfile.write(ctx.resp_body)
            return
        self._finalize_response_recording(ctx)

    def _handle_post(self, handler: BaseHTTPRequestHandler) -> None:
        self._inc("requests")
        parsed_path = urlsplit(handler.path)
        request_path = parsed_path.path
        query_params = parse_qs(parsed_path.query, keep_blank_values=True)
        ctx = _RequestContext(
            handler=handler,
            request_started=time.perf_counter(),
            circuit_state_header=self._circuit_breaker.get_state().lower().replace("_", "-"),
            session_id=self._resolve_session_id(handler.headers),
            request_id=uuid.uuid4().hex if self._recorder is not None else "",
        )
        ctx.session_headers = (
            {"X-Orchesis-Session-Id": ctx.session_id, "X-Orchesis-Request-Id": ctx.request_id}
            if self._recorder is not None
            else {}
        )
        if self._span_emitter:
            headers_dict = {k: v for k, v in handler.headers.items()}
            ctx.trace_ctx = TraceContext.from_headers(headers_dict)
        try:
            if request_path == "/api/v1/telemetry/export-file":
                if self._telemetry_collector is None:
                    self._send_json(handler, 200, {"enabled": False})
                    return
                fmt = str((query_params.get("format") or ["jsonl"])[0]).strip().lower()
                if fmt == "csv":
                    export_path = "telemetry_export.csv"
                    count = self._telemetry_collector.export_csv(export_path)
                else:
                    export_path = "telemetry_export.jsonl"
                    count = self._telemetry_collector.export_jsonl(export_path)
                self._send_json(handler, 200, {"exported": count, "path": export_path})
                return
            if request_path.startswith("/api/v1/approvals/") and request_path.endswith("/approve"):
                if self._tool_policy is None:
                    self._send_json(handler, 200, {"enabled": False})
                    return
                approval_id = request_path.split("/api/v1/approvals/", 1)[1].rsplit("/approve", 1)[0].strip("/")
                ok = self._tool_policy.approval_queue.approve(approval_id)
                self._send_json(handler, 200 if ok else 404, {"approved": ok, "approval_id": approval_id})
                return
            if request_path.startswith("/api/v1/approvals/") and request_path.endswith("/deny"):
                if self._tool_policy is None:
                    self._send_json(handler, 200, {"enabled": False})
                    return
                approval_id = request_path.split("/api/v1/approvals/", 1)[1].rsplit("/deny", 1)[0].strip("/")
                ok = self._tool_policy.approval_queue.deny(approval_id)
                self._send_json(handler, 200 if ok else 404, {"denied": ok, "approval_id": approval_id})
                return
            if request_path == "/kill":
                self._handle_kill(handler)
                return
            if request_path == "/resume":
                self._handle_resume(handler)
                return
            if self._experiment_manager is not None and request_path == "/api/experiments":
                body = self._read_json_body(handler)
                if isinstance(body, dict) and body.get("name") and body.get("variants"):
                    try:
                        exp = self._experiment_manager.create_experiment(**body)
                        self._send_json(handler, 201, exp.to_dict())
                    except ValueError as e:
                        self._send_json(handler, 400, {"error": str(e)})
                else:
                    self._send_json(handler, 400, {"error": "name and variants required"})
                return
            if self._experiment_manager is not None and "/api/experiments/" in handler.path:
                parts = handler.path.split("/")
                if len(parts) >= 4:
                    exp_id = parts[3]
                    if handler.path.endswith("/start"):
                        ok = self._experiment_manager.start_experiment(exp_id)
                        self._send_json(handler, 200 if ok else 409, {"started": ok})
                        return
                    if handler.path.endswith("/stop"):
                        try:
                            result = self._experiment_manager.stop_experiment(exp_id)
                            self._send_json(handler, 200, result.to_dict())
                        except ValueError:
                            self._send_json(handler, 404, {"error": "experiment_not_found"})
                        return
                    if handler.path.endswith("/pause"):
                        ok = self._experiment_manager.pause_experiment(exp_id)
                        self._send_json(handler, 200 if ok else 409, {"paused": ok})
                        return
                    if handler.path.endswith("/resume"):
                        ok = self._experiment_manager.resume_experiment(exp_id)
                        self._send_json(handler, 200 if ok else 409, {"resumed": ok})
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
            if self._span_emitter and ctx.trace_ctx:
                agent_id = (
                    ctx.handler.headers.get("X-Orchesis-Agent")
                    or ctx.handler.headers.get("x-orchesis-agent")
                    or ctx.behavior_agent_id
                    or ""
                )
                ctx.root_span = self._span_emitter.create_request_span(
                    ctx.trace_ctx,
                    model=str(ctx.body.get("model", ctx.parsed_req.model or "")),
                    provider=ctx.parsed_req.provider or "",
                    session_id=ctx.session_id or "",
                    agent_id=agent_id,
                )
            if not self._run_phase_span(ctx, "experiment", self._phase_experiment):
                return
            if not self._run_phase_span(ctx, "flow_xray_record", self._phase_flow_xray_record):
                return
            if not self._run_phase_span(ctx, "cascade", self._phase_cascade):
                if ctx.root_span:
                    self._span_emitter.end_span(
                        ctx.root_span,
                        attributes={
                            "orchesis.cascade_level": str(getattr(ctx, "cascade_level_name", "")),
                            "orchesis.cache_hit": bool(getattr(ctx, "cascade_cache_state", "") == "hit"),
                        },
                    )
                return
            def _end_root_early() -> None:
                if ctx.root_span and self._span_emitter:
                    self._span_emitter.end_span(
                        ctx.root_span,
                        status="OK",
                        attributes={"orchesis.decision": "block"},
                    )

            if not self._run_phase_span(ctx, "circuit_breaker", self._phase_circuit_breaker):
                _end_root_early()
                return
            if not self._run_phase_span(ctx, "loop_detection", self._phase_loop_detection):
                _end_root_early()
                return
            if not self._run_phase_span(ctx, "behavioral", self._phase_behavioral):
                _end_root_early()
                return
            if not self._run_phase_span(ctx, "adaptive_detection", self._phase_adaptive_detection):
                _end_root_early()
                return
            if not self._run_phase_span(ctx, "mast_request", self._phase_mast_request):
                _end_root_early()
                return
            if not self._run_phase_span(ctx, "auto_healing", self._phase_auto_healing):
                _end_root_early()
                return
            if not self._run_phase_span(ctx, "budget", self._phase_budget):
                _end_root_early()
                return
            if not self._run_phase_span(ctx, "policy", self._phase_policy):
                _end_root_early()
                return
            if not self._run_phase_span(ctx, "threat_intel", self._phase_threat_intel):
                _end_root_early()
                return
            if not self._run_phase_span(ctx, "model_router", self._phase_model_router):
                _end_root_early()
                return
            if not self._run_phase_span(ctx, "secrets", self._phase_secrets):
                _end_root_early()
                return
            if not self._run_phase_span(ctx, "context", self._phase_context):
                _end_root_early()
                return
            if not self._run_phase_span(ctx, "upstream", self._phase_upstream):
                _end_root_early()
                return
            if not self._run_phase_span(ctx, "post_upstream", self._phase_post_upstream):
                _end_root_early()
                return
            if ctx.root_span:
                cost = (ctx.proc_result or {}).get("cost", 0.0) if isinstance(ctx.proc_result, dict) else 0.0
                parsed = ctx.parsed_resp_obj
                self._span_emitter.end_span(
                    ctx.root_span,
                    attributes={
                        "gen_ai.response.model": str(ctx.body.get("model", "")),
                        "gen_ai.usage.input_tokens": getattr(parsed, "input_tokens", 0) if parsed else 0,
                        "gen_ai.usage.output_tokens": getattr(parsed, "output_tokens", 0) if parsed else 0,
                        "gen_ai.response.finish_reasons": getattr(parsed, "stop_reason", "") if parsed else "",
                        "orchesis.cost_usd": float(cost) if isinstance(ctx.proc_result, dict) else 0.0,
                        "orchesis.decision": "allow",
                        "orchesis.experiment_id": getattr(ctx, "experiment_id", "") or "",
                        "orchesis.variant_name": getattr(ctx, "variant_name", "") or "",
                    },
                )
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
        finally:
            self._record_telemetry_for_ctx(ctx)

    def _record_telemetry_for_ctx(self, ctx: _RequestContext) -> None:
        try:
            proc = ctx.proc_result if isinstance(ctx.proc_result, dict) else {}
            if not isinstance(proc, dict):
                proc = {}
            elapsed_ms = (time.perf_counter() - float(ctx.request_started or 0.0)) * 1000.0
            if elapsed_ms > 0:
                proc["total_ms"] = float(proc.get("total_ms", 0.0) or elapsed_ms)
            if "upstream_ms" not in proc:
                proc["upstream_ms"] = float(proc.get("upstream_ms", 0.0) or 0.0)
            if "request_id" not in proc or not proc.get("request_id"):
                proc["request_id"] = str(ctx.request_id or "")
            if "session_id" not in proc or not proc.get("session_id"):
                proc["session_id"] = str(ctx.session_id or "unknown")
            if "agent_id" not in proc or not proc.get("agent_id"):
                proc["agent_id"] = str(ctx.behavior_agent_id or "")
            if "model" not in proc or not proc.get("model"):
                proc["model"] = str(ctx.original_model or ctx.body.get("model", ""))
            if "model_used" not in proc or not proc.get("model_used"):
                proc["model_used"] = str(ctx.body.get("model", ctx.original_model))
            if "cost_usd" not in proc:
                proc["cost_usd"] = float(proc.get("cost", 0.0) or 0.0)
            if "input_tokens" not in proc:
                proc["input_tokens"] = int(getattr(ctx.parsed_resp_obj, "input_tokens", 0) or 0)
            if "output_tokens" not in proc:
                proc["output_tokens"] = int(getattr(ctx.parsed_resp_obj, "output_tokens", 0) or 0)
            if "tool_calls_count" not in proc:
                proc["tool_calls_count"] = len(getattr(ctx.parsed_req, "tool_calls", []) or [])
            if "has_tool_results" not in proc:
                proc["has_tool_results"] = bool(getattr(ctx.parsed_resp_obj, "tool_calls", []) or [])
            if "streaming" not in proc:
                proc["streaming"] = bool(ctx.is_streaming)
            if "cache_hit" not in proc:
                proc["cache_hit"] = bool(ctx.from_semantic_cache)
            if "cache_type" not in proc:
                proc["cache_type"] = (
                    str(ctx.semantic_cache_type or "semantic")
                    if ctx.from_semantic_cache
                    else str("miss" if ctx.cascade_cache_state == "miss" else "exact")
                )
            if "loop_detected" not in proc:
                proc["loop_detected"] = bool(ctx.was_loop_detected)
            if "loop_count" not in proc:
                proc["loop_count"] = int(ctx.content_loop_count)
            if "content_hash_blocked" not in proc:
                proc["content_hash_blocked"] = bool(
                    getattr(ctx.handler, "_orchesis_last_error_type", "") == "content_loop_detected"
                )
            if "heartbeat_detected" not in proc:
                proc["heartbeat_detected"] = bool(ctx.heartbeat_detected)
            if "spend_rate_5min" not in proc:
                proc["spend_rate_5min"] = float(ctx.spend_rate_per_min)
            if "cascaded" not in proc:
                proc["cascaded"] = bool(ctx.was_escalated)
            if "cascade_reason" not in proc:
                proc["cascade_reason"] = "escalated" if ctx.was_escalated else ""
            if "threat_matches" not in proc and ctx.threat_matches:
                proc["threat_matches"] = list(ctx.threat_matches)
            status_hint = int(getattr(ctx.handler, "_orchesis_last_status", 0) or 0)
            if "status_code" not in proc or int(proc.get("status_code", 0) or 0) <= 0:
                proc["status_code"] = int(ctx.resp_status if ctx.resp_status > 0 else status_hint or 200)
            if "error_type" not in proc or not proc.get("error_type"):
                proc["error_type"] = str(getattr(ctx.handler, "_orchesis_last_error_type", ""))[:120]
            if "blocked" not in proc:
                proc["blocked"] = bool(int(proc.get("status_code", 0) or 0) >= 400)
            if "block_reason" not in proc or not proc.get("block_reason"):
                proc["block_reason"] = str(proc.get("error_type", ""))
            ctx.proc_result = proc
            if self._ars is not None:
                agent_id = str(proc.get("agent_id", "") or "")
                if agent_id:
                    status_code = int(proc.get("status_code", 200) or 200)
                    error_type = str(proc.get("error_type", "") or "").lower()
                    session_success = bool(status_code < 400 and not proc.get("blocked", False))
                    clean_termination = bool(
                        status_code < 500
                        and "timeout" not in error_type
                        and "circuit" not in error_type
                        and "budget_exceeded" not in error_type
                    )
                    self._ars.update(
                        agent_id,
                        is_session_end=True,
                        session_success=session_success,
                        loop_flagged=bool(proc.get("loop_detected", False)),
                        cost_usd=float(proc.get("cost_usd", 0.0) or 0.0),
                        latency_ms=float(proc.get("total_ms", 0.0) or 0.0),
                        token_count=int(proc.get("input_tokens", 0) or 0) + int(proc.get("output_tokens", 0) or 0),
                        clean_termination=clean_termination,
                        has_threat=bool(proc.get("threat_matches")),
                    )
            if self._telemetry_collector is not None:
                from orchesis.telemetry_export import build_record_from_context

                rec = build_record_from_context(ctx)
                self._telemetry_collector.record(rec)
        except Exception as error:  # noqa: BLE001
            _HTTP_PROXY_LOGGER.warning("telemetry/ars finalize hook failed: %s", error)
            return

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
        if self._experiment_manager is not None and handler.path.startswith("/api/experiments/"):
            parts = handler.path.split("/")
            if len(parts) >= 4 and parts[3]:
                exp_id = parts[3]
                ok = self._experiment_manager.delete_experiment(exp_id)
                self._send_json(handler, 200 if ok else 404, {"deleted": ok})
                return
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
        sid = (
            headers.get("X-OpenClaw-Session")
            or headers.get("x-openclaw-session")
            or headers.get("X-Session-Id")
            or headers.get("x-session-id")
            or headers.get("X-Request-Id")
            or headers.get("x-request-id")
            or headers.get("X-Session")
            or headers.get("x-session")
        )
        if not isinstance(sid, str) or not sid.strip():
            sid = headers.get("X-Orchesis-Session-Id") or headers.get("x-orchesis-session-id")
        if isinstance(sid, str) and sid.strip():
            return sid.strip()
        return "unknown"

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
        try:
            setattr(handler, "_orchesis_last_status", int(status))
            error_type = ""
            raw_err = payload.get("error") if isinstance(payload, dict) else None
            if isinstance(raw_err, dict):
                maybe = raw_err.get("type", "") or raw_err.get("error", "")
                if isinstance(maybe, str):
                    error_type = maybe
            elif isinstance(raw_err, str):
                error_type = raw_err
            setattr(handler, "_orchesis_last_error_type", str(error_type))
        except Exception:
            pass
        try:
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
        except (ConnectionAbortedError, BrokenPipeError, OSError):
            return
