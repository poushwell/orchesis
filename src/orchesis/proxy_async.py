"""Asyncio FastAPI proxy variant + factory functions."""

from __future__ import annotations

import atexit
import asyncio
import concurrent.futures
from collections import deque
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import logging
import os
import random
import socket
import threading
import time
import uuid
from typing import Any, AsyncGenerator
import http.client
from urllib.parse import parse_qs, urlsplit
from urllib.error import URLError
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
from orchesis.integrations.alert_manager import AlertConfig, AlertEvent, AlertManager, AlertSeverity
from orchesis.behavioral import BehavioralDetector, extract_agent_id
from orchesis.cost_tracker import CostTracker
from orchesis.circuit_breaker import CircuitBreaker
from orchesis.credential_injector import CredentialInjector
from orchesis.credential_vault import CredentialNotFoundError, build_vault_from_policy
from orchesis.contrib.pii_detector import PiiDetector
from orchesis.contrib.secret_scanner import SecretScanner
from orchesis.config import (
    DEFAULT_CONNECTION_POOL_MAX_PER_HOST,
    DEFAULT_CONNECTION_POOL_MAX_TOTAL,
    DEFAULT_PROXY_MAX_WORKERS,
    DEFAULT_RESUME_TOKEN,
    DEFAULT_STREAMING_MAX_ACCUMULATED_EVENTS,
    PolicyWatcher,
    _redact_config,
    load_policy,
    validate_policy,
    validate_startup_policy,
)
from orchesis.engine import evaluate
from orchesis.events import EventBus
from orchesis.forensics import Incident
from orchesis.integrations import SlackEmitter, SlackNotifier, TelegramEmitter, TelegramNotifier
from orchesis.integrations.forensics_emitter import ForensicsEmitter
from orchesis.loop_detector import ContentLoopDetector, LoopDetector
from orchesis.metrics import MetricsCollector
from orchesis.model_router import ModelRouter
from orchesis.cascade import CascadeLevel, CascadeRouter
from orchesis.otel import OTelEmitter, ProxySpanEmitter, TraceContext
from orchesis.otel_export import OTLPExportConfig, OTLPSpanExporter
from orchesis.policy_store import PolicyStore
from orchesis.state import RateLimitTracker
from orchesis.structured_log import StructuredLogger
from orchesis.telemetry import JsonlEmitter
from orchesis.request_sampler import RequestSampler
from orchesis.webhooks import WebhookConfig, WebhookEmitter
from orchesis.request_parser import parse_request, parse_response
from orchesis.recorder import SessionRecord, SessionRecorder
from orchesis.response_handler import ResponseProcessor, SECRET_PATTERNS
from orchesis.session_risk import RiskSignal, SessionRiskAccumulator
from orchesis.flow_xray import FlowAnalyzer, FlowXRayConfig
from orchesis.pipeline import (
    Identity as _PipelineIdentity,
    InputSnapshot as _PipelineInputSnapshot,
    PhaseRegistry,
    PipelineEngine,
    Processed as _PipelineProcessed,
    RecordingHandle as _PipelineRecordingHandle,
    RequestContext as _PipelineRequestContext,
    Tracking as _PipelineTracking,
)
from orchesis.phases import (
    CanonicalizePhase,
    CompressionDecodePhase,
    FlowXrayRecordPhase,
    make_legacy_phase,
)
from orchesis.phases._phase_methods import PhaseMethodsMixin
from orchesis.dsl import (
    DslError,
    ResolverContext as _DslResolverContext,
    ThresholdResolver,
)
from orchesis.sigma import SigmaMonitor
from orchesis.blind_spots import BlindSpotDetector
from orchesis.signed_journal import SignedJournal
from orchesis.providers import (
    adapter_for_model as _adapter_for_model,
    get_adapter as _get_adapter,
)
from orchesis.ars import AgentReliabilityScore
from orchesis.adaptive_detector import AdaptiveDetector
from orchesis.adaptive_detection_v2 import AdaptiveDetectionV2
from orchesis.community import CommunityClient
from orchesis.mast_detectors import MASTDetectors
from orchesis.message_chain import validate_tool_chain
from orchesis.context_optimizer import ContextOptimizer
from orchesis.context_router import ContextStrategyRouter
from orchesis.auto_healer import AutoHealer
from orchesis.mco import MCO
from orchesis.bandit_sampler import BanditSampler
from orchesis.agent_discovery import AgentDiscovery
from orchesis.tool_policy import ToolPolicyEngine
from orchesis.cost_velocity import CostVelocity
from orchesis.plugin_system import (
    PluginRegistry,
    RequestEnricherPlugin,
    RequestLoggerPlugin,
    ResponseValidatorPlugin,
)
from orchesis.cost_optimizer import CostOptimizer
from orchesis.content_ranker import ContentRanker
from orchesis.dashboard import get_dashboard_html
from orchesis.error_responses import ErrorResponseBuilder
from orchesis.session_export import export_session_to_air
from orchesis import __version__ as ORCHESIS_VERSION
from orchesis.compliance import ComplianceEngine, Framework, Severity
from orchesis.connection_pool import ConnectionPool, PoolConfig, PooledConnection
from orchesis.experiment import ExperimentConfig, ExperimentManager
from orchesis.context_engine import ContextConfig, ContextEngine
from orchesis.context_budget import ContextBudget
from orchesis.context_window_optimizer import ContextWindowOptimizer
from orchesis.context_compression_v2 import ContextCompressionV2
from orchesis.threat_intel import ThreatIntelConfig, ThreatMatcher
from orchesis.openclaw_presets import OPENCLAW_SAFE_POLICY, apply_openclaw_preset
from orchesis.semantic_cache import SemanticCache, SemanticCacheConfig
from orchesis.spend_rate import SpendRateDetector, SpendWindow
from orchesis.request_prioritizer import RequestPrioritizer
from orchesis.injection_protocol import ContextInjectionProtocol
from orchesis.context_termination import ContextTerminationEngine
from orchesis.core.context_profile_logger import log_context_profile
from orchesis.core.evidence_ledger import EvidenceLedger

_HTTP_PROXY_LOGGER = logging.getLogger("orchesis.http_proxy")
_evidence_ledger = EvidenceLedger()
atexit.register(_evidence_ledger.close)


def compute_upstream_retry_delay(
    failed_attempt_index: int,
    *,
    base_delay: float = 0.1,
    max_delay: float = 2.0,
    random_unit: float | None = None,
) -> float:
    """Delay before the next upstream retry after a failure (full jitter on [0.5, 1.0] × capped exponential).

    ``failed_attempt_index`` is the 0-based index of the attempt that just failed (0 after first failure).
    """
    if failed_attempt_index < 0:
        return 0.0
    delay = min(float(base_delay) * (2**failed_attempt_index), float(max_delay))
    u = float(random_unit) if random_unit is not None else random.random()
    return delay * (0.5 + u * 0.5)


_DEFAULT_LISTEN_HOST = "127.0.0.1"
_LOCALHOST_HOSTNAMES = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0"})
_DASHBOARD_MAX_EVENTS = 500
_DASHBOARD_MAX_COST_TIMELINE = 1000
_DASHBOARD_RECENT_BLOCKED_WINDOW_SECONDS = 300.0
_DEFAULT_OTLP_HTTP_ENDPOINT = "http://localhost:4318"


@dataclass
class ProxyConfig:
    """Listen/bind and forwarding options for the asyncio :class:`OrchesisProxy` server."""

    listen_host: str = _DEFAULT_LISTEN_HOST
    listen_port: int = 8080
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

    def record_detection(
        self, *, secrets_detected: int = 0, secrets_blocked: int = 0, pii_detected: int = 0
    ) -> None:
        with self._lock:
            self.secrets_detected += max(0, int(secrets_detected))
            self.secrets_blocked += max(0, int(secrets_blocked))
            self.pii_detected += max(0, int(pii_detected))


class PooledThreadHTTPServer(HTTPServer):
    """HTTPServer with bounded worker pool."""

    def __init__(
        self,
        server_address: tuple[str, int],
        request_handler_class: Any,
        max_workers: int = DEFAULT_PROXY_MAX_WORKERS,
    ) -> None:
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


# Default declarative thresholds. Replaced by `policy["thresholds"]` when
# the operator provides one. The keys here are the only thresholds the
# proxy looks up via the DSL today — additions land here when new phases
# adopt declarative configuration.
DEFAULT_THRESHOLDS: dict[str, list[dict[str, object]]] = {
    "sigma_cascade": [
        {"if": 'ctx.tier == "deep_pro" and ctx.task_type == "tool_use"',
         "value": 0.55},
        {"if": 'ctx.tier == "deep_pro"', "value": 0.70},
        {"if": "ctx.chain_length > 50", "value": 0.65},
        {"default": 0.80},
    ],
    "circuit_breaker_max_errors": [
        {"if": 'ctx.tier == "free"', "value": 3},
        {"if": 'ctx.tier == "lite"', "value": 5},
        {"if": 'ctx.tier == "pro"', "value": 10},
        {"if": 'ctx.tier == "deep_pro"', "value": 15},
        {"default": 5},
    ],
    "loop_max_repeats": [
        {"if": "ctx.chain_length > 30", "value": 1},
        {"if": "ctx.chain_length > 10", "value": 2},
        {"default": 3},
    ],
}


def _redact_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{k: v for k, v in finding.items() if k != "raw_match"} for finding in findings]


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
            framework = ComplianceEngine._framework_from_alias(
                token if isinstance(token, str) else None
            )
            if framework is not None and framework not in resolved:
                resolved.append(framework)
    if not resolved:
        resolved = [Framework.OWASP_LLM_TOP_10, Framework.NIST_AI_RMF]
    return resolved


def _init_components(
    policy: dict[str, Any], *, policy_path: str = "policy.yaml"
) -> ProxyComponents:
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
            strategies=list(
                context_cfg.get("strategies", ["dedup", "trim_tool_results", "trim_system_dups"])
            ),
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
            "critical": "warn",
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
                token_waste_stddev_threshold=float(
                    flow_cfg.get("token_waste_stddev_threshold", 2.0)
                ),
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



# === Extracted classes / functions ===

class OrchesisProxy:
    """Asyncio HTTP proxy that can enforce Orchesis policy checks."""

    def __init__(
        self,
        engine,
        config: ProxyConfig,
        event_bus=None,
        redactor=None,
        policy: dict[str, Any] | None = None,
    ) -> None:
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
        secret_cfg = (
            proxy_cfg.get("secret_scanning")
            if isinstance(proxy_cfg.get("secret_scanning"), dict)
            else {}
        )
        pii_cfg = (
            proxy_cfg.get("pii_scanning") if isinstance(proxy_cfg.get("pii_scanning"), dict) else {}
        )
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

    async def start(self) -> asyncio.Server:
        self._server = await asyncio.start_server(
            self.handle_request,
            host=self._config.listen_host,
            port=self._config.listen_port,
        )
        return self._server

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def handle_request(self, reader: Any, writer: Any) -> None:
        started = time.perf_counter()
        decision_label = "ERROR"
        bytes_count = 0
        try:
            parsed = await self._read_http_request(reader)
            if parsed is None:
                writer.write(
                    self._build_error_response(400, "bad_request", "Malformed HTTP request")
                )
                await writer.drain()
                decision_label = "ERROR"
                return
            method, path, headers, body = parsed
            bytes_count = len(body)
            behavior_state_header = "normal"
            anomaly_score_header = ""
            anomaly_dimensions_header = ""

            if len(body) > self._config.max_body_size:
                writer.write(
                    self._build_error_response(413, "payload_too_large", "Request body too large")
                )
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
                        "context": {
                            "path": path,
                            "method": method,
                            "agent": headers.get("x-agent", "proxy_agent"),
                        },
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
                        "context": {
                            "path": path,
                            "method": method,
                            "agent": headers.get("x-agent", "proxy_agent"),
                        },
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
                critical = [
                    item
                    for item in request_findings
                    if str(item.get("severity", "")).lower() == "critical"
                ]
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
                            "findings": _redact_findings(request_findings[:10]),
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

            status, resp_headers, resp_body = await self._forward_request(
                method, path, headers, body
            )
            if self._behavioral_detector.enabled:
                completion_tokens = 0
                try:
                    decoded = json.loads(resp_body.decode("utf-8"))
                    if isinstance(decoded, dict):
                        usage = decoded.get("usage")
                        if isinstance(usage, dict):
                            completion_tokens = int(
                                usage.get("completion_tokens") or usage.get("output_tokens") or 0
                            )
                except Exception:
                    completion_tokens = 0
                self._behavioral_detector.record_response(
                    extract_agent_id(
                        {"headers": headers, "model": (body_json or {}).get("model", "")}
                    ),
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
                            "secret_findings": _redact_findings(secrets[:10]),
                            "pii_findings": _redact_findings(pii[:10]),
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
                writer.write(
                    self._build_error_response(400, "bad_request", "Malformed HTTP request")
                )
                await writer.drain()
            except Exception as exc:
                _HTTP_PROXY_LOGGER.debug("Suppressed: %s", exc)
            decision_label = "ERROR"
        finally:
            latency_ms = (time.perf_counter() - started) * 1000.0
            self._stats.record_request(decision_label, latency_ms, bytes_count)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception as exc:
                _HTTP_PROXY_LOGGER.debug("Suppressed: %s", exc)

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
            return (
                502,
                {"content-type": "application/json"},
                b'{"error":"unsupported_upstream_scheme"}',
            )
        host = parsed.hostname or _DEFAULT_LISTEN_HOST
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
            return (
                502,
                {"content-type": "application/json"},
                b'{"error":"upstream_connection_failed"}',
            )

        try:
            writer.write(request_bytes)
            await asyncio.wait_for(writer.drain(), timeout=self._config.timeout_seconds)
            response = await self._read_http_response(reader)
            if response is None:
                return (
                    502,
                    {"content-type": "application/json"},
                    b'{"error":"invalid_upstream_response"}',
                )
            return response
        except Exception:
            return 502, {"content-type": "application/json"}, b'{"error":"upstream_timeout"}'
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception as exc:
                _HTTP_PROXY_LOGGER.debug("Suppressed: %s", exc)

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
                        "findings": _redact_findings(findings[:10]),
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
                    if _SEVERITY_ORDER.get(str(item.get("severity", "")).lower(), 0)
                    >= threshold_rank
                ]
            if findings:
                self._emit_event(
                    {
                        "event": "proxy_request_scan",
                        "tool": tool_name,
                        "count": len(findings),
                        "findings": _redact_findings(findings[:10]),
                    }
                )
        except Exception:
            return []
        return findings

    def _scan_response_findings(
        self, tool_name: str, response_body: bytes
    ) -> dict[str, list[dict[str, Any]]]:
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
                        if _SEVERITY_ORDER.get(str(item.get("severity", "")).lower(), 0)
                        >= threshold_rank
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
                        "secret_findings": _redact_findings(secret_findings[:10]),
                        "pii_findings": _redact_findings(pii_findings[:10]),
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

    def _evaluate(self, payload: dict[str, Any]) -> Any:
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
        except Exception as exc:
            _HTTP_PROXY_LOGGER.debug("Suppressed: %s", exc)

    def _extract_reason_rule_severity(self, decision) -> tuple[str, str, str]:
        reasons = getattr(decision, "reasons", [])
        reason = reasons[0] if isinstance(reasons, list) and reasons else "blocked_by_policy"
        rule = reason.split(":", 1)[0] if ":" in reason else "policy"
        severity = "high" if "daily token budget" in reason.lower() else "medium"
        return reason, rule, severity

    async def _read_http_request(self, reader) -> tuple[str, str, dict[str, str], bytes] | None:
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

    async def _read_http_response(self, reader) -> tuple[int, dict[str, str], bytes] | None:
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
            raw = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"), timeout=self._config.timeout_seconds
            )
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
    session_header = _resolve_session_id(request.headers)
    if isinstance(session_header, str) and session_header.strip():
        context["session"] = session_header.strip()
    return context


def _resolve_session_id(headers: Any) -> str:
    """Resolve canonical request session scope from known headers."""
    if headers is None:
        return "default"

    def _header(name: str) -> str:
        value = ""
        try:
            value = headers.get(name, "")  # type: ignore[attr-defined]
        except Exception:
            value = ""
        if not value:
            try:
                value = headers.get(name.lower(), "")  # type: ignore[attr-defined]
            except Exception:
                value = ""
        return str(value).strip() if value is not None else ""

    for header in (
        "x-orchesis-session-id",
        "x-openclaw-session-id",
        "x-openclaw-session",
        "x-session-id",
        "x-session",
    ):
        sid = _header(header)
        if sid:
            return sid
    return "default"



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
    recording_cfg = (
        current_policy.get("recording") if isinstance(current_policy.get("recording"), dict) else {}
    )
    sampling_cfg = (
        recording_cfg.get("sampling")
        if isinstance(recording_cfg.get("sampling"), dict)
        else {"rate": 1.0, "strategy": "always_block", "always_record_blocks": True}
    )
    request_sampler = RequestSampler(sampling_cfg)
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

    class _SampledJsonlEmitter:
        def __init__(self, emitter: JsonlEmitter, sampler: RequestSampler) -> None:
            self._emitter = emitter
            self._sampler = sampler

        def set_sampler(self, sampler: RequestSampler) -> None:
            self._sampler = sampler

        def emit(self, event: dict[str, Any]) -> None:
            if isinstance(event, dict) and "decision" in event:
                if not self._sampler.should_record(event):
                    return
            self._emitter.emit(event)

    sampled_jsonl = _SampledJsonlEmitter(JsonlEmitter(decisions_log_path), request_sampler)
    _ = event_bus.subscribe(sampled_jsonl)
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
            except Exception as exc:
                _HTTP_PROXY_LOGGER.debug("Suppressed: %s", exc)
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
                    channel=slack_cfg.get("channel")
                    if isinstance(slack_cfg.get("channel"), str)
                    else None,
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
            nonlocal \
                current_policy, \
                current_registry, \
                current_policy_hash, \
                behavioral_detector, \
                recorder, \
                recording_cfg
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
                current_policy.get("recording")
                if isinstance(current_policy.get("recording"), dict)
                else {}
            )
            sampling_cfg_reload = (
                recording_cfg.get("sampling")
                if isinstance(recording_cfg.get("sampling"), dict)
                else {"rate": 1.0, "strategy": "always_block", "always_record_blocks": True}
            )
            sampled_jsonl.set_sampler(RequestSampler(sampling_cfg_reload))
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
    async def _lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
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
        session_id = _resolve_session_id(request.headers)
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
                    {
                        "tool_name": extracted_tool,
                        "params": extracted_params,
                        "headers": forwarded_headers,
                    }
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
            injected_params = (
                injected.get("params")
                if isinstance(injected.get("params"), dict)
                else extracted_params
            )
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
                elif body_json.get("method") == "tools/call" and isinstance(
                    body_json.get("params"), dict
                ):
                    nested = dict(body_json.get("params"))
                    nested["arguments"] = dict(extracted_params)
                    body_json["params"] = nested
                elif body_json.get("jsonrpc") == "2.0" and isinstance(
                    body_json.get("params"), dict
                ):
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
                            usage.get("completion_tokens") or usage.get("output_tokens") or 0
                        )
            except Exception:
                completion_tokens = 0
            behavioral_detector.record_response(
                extract_agent_id(
                    {"headers": dict(request.headers), "model": (body_json or {}).get("model", "")}
                ),
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
                        error=None
                        if forwarded.status_code < 400
                        else f"http_{forwarded.status_code}",
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
            "version": ORCHESIS_VERSION,
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
    backend_url = os.getenv("BACKEND_URL", f"http://{_DEFAULT_LISTEN_HOST}:8081")
    policy = load_policy(policy_path)
    return create_proxy_app(policy=policy, policy_path=policy_path, backend_url=backend_url)


app = build_app_from_env()


@dataclass
class HTTPProxyConfig:
    """Configuration for stdlib HTTP LLM proxy."""

    host: str = _DEFAULT_LISTEN_HOST
    port: int = 8080
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
    skip_phases: set[str] = field(default_factory=set)


# Inject proxy module-level helpers into the mixin module's namespace so the
# extracted methods can call them as bare names. This avoids a circular
# import (mixin → proxy) and keeps the extracted method bodies byte-identical
# to their original form. Names are resolved at runtime via the mixin
# module's globals, which include all the names listed here.
import orchesis.phases._phase_methods as _pm_mod
for _name, _val in list(globals().items()):
    if _name.startswith("__"):
        continue
    if _name not in vars(_pm_mod):
        setattr(_pm_mod, _name, _val)
del _name, _val, _pm_mod

