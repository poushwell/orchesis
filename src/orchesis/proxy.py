"""FastAPI proxy layer using Orchesis rule engine."""

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
from orchesis.phases._handler_methods import HandlerMethodsMixin
# Re-export the asyncio variant + factory functions from the dedicated module.
from orchesis import proxy_async as _proxy_async_mod
for _name, _val in vars(_proxy_async_mod).items():
    if _name.startswith("__"):
        continue
    if _name not in globals():
        globals()[_name] = _val
del _name, _val
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

# Inject proxy module-level names into the handler-methods mixin module so
# bare references inside extracted method bodies resolve at runtime.
import orchesis.phases._handler_methods as _hm_mod
import orchesis.phases._phase_methods as _pm_mod
for _name, _val in list(globals().items()):
    if _name.startswith("__"):
        continue
    if _name not in vars(_hm_mod):
        setattr(_hm_mod, _name, _val)
    if _name not in vars(_pm_mod):
        setattr(_pm_mod, _name, _val)
del _name, _val, _hm_mod, _pm_mod


class LLMHTTPProxy(PhaseMethodsMixin, HandlerMethodsMixin):
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
            self._policy = load_policy(policy_path)

        critical, startup_warnings = validate_startup_policy(
            self._policy,
            listen_port=self._config.port,
            runtime_upstream=dict(self._config.upstream) if self._config.upstream else None,
        )
        for msg in startup_warnings:
            _HTTP_PROXY_LOGGER.warning("%s", msg)
        if critical:
            for msg in critical:
                _HTTP_PROXY_LOGGER.critical("%s", msg)
            raise RuntimeError("; ".join(critical))

        if _HTTP_PROXY_LOGGER.isEnabledFor(logging.DEBUG):
            snap = json.dumps(_redact_config(self._policy), ensure_ascii=False, default=str)
            if len(snap) > 8000:
                snap = snap[:8000] + "…"
            _HTTP_PROXY_LOGGER.debug("policy snapshot (redacted): %s", snap)

        self._fast_path = None
        self._fast_path_mandatory_phases = {
            "parse",
            "policy",
            "secrets",
            "budget",
            "upstream",
            "post_upstream",
            "send",
        }
        try:
            from orchesis.fast_path import (
                FastPathEvaluator,
                MANDATORY_PHASES as _FAST_PATH_MANDATORY_PHASES,
            )

            self._fast_path = FastPathEvaluator(policy=self._policy)
            self._fast_path_mandatory_phases = set(_FAST_PATH_MANDATORY_PHASES)
        except ImportError:
            self._fast_path = None
        self._openclaw_safe_policy = apply_openclaw_preset(self._policy)
        safe_ti_cfg = OPENCLAW_SAFE_POLICY.get("threat_intel", {})
        disabled = safe_ti_cfg.get("disabled_threats", []) if isinstance(safe_ti_cfg, dict) else []
        self._openclaw_safe_skip: set[str] = {
            str(item).strip().upper() for item in disabled if str(item).strip()
        }
        proxy_engine_cfg = self._policy.get("proxy")
        self._proxy_engine_cfg = proxy_engine_cfg if isinstance(proxy_engine_cfg, dict) else {}
        self._ssrf_allow_private = bool(self._proxy_engine_cfg.get("ssrf_allow_private", False))
        self._max_workers = int(
            self._proxy_engine_cfg.get("max_workers", DEFAULT_PROXY_MAX_WORKERS)
        )
        if self._max_workers <= 0:
            self._max_workers = DEFAULT_PROXY_MAX_WORKERS
        max_body_size_raw = self._proxy_engine_cfg.get("max_body_size_bytes", 10_485_760)
        self._max_body_size_bytes = (
            int(max_body_size_raw) if isinstance(max_body_size_raw, int | float) else 10_485_760
        )
        if self._max_body_size_bytes <= 0:
            self._max_body_size_bytes = 10_485_760
        pool_cfg_raw = self._proxy_engine_cfg.get("connection_pool", {})
        pool_cfg = pool_cfg_raw if isinstance(pool_cfg_raw, dict) else {}
        self._connection_pool = ConnectionPool(
            PoolConfig(
                max_connections_per_host=int(
                    pool_cfg.get("max_per_host", DEFAULT_CONNECTION_POOL_MAX_PER_HOST)
                ),
                max_total_connections=int(
                    pool_cfg.get("max_total", DEFAULT_CONNECTION_POOL_MAX_TOTAL)
                ),
                idle_timeout=float(pool_cfg.get("idle_timeout", 60.0)),
                connection_timeout=float(pool_cfg.get("connection_timeout", self._config.timeout)),
                retry_on_connection_error=bool(pool_cfg.get("retry_on_connection_error", True)),
                max_retries=int(pool_cfg.get("max_retries", 2)),
            )
        )
        base_retry = pool_cfg.get("upstream_retry_base_delay_seconds", 0.1)
        max_retry = pool_cfg.get("upstream_retry_max_delay_seconds", 2.0)
        self._upstream_retry_base_delay = (
            float(base_retry) if isinstance(base_retry, int | float) else 0.1
        )
        self._upstream_retry_max_delay = (
            float(max_retry) if isinstance(max_retry, int | float) else 2.0
        )
        if self._upstream_retry_base_delay < 0:
            self._upstream_retry_base_delay = 0.0
        if self._upstream_retry_max_delay < self._upstream_retry_base_delay:
            self._upstream_retry_max_delay = self._upstream_retry_base_delay
        streaming_cfg_raw = self._proxy_engine_cfg.get("streaming", {})
        streaming_cfg = streaming_cfg_raw if isinstance(streaming_cfg_raw, dict) else {}
        self._streaming_enabled = bool(streaming_cfg.get("enabled", True))
        self._streaming_buffer_size = int(streaming_cfg.get("buffer_size", 4096))
        if self._streaming_buffer_size <= 0:
            self._streaming_buffer_size = 4096
        self._streaming_max_accumulated_events = int(
            streaming_cfg.get("max_accumulated_events", DEFAULT_STREAMING_MAX_ACCUMULATED_EVENTS)
        )
        if self._streaming_max_accumulated_events <= 0:
            self._streaming_max_accumulated_events = DEFAULT_STREAMING_MAX_ACCUMULATED_EVENTS
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
        reset_cmds_raw = self._loop_cfg.get("openclaw_reset_commands", ["/start", "/new", "/reset"])
        self._openclaw_reset_commands: tuple[str, ...] = tuple(
            cmd.strip().lower() for cmd in reset_cmds_raw if isinstance(cmd, str) and cmd.strip()
        ) or ("/start", "/new", "/reset")
        self._loop_detector = None
        if bool(self._loop_cfg.get("enabled", False)):
            self._loop_detector = LoopDetector(config=self._loop_cfg)
        self._content_loop_detector: ContentLoopDetector | None = None
        content_loop_cfg = self._loop_cfg.get("content_loop")
        content_loop_enabled = False
        if isinstance(content_loop_cfg, dict):
            content_loop_enabled = bool(content_loop_cfg.get("enabled", False))
        elif bool(self._loop_cfg.get("enabled", False)):
            # Backward-compatible default: enable content-loop checks whenever
            # loop_detection is enabled, even if content_loop subsection is absent.
            content_loop_enabled = True
        if content_loop_enabled:
            safe_content_loop_cfg = content_loop_cfg if isinstance(content_loop_cfg, dict) else {}
            self._content_loop_detector = ContentLoopDetector(
                window_seconds=int(
                    safe_content_loop_cfg.get(
                        "window_seconds", self._loop_cfg.get("window_seconds", 300)
                    )
                ),
                max_identical=int(
                    safe_content_loop_cfg.get(
                        "max_identical", self._loop_cfg.get("block_threshold", 5)
                    )
                ),
                cooldown_seconds=int(safe_content_loop_cfg.get("cooldown_seconds", 300)),
                hash_prefix_len=int(safe_content_loop_cfg.get("hash_prefix_len", 256)),
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
                    if not isinstance(seconds, int | float) or not isinstance(
                        max_spend, int | float
                    ):
                        continue
                    if int(seconds) <= 0:
                        continue
                    windows.append(
                        SpendWindow(window_seconds=int(seconds), max_spend=float(max_spend))
                    )
            self._spend_rate_detector = SpendRateDetector(
                windows=windows or None,
                spike_multiplier=float(self._spend_rate_cfg.get("spike_multiplier", 5.0)),
                heartbeat_cost_threshold=float(
                    self._spend_rate_cfg.get("heartbeat_cost_threshold", 0.10)
                ),
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
        self._router = (
            ModelRouter(self._routing_cfg)
            if bool(self._routing_cfg.get("enabled", False))
            else None
        )
        cascade_cfg = self._policy.get("cascade")
        self._cascade_cfg = cascade_cfg if isinstance(cascade_cfg, dict) else {}
        self._cascade_router = (
            CascadeRouter(self._cascade_cfg)
            if bool(self._cascade_cfg.get("enabled", False))
            else None
        )
        secret_cfg = self._policy.get("secret_scanning")
        if not isinstance(secret_cfg, dict):
            secret_cfg = (
                self._policy.get("secrets") if isinstance(self._policy.get("secrets"), dict) else {}
            )
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
        # Plugin pipeline (Checkpoints 1-2): registry holds one self-contained
        # phase (FlowXrayRecordPhase) plus legacy-wrapper plugins for nine more
        # phases. Each wrapper delegates to its `_phase_<name>` method on this
        # proxy; the engine drives execution via `process_one()` from the
        # request handler. Phases not migrated as plugins (the five
        # internal helper phases) continue to be invoked from inside the
        # currently registered phases.
        self._phase_registry = PhaseRegistry()
        self._phase_registry.register(FlowXrayRecordPhase(self._flow_analyzer))
        # Self-contained pipeline phases (no legacy proxy method wrapper).
        self._phase_registry.register(CompressionDecodePhase())
        self._phase_registry.register(CanonicalizePhase())
        self._migrated_phase_names: tuple[str, ...] = (
            "parse",
            "experiment",
            "flow_xray_record",
            "cascade",
            "circuit_breaker",
            "loop_detection",
            "behavioral",
            "adaptive_detection",
            "mast_request",
            "auto_healing",
            "budget",
            "policy",
            "threat_intel",
            "model_router",
            "secrets",
            "context",
            "upstream",
            "post_upstream",
            "send_response",
        )
        for phase_name in self._migrated_phase_names:
            if phase_name == "flow_xray_record":
                continue  # already registered as a self-contained plugin
            legacy_method = getattr(self, f"_phase_{phase_name}")
            self._phase_registry.register(
                make_legacy_phase(phase_name, legacy_method)
            )
        self._phase_registry.reload()
        # State estimator + L7 detector + signed journal — wired into the
        # engine as post-phase hooks. These remain fully functional even when
        # nothing in the proxy reads them yet (their outputs land in
        # processed.params and the recording handle).
        self._sigma_monitor = SigmaMonitor()
        self._blind_spot_detector = BlindSpotDetector()
        sj_cfg = self._policy.get("signed_journal")
        if isinstance(sj_cfg, dict) and bool(sj_cfg.get("enabled", False)):
            hmac_key_raw = sj_cfg.get("hmac_key")
            hmac_key = (
                hmac_key_raw.encode("utf-8") if isinstance(hmac_key_raw, str) else None
            )
            self._signed_journal = SignedJournal(hmac_key=hmac_key)
        else:
            self._signed_journal = None
        self._pipeline_engine = PipelineEngine(
            self._phase_registry,
            sigma_monitor=self._sigma_monitor,
            blind_spot_detector=self._blind_spot_detector,
            signed_journal=self._signed_journal,
        )
        # ThresholdResolver — declarative thresholds via the config DSL.
        # Phases query thresholds at runtime via `self.get_threshold(...)`.
        thresholds_cfg = self._policy.get("thresholds")
        thresholds_lookups = self._policy.get("threshold_lookups") or {}
        if isinstance(thresholds_cfg, dict):
            try:
                self._threshold_resolver = ThresholdResolver.from_config(
                    thresholds_cfg, lookups=thresholds_lookups
                )
            except DslError as e:
                _HTTP_PROXY_LOGGER.warning(
                    "threshold config rejected (%s); falling back to defaults", e
                )
                self._threshold_resolver = ThresholdResolver.from_config(
                    DEFAULT_THRESHOLDS, lookups=thresholds_lookups
                )
        else:
            self._threshold_resolver = ThresholdResolver.from_config(
                DEFAULT_THRESHOLDS, lookups=thresholds_lookups
            )
        self._compliance_engine = components.compliance_engine
        otel_cfg = self._policy.get("otel_export")
        self._otlp_exporter = None
        self._span_emitter = None
        if isinstance(otel_cfg, dict) and bool(otel_cfg.get("enabled", False)):
            export_cfg = OTLPExportConfig(
                enabled=True,
                endpoint=str(otel_cfg.get("endpoint", _DEFAULT_OTLP_HTTP_ENDPOINT)),
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
        self._resume_token = str(self._kill_cfg.get("resume_token", DEFAULT_RESUME_TOKEN))
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
                decay_half_life_seconds=float(
                    session_risk_cfg.get("decay_half_life_seconds", 300.0)
                ),
                max_signals_per_session=int(session_risk_cfg.get("max_signals_per_session", 100)),
                session_ttl_seconds=float(session_risk_cfg.get("session_ttl_seconds", 3600.0)),
                category_diversity_bonus=float(
                    session_risk_cfg.get("category_diversity_bonus", 10.0)
                ),
                enabled=True,
            )
        ars_cfg = self._policy.get("ars")
        self._ars: AgentReliabilityScore | None = None
        if isinstance(ars_cfg, dict) and bool(ars_cfg.get("enabled", False)):
            self._ars = AgentReliabilityScore(
                weights=ars_cfg.get("weights")
                if isinstance(ars_cfg.get("weights"), dict)
                else None,
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
        adaptive_v2_cfg = self._policy.get("adaptive_detection_v2")
        self._adaptive_detection_v2: AdaptiveDetectionV2 | None = None
        self._adaptive_detection_v2_threshold = 0.62
        if isinstance(adaptive_v2_cfg, dict) and bool(adaptive_v2_cfg.get("enabled", False)):
            self._adaptive_detection_v2 = AdaptiveDetectionV2(adaptive_v2_cfg)
            self._adaptive_detection_v2_threshold = float(
                adaptive_v2_cfg.get("confidence_threshold", 0.62)
            )
        context_opt_cfg = self._policy.get("context_optimizer")
        self._context_optimizer: ContextOptimizer | None = None
        if isinstance(context_opt_cfg, dict) and bool(context_opt_cfg.get("enabled", False)):
            self._context_optimizer = ContextOptimizer(context_opt_cfg)
        self._context_router = ContextStrategyRouter()
        prioritizer_cfg = self._policy.get("request_prioritizer")
        self._prioritizer = RequestPrioritizer(
            prioritizer_cfg if isinstance(prioritizer_cfg, dict) else {}
        )
        injection_cfg = self._policy.get("injection_protocol")
        self._injection_protocol: ContextInjectionProtocol | None = None
        if isinstance(injection_cfg, dict):
            self._injection_protocol = ContextInjectionProtocol(injection_cfg)
        context_window_cfg = self._policy.get("context_window_optimizer")
        self._context_window_optimizer: ContextWindowOptimizer | None = None
        if isinstance(context_window_cfg, dict) and bool(context_window_cfg.get("enabled", False)):
            self._context_window_optimizer = ContextWindowOptimizer(context_window_cfg)
        context_budget_cfg = self._policy.get("context_budget")
        self._context_budget: ContextBudget | None = None
        if isinstance(context_budget_cfg, dict) and bool(context_budget_cfg.get("enabled", False)):
            self._context_budget = ContextBudget(context_budget_cfg)
        compression_v2_cfg = self._policy.get("context_compression_v2")
        self._compression_v2: ContextCompressionV2 | None = None
        if isinstance(compression_v2_cfg, dict) and bool(compression_v2_cfg.get("enabled", False)):
            self._compression_v2 = ContextCompressionV2(compression_v2_cfg)
        termination_cfg = self._policy.get("context_termination")
        self._context_termination: ContextTerminationEngine | None = None
        if isinstance(termination_cfg, dict):
            self._context_termination = ContextTerminationEngine(termination_cfg)
        mast_cfg = self._policy.get("mast")
        self._mast: MASTDetectors | None = None
        if isinstance(mast_cfg, dict) and bool(mast_cfg.get("enabled", False)):
            self._mast = MASTDetectors(mast_cfg)
        auto_healing_cfg = self._policy.get("auto_healing")
        self._auto_healer: AutoHealer | None = None
        if isinstance(auto_healing_cfg, dict) and bool(auto_healing_cfg.get("enabled", False)):
            self._auto_healer = AutoHealer(auto_healing_cfg)
        thompson_cfg = self._policy.get("mco")
        self._thompson: MCO | None = None
        if isinstance(thompson_cfg, dict) and bool(thompson_cfg.get("enabled", False)):
            self._thompson = MCO(thompson_cfg)
        bandit_sampler_cfg = self._policy.get("bandit_sampler")
        self._thompson_sampler: BanditSampler | None = None
        if isinstance(bandit_sampler_cfg, dict) and bool(
            bandit_sampler_cfg.get("enabled", False)
        ):
            self._thompson_sampler = BanditSampler(bandit_sampler_cfg)
        self._agent_discovery = AgentDiscovery(self._policy.get("agent_discovery"))
        self._tool_policy: ToolPolicyEngine | None = None
        tools_cfg_raw = self._policy.get("capabilities", {})
        tools_cfg = tools_cfg_raw.get("tools") if isinstance(tools_cfg_raw, dict) else {}
        if isinstance(tools_cfg, dict) and (
            isinstance(tools_cfg.get("rules"), dict) or isinstance(tools_cfg.get("allowed"), list)
        ):
            self._tool_policy = ToolPolicyEngine(tools_cfg)
        self._cost_velocity = CostVelocity()
        self._plugin_registry = self._build_plugin_registry(self._policy)
        cost_opt_cfg = self._policy.get("cost_optimizer")
        self._cost_optimizer: CostOptimizer | None = None
        if isinstance(cost_opt_cfg, dict) and bool(cost_opt_cfg.get("enabled", False)):
            self._cost_optimizer = CostOptimizer(cost_opt_cfg)
        uci_cfg = self._policy.get("content_ranker")
        self._uci_compressor: ContentRanker | None = None
        if isinstance(uci_cfg, dict) and bool(uci_cfg.get("enabled", False)):
            self._uci_compressor = ContentRanker(uci_cfg)
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
        self._dashboard_events: deque[dict[str, Any]] = deque(maxlen=_DASHBOARD_MAX_EVENTS)
        self._dashboard_cost_timeline: deque[dict[str, float]] = deque(
            maxlen=_DASHBOARD_MAX_COST_TIMELINE
        )
        self._dashboard_cost_timeline.append(
            {
                "timestamp": time.time(),
                "cumulative_cost": float(self._cost_tracker.get_daily_total()),
            }
        )

    @property
    def stats(self) -> dict[str, Any]:
        with self._stats_lock:
            payload = dict(self._stats)
        payload["cost_today"] = round(self._cost_tracker.get_daily_total(), 4)
        payload["cost_by_tool"] = self._cost_tracker.get_tool_costs()
        payload["cascade_savings_today_usd"] = round(
            self._cost_tracker.get_cascade_savings_today(), 8
        )
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
                sum(v.get("requests", 0) for v in e.get("variants", [])) for e in exps
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
        if self._adaptive_detection_v2 is not None:
            payload["adaptive_detection_v2"] = self._adaptive_detection_v2.get_layer_stats()
        if self._mast is not None:
            payload["mast"] = self._mast.get_stats()
        if self._context_optimizer is not None:
            payload["context_optimizer"] = self._context_optimizer.get_stats()
        if self._context_budget is not None:
            payload["context_budget"] = self._context_budget.get_stats()
        if self._auto_healer is not None:
            payload["auto_healing"] = self._auto_healer.get_stats()
        if self._thompson is not None:
            payload["mco"] = self._thompson.get_model_stats()
        if self._agent_discovery is not None and self._agent_discovery.enabled:
            payload["agent_discovery"] = self._agent_discovery.get_stats()
        if self._tool_policy is not None:
            payload["tool_policy"] = self._tool_policy.get_tool_stats()
        payload["plugins"] = {
            "count": len(self._plugin_registry.list_plugins()),
            "items": self._plugin_registry.list_plugins(),
        }
        if self._cost_optimizer is not None:
            payload["cost_optimizer"] = {"savings": self._cost_optimizer.get_savings_report()}
        if self._uci_compressor is not None:
            payload["content_ranker"] = self._uci_compressor.get_stats()
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

    @staticmethod
    def _policy_hash(policy: dict[str, Any]) -> str:
        encoded = json.dumps(
            policy, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()[:12]

    def reload_policy(self, new_policy: dict[str, Any]) -> bool:
        """Atomically replace active policy if valid."""
        if not isinstance(new_policy, dict):
            return False
        validation_errors = validate_policy(new_policy)
        if validation_errors:
            return False
        candidate = dict(new_policy)
        with self._stats_lock:
            self._policy = candidate
        _HTTP_PROXY_LOGGER.info("Policy reloaded: %s", self._policy_hash(candidate))
        return True

    def get_threshold(
        self,
        name: str,
        *,
        tier: str | None = None,
        chain_length: int = 0,
        task_type: str | None = None,
        request_size: int = 0,
        agent_class: str | None = None,
        reliability_profile: str | None = None,
    ) -> object:
        """Query the declarative threshold table.

        Phases call this to get the live value for a threshold given the
        current request shape. Defaults to the policy's `thresholds` table
        when one is provided, else to DEFAULT_THRESHOLDS.
        """
        ctx = _DslResolverContext(
            tier=tier,
            chain_length=int(chain_length),
            task_type=task_type,
            request_size=int(request_size),
            agent_class=agent_class,
            reliability_profile=reliability_profile,
        )
        return self._threshold_resolver.resolve(name, ctx)

    def _activate_kill_switch(self, reason: str) -> None:
        self._killed = True
        self._kill_reason = reason
        self._kill_time = datetime.now(timezone.utc).isoformat()
        self._inc("kill_switch_activations")

    def _read_json_body(self, handler: BaseHTTPRequestHandler) -> dict[str, Any] | None:
        setattr(handler, "_orchesis_body_too_large", False)
        try:
            length = int(handler.headers.get("Content-Length", "0") or "0")
        except Exception:
            return None
        if self._reject_if_body_too_large(handler, length):
            setattr(handler, "_orchesis_body_too_large", True)
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

    def _reject_if_body_too_large(
        self, handler: BaseHTTPRequestHandler, content_length: int
    ) -> bool:
        if int(content_length) <= int(self._max_body_size_bytes):
            return False
        self._send_json(
            handler,
            413,
            {
                "error": {
                    "type": "request_entity_too_large",
                    "message": "Request body exceeds configured max_body_size_bytes",
                    "max_body_size_bytes": int(self._max_body_size_bytes),
                }
            },
        )
        return True

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
        return _resolve_session_id(headers)

    @staticmethod
    def _normalize_header_map(headers: Any) -> dict[str, str]:
        normalized: dict[str, str] = {}
        if headers is None:
            return normalized
        try:
            if isinstance(headers, dict):
                iterator = headers.items()
            elif hasattr(headers, "items"):
                iterator = headers.items()
            elif hasattr(headers, "keys"):
                iterator = ((key, headers.get(key, "")) for key in headers.keys())
            else:
                iterator = []
            for key, value in iterator:
                lowered = str(key).strip().lower()
                normalized[lowered] = str(value) if value is not None else ""
        except Exception:
            return {}
        return normalized

    def _detect_agent_framework(self, headers: Any, body: dict[str, Any] | None = None) -> str:
        """Detect agent framework from request headers."""
        h = self._normalize_header_map(headers)
        ua = str(h.get("user-agent", "")).lower()
        if "openclaw" in ua or "openhands" in ua:
            return "openclaw"
        framework = str(h.get("x-orchesis-framework", "")).strip().lower()
        if framework:
            return framework
        if h.get("x-openclaw-session-id") or h.get("x-openclaw-session"):
            return "openclaw"
        if isinstance(body, dict):
            messages = body.get("messages", [])
            if isinstance(messages, list):
                for msg in messages[-3:]:
                    if not isinstance(msg, dict):
                        continue
                    content = msg.get("content", "")
                    if isinstance(content, str):
                        lowered = content.lower()
                        if any(
                            marker in lowered
                            for marker in (
                                "openclaw",
                                "openhands",
                                "/workspace/",
                                "cwd:",
                                "agents.md",
                            )
                        ):
                            return "openclaw"
            tools = body.get("tools", [])
            if isinstance(tools, list):
                tool_names: list[str] = []
                for tool in tools:
                    if not isinstance(tool, dict):
                        continue
                    direct_name = tool.get("name")
                    if isinstance(direct_name, str) and direct_name.strip():
                        tool_names.append(direct_name.strip())
                    fn = tool.get("function")
                    if isinstance(fn, dict):
                        fn_name = fn.get("name")
                        if isinstance(fn_name, str) and fn_name.strip():
                            tool_names.append(fn_name.strip())
                openclaw_tools = {
                    "read_file",
                    "write_file",
                    "execute_bash",
                    "browser_action",
                    "run_ipython_cell",
                }
                if len({name.lower() for name in tool_names}.intersection(openclaw_tools)) >= 2:
                    return "openclaw"
        return "unknown"

    def _apply_framework_threat_overrides(
        self,
        matches: list[Any],
        *,
        framework: str,
    ) -> list[Any]:
        if framework != "openclaw" or not matches:
            return matches
        threat_cfg = self._openclaw_safe_policy.get("threat_intel", {})
        severity_actions = {}
        default_action = "warn"
        if isinstance(threat_cfg, dict):
            severity_actions = threat_cfg.get("severity_actions", {})
            default_action = str(threat_cfg.get("default_action", "warn")).strip().lower() or "warn"

        filtered: list[Any] = []
        for match in matches:
            threat_id = str(getattr(match, "threat_id", "")).strip().upper()
            if threat_id in self._openclaw_safe_skip:
                continue
            sig = (
                self._threat_matcher.get_threat(threat_id)
                if self._threat_matcher is not None
                else None
            )
            excluded = getattr(sig, "frameworks_exclude", ()) if sig is not None else ()
            excluded_lc = {str(item).strip().lower() for item in excluded}
            if "openclaw" in excluded_lc:
                continue

            severity = str(getattr(match, "severity", "medium")).strip().lower()
            preferred = (
                (
                    str(severity_actions.get(severity, default_action))
                    if isinstance(severity_actions, dict)
                    else default_action
                )
                .strip()
                .lower()
            )
            if preferred == "block":
                preferred = "warn"
            if str(getattr(match, "action", "")).lower() == "block":
                setattr(match, "action", preferred or "warn")
            filtered.append(match)
        return filtered

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
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "Content-Length": str(len(payload)),
        }
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
    def _copy_upstream_headers(
        handler: BaseHTTPRequestHandler, headers: dict[str, str], body_len: int
    ) -> None:
        skip = {"transfer-encoding", "connection", "content-length"}
        for key, value in headers.items():
            if str(key).lower() in skip:
                continue
            handler.send_header(str(key), str(value))
        handler.send_header("Content-Length", str(body_len))

    def _get_upstream(self, provider: str, headers: Any) -> str:
        custom = headers.get("X-Orchesis-Upstream") or headers.get("x-orchesis-upstream")
        if isinstance(custom, str) and custom.strip():
            candidate = custom.strip()
            if self._is_safe_upstream_override(candidate):
                return candidate.rstrip("/")
            _HTTP_PROXY_LOGGER.warning("SSRF blocked: %s", candidate)
        return self._config.upstream.get(
            provider, self._config.upstream.get("openai", "https://api.openai.com")
        )

    def _is_safe_upstream_override(self, url: str) -> bool:
        parsed = urlsplit(str(url).strip())
        if parsed.scheme not in {"http", "https"}:
            return False
        host = parsed.hostname
        if not isinstance(host, str) or not host.strip():
            return False
        if self._ssrf_allow_private:
            return True
        if host.strip().lower() in _LOCALHOST_HOSTNAMES:
            return False
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            resolved = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except Exception:
            return False
        if not resolved:
            return False
        for entry in resolved:
            sockaddr = entry[4]
            ip_raw = sockaddr[0] if isinstance(sockaddr, tuple) and sockaddr else ""
            try:
                ip_obj = ipaddress.ip_address(str(ip_raw))
            except ValueError:
                return False
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                return False
        return True

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
            elif raw_err is True and isinstance(payload, dict):
                maybe_code = payload.get("code", "")
                if isinstance(maybe_code, str):
                    error_type = maybe_code
            elif isinstance(raw_err, str):
                error_type = raw_err
            setattr(handler, "_orchesis_last_error_type", str(error_type))
        except Exception as exc:
            _HTTP_PROXY_LOGGER.debug("Suppressed: %s", exc)
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

    @staticmethod
    def _smart_error_payload(error: Any, error_type: str) -> dict[str, Any]:
        return {
            "error": {
                "type": str(error_type or "policy_violation"),
                "message": str(getattr(error, "reason", "Request blocked")),
                "suggestion": str(getattr(error, "suggestion", "")),
                "severity": str(getattr(error, "severity", "medium")),
                "detector": str(getattr(error, "detector", "policy")),
                "code": str(getattr(error, "code", "ORCH-UNKNOWN-001")),
            }
        }
