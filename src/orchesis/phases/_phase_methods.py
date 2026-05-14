"""Phase method bodies + their per-phase helpers, extracted from proxy.py.

Mixed into `LLMHTTPProxy` via PhaseMethodsMixin. Methods operate on the
legacy `_RequestContext` and reference `self.<attr>` for shared state.
Annotations are deferred (from __future__ import annotations) so 
`_RequestContext` and other proxy-internal types are referenced as
strings at module-load time — runtime resolution happens inside method
bodies only where Python actually needs the value.
"""

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

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from orchesis.proxy import _RequestContext  # noqa: F401


class PhaseMethodsMixin:
    """Phase implementations + helpers shared by LLMHTTPProxy."""

    def _phase_parse(self, ctx: _RequestContext) -> bool:
        try:
            length = int(ctx.handler.headers.get("Content-Length", "0") or "0")
        except Exception:
            self._send_json(ctx.handler, 400, {"error": "Invalid Content-Length header"})
            return False
        if self._reject_if_body_too_large(ctx.handler, length):
            return False
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
        parsed_session_id = _resolve_session_id(ctx.handler.headers)
        if isinstance(parsed_session_id, str):
            ctx.proc_result["session_id"] = parsed_session_id.strip() or "default"
            if not ctx.session_id:
                ctx.session_id = parsed_session_id.strip() or "default"
        return True

    def _compute_fast_path_skip_phases(self, ctx: _RequestContext) -> None:
        skip_phases: set[str] = set()
        if self._fast_path is not None:
            headers_dict = self._normalize_header_map(ctx.handler.headers)
            fp_decision = self._fast_path.evaluate(headers=headers_dict, body=ctx.body)
            if bool(getattr(fp_decision, "fast_path", False)):
                skip_phases = set(getattr(fp_decision, "skip_phases", []) or [])
                skip_phases -= set(self._fast_path_mandatory_phases)
                _HTTP_PROXY_LOGGER.debug(
                    "Fast path enabled: skipping %d phases (framework=%s trust=%s)",
                    len(skip_phases),
                    str(getattr(fp_decision, "framework", "")),
                    str(getattr(getattr(fp_decision, "trust_level", ""), "value", "")),
                )
            ctx.proc_result["fast_path"] = bool(getattr(fp_decision, "fast_path", False))
            ctx.proc_result["fast_path_framework"] = str(getattr(fp_decision, "framework", ""))
            ctx.proc_result["fast_path_trust"] = str(
                getattr(getattr(fp_decision, "trust_level", ""), "value", "")
            )
        ctx.skip_phases = skip_phases
        ctx.proc_result["skip_phases"] = sorted(skip_phases)

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
            except (TypeError, ValueError) as exc:
                _HTTP_PROXY_LOGGER.debug("Suppressed: %s", exc)
                current = 0.0
            adjusted = max(0.0, min(1.0, current * 0.5))
            try:
                match.confidence = adjusted
            except Exception as exc:
                _HTTP_PROXY_LOGGER.debug("Suppressed: %s", exc)
            try:
                action = str(getattr(match, "action", "")).lower()
                if action == "block" and adjusted < 0.7:
                    match.action = "warn"
            except Exception as exc:
                _HTTP_PROXY_LOGGER.debug("Suppressed: %s", exc)
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
            ctx.handler.send_header(
                "X-Orchesis-Daily-Total", str(round(self._cost_tracker.get_daily_total(), 4))
            )
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
        # Checkpoint 2: the request handler dispatches this phase via
        # `_run_migrated_phase`. This method remains as a single-phase
        # entry point usable from tests and any non-handler code paths
        # that want to invoke the migrated phase directly. It is a thin
        # delegate to `_run_migrated_phase` to keep one source of truth
        # for the legacy→pipeline bridge.
        if self._flow_analyzer is None:
            return True
        return self._run_migrated_phase(ctx, "flow_xray_record")

    def _build_pipeline_ctx(self, legacy: "_RequestContext") -> _PipelineRequestContext:
        """Bridge a legacy proxy request context into a plugin RequestContext.

        Used by the migrated flow_xray_record phase. Subsequent checkpoints
        progressively widen the bridge as more phases migrate.
        """
        body = legacy.body if isinstance(legacy.body, dict) else {}
        messages_raw = body.get("messages")
        messages: list = messages_raw if isinstance(messages_raw, list) else []
        tools_raw = body.get("tools")
        tools_list: list = []
        if isinstance(tools_raw, list):
            for item in tools_raw:
                if isinstance(item, (dict, str)):
                    tools_list.append(item)
        # Compression hint + headers map.
        compression_format: str | None = None
        header_map: dict[str, str] = {}
        handler = getattr(legacy, "handler", None)
        try:
            if handler is not None and handler.headers is not None:
                for k, v in handler.headers.items():
                    header_map[str(k)] = str(v)
                enc = handler.headers.get("Content-Encoding") or handler.headers.get("content-encoding")
                if isinstance(enc, str) and enc.strip():
                    compression_format = enc.strip()
        except Exception:
            pass
        ident = _PipelineIdentity(
            request_id=legacy.request_id or "",
            session_id=legacy.session_id or "default",
            agent_id=legacy.behavior_agent_id or "default",
            customer_id=legacy.behavior_agent_id or "default",
            tier="lite",
        )
        # Reconstruct raw_body from the parsed body for canonicalization. The
        # legacy parse phase already consumed the request stream, so we can't
        # see the original bytes — best-effort: serialize the parsed body.
        try:
            raw_body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        except Exception:
            raw_body = b""
        inp = _PipelineInputSnapshot(
            raw_body=raw_body,
            original_messages=tuple(messages),
            original_tools=tuple(tools_list),
            requested_model=str(body.get("model", legacy.original_model or "")),
            requested_params={},
            provider_hint=legacy.provider or None,
            headers=header_map,
            compression_format=compression_format,
        )
        return _PipelineRequestContext(
            id=ident,
            input=inp,
            processed=_PipelineProcessed(),
            tracking=_PipelineTracking(),
            recording=_PipelineRecordingHandle(),
        )

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
                self._alert_manager.alert(
                    AlertEvent(
                        severity=AlertSeverity.WARNING,
                        event_type="circuit_open",
                        title="Circuit breaker open",
                        details=self._circuit_breaker.fallback_message,
                        session_id=ctx.session_id,
                    )
                )
            return False
        ctx.circuit_state_header = self._circuit_breaker.get_state().lower().replace("_", "-")
        return True

    def _phase_loop_detection(self, ctx: _RequestContext) -> bool:
        openclaw_reset_detected = self._is_openclaw_reset_request(ctx.body)
        if self._loop_detector is None or openclaw_reset_detected:
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
                ctx.handler.send_header(
                    "X-Orchesis-Loop-Blocked",
                    loop_decision.reason or "Fuzzy loop threshold exceeded",
                )
                ctx.handler.send_header(
                    "X-Orchesis-Loop-Saved", f"${loop_decision.estimated_cost_saved:.2f}"
                )
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
        if self._content_loop_detector is not None and "/v1/chat/completions" in str(
            ctx.handler.path
        ):
            last_user_message = self._extract_last_user_message(ctx.body)
            if isinstance(last_user_message, str) and len(last_user_message) > 0:
                session_scope = self._resolve_loop_session_scope(ctx)
                if openclaw_reset_detected:
                    self._clear_content_loop_session_history(session_scope)
                    ctx.content_loop_count = 0
                    _HTTP_PROXY_LOGGER.debug(
                        "OpenClaw reset detected, clearing loop history for session %s",
                        session_scope,
                    )
                    return True
                result = self._content_loop_detector.check(last_user_message, session_scope)
                ctx.content_loop_count = int(result.get("count", 0))
                if result.get("action") == "block":
                    self._loop_trigger_hits += 1
                    self._inc("blocked")
                    retry_after = int(result.get("retry_after", 300))
                    _HTTP_PROXY_LOGGER.warning(
                        "Loop detected: %s identical requests",
                        int(result.get("count", 0)),
                    )
                    self._cost_tracker.record_loop_prevented_savings(
                        self._estimated_avg_request_cost_usd
                    )
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
                        self._alert_manager.alert(
                            AlertEvent(
                                severity=AlertSeverity.CRITICAL,
                                event_type="loop_detected",
                                title="Content loop blocked",
                                details=f"{result.get('count', 0)} identical messages in {result.get('window_seconds', 0)}s",
                                session_id=str(session_scope),
                            )
                        )
                    return False
                content_loop_cfg = self._loop_cfg.get("content_loop")
                content_warn_threshold = 3
                if isinstance(content_loop_cfg, dict):
                    content_warn_threshold = int(
                        content_loop_cfg.get(
                            "warn_threshold", self._loop_cfg.get("warn_threshold", 3)
                        )
                    )
                else:
                    content_warn_threshold = int(self._loop_cfg.get("warn_threshold", 3))
                if int(result.get("count", 0)) >= max(1, content_warn_threshold):
                    ctx.loop_warning_header = f"count={int(result.get('count', 0))}"
                    ctx.was_loop_detected = True
        return True

    def _is_openclaw_reset_request(self, body: dict[str, Any]) -> bool:
        if not isinstance(body, dict):
            return False
        messages = body.get("messages", [])
        if not isinstance(messages, list) or len(messages) == 0:
            return False
        if len(messages) > 2:
            return False
        reset_commands = {
            cmd.lower() for cmd in self._openclaw_reset_commands if isinstance(cmd, str)
        }
        last_user = self._extract_last_user_message(body) or ""
        lowered_user = last_user.lower()
        has_reset_command = any(
            (f" {cmd} " in f" {lowered_user} ")
            or lowered_user.startswith(cmd + " ")
            or lowered_user == cmd
            for cmd in reset_commands
        )
        init_markers = (
            "session initialization",
            "session init",
            "initialize session",
            "initializing session",
            "new session",
            "starting session",
        )
        has_session_init_system = False
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            if str(msg.get("role", "")).strip().lower() != "system":
                continue
            content = msg.get("content", "")
            if isinstance(content, str):
                lowered = content.lower()
                if any(marker in lowered for marker in init_markers):
                    has_session_init_system = True
                    break
        return bool(has_reset_command or has_session_init_system)

    def _clear_content_loop_session_history(self, session_scope: str) -> None:
        detector = self._content_loop_detector
        if detector is None:
            return
        safe_scope = str(session_scope or "default")
        prefix = f"{safe_scope}:"
        with detector._lock:  # type: ignore[attr-defined]
            for table_name in ("_history", "_cooldowns", "_cooldown_level"):
                table = getattr(detector, table_name, None)
                if not isinstance(table, dict):
                    continue
                stale_keys = [key for key in table if str(key).startswith(prefix)]
                for key in stale_keys:
                    table.pop(key, None)
            last_hash = getattr(detector, "_last_hash_by_session", None)
            if isinstance(last_hash, dict):
                last_hash.pop(safe_scope, None)

    @staticmethod
    def _extract_last_user_message(body: dict[str, Any]) -> str | None:
        messages = body.get("messages", [])
        if not isinstance(messages, list):
            return None
        for msg in reversed(messages):
            if not isinstance(msg, dict):
                continue
            if str(msg.get("role", "")).strip().lower() != "user":
                continue
            content = msg.get("content", "")
            if isinstance(content, str):
                trimmed = content.strip()
                return trimmed or None
        return None

    @staticmethod
    def _resolve_loop_session_scope(ctx: _RequestContext) -> str:
        headers = ctx.handler.headers
        stable_session = _resolve_session_id(headers)
        if stable_session == "default" and isinstance(ctx.session_id, str):
            candidate = ctx.session_id.strip()
            if candidate and candidate != "unknown":
                stable_session = candidate
        if isinstance(stable_session, str) and stable_session.strip():
            return stable_session.strip()
        stable_agent = (
            headers.get("x-orchesis-agent")
            or headers.get("x-agent-id")
            or (ctx.behavior_agent_id if isinstance(ctx.behavior_agent_id, str) else "")
        )
        if isinstance(stable_agent, str) and stable_agent.strip():
            return f"agent:{stable_agent.strip()}"
        return "default"

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
        behavior_decision = self._behavioral_detector.check_request(
            ctx.behavior_agent_id, behavior_data
        )
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
            ctx.behavior_dims_header = ",".join(
                sorted({item.dimension for item in behavior_decision.anomalies})
            )
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
                smart = ErrorResponseBuilder.build(
                    "budget_exceeded",
                    limit=f"{float(self._budget_cfg.get('daily', 0.0) or 0.0):.2f}",
                    current=f"{float(budget_status.get('daily_spent', 0.0) or 0.0):.2f}",
                )
                self._send_json(
                    ctx.handler,
                    429,
                    self._smart_error_payload(smart, "budget_exceeded"),
                    extra_headers={"X-Orchesis-Error": ErrorResponseBuilder.to_header(smart)},
                )
                if self._alert_manager:
                    self._alert_manager.alert(
                        AlertEvent(
                            severity=AlertSeverity.CRITICAL,
                            event_type="budget_exceeded",
                            title="Budget exceeded",
                            details=f"Daily budget exceeded. Spent ${budget_status.get('daily_spent', 0):.4f}",
                            session_id=ctx.session_id,
                        )
                    )
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
                    self._alert_manager.alert(
                        AlertEvent(
                            severity=AlertSeverity.WARNING,
                            event_type="spend_rate_exceeded",
                            title="Spend rate exceeded",
                            details=f"Spending too fast: ${rate_result.window_spend:.2f} in {rate_result.reason}",
                            session_id=ctx.session_id,
                        )
                    )
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
            "tokens": int(
                ctx.body.get("max_completion_tokens", ctx.body.get("max_tokens", 0)) or 0
            ),
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
        if (
            self._community is not None
            and detection.anomaly_score >= self._community.min_anomaly_score
        ):
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
                request_meta={
                    "model": str(ctx.body.get("model", "")),
                    "agent_type": str(agent_id or "unknown"),
                },
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
                "token_budget": {
                    "max_tokens": int(
                        ctx.body.get("max_completion_tokens", ctx.body.get("max_tokens", 0)) or 0
                    )
                },
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
                ctx.session_headers[f"X-Orchesis-MAST-{finding.failure_mode}"] = (
                    finding.description[:180]
                )
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
            smart = ErrorResponseBuilder.build(
                "rate_limited",
                agent=agent_id,
                current=1,
                max=1,
                window="auto-healer window",
                retry_after=60,
            )
            self._send_json(
                ctx.handler,
                429,
                self._smart_error_payload(smart, "agent_rate_limited"),
                extra_headers={"X-Orchesis-Error": ErrorResponseBuilder.to_header(smart)},
            )
            return False
        detection = ctx.adaptive_detection_result
        mast_findings = ctx.mast_request_findings
        has_detection_issue = bool(
            detection is not None and bool(getattr(detection, "is_anomalous", False))
        )
        has_mast_issue = bool(mast_findings)
        if not has_detection_issue and not has_mast_issue:
            return True
        pre_score = float(
            getattr(detection, "anomaly_score", 0.0) if detection is not None else 0.0
        )
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
                    name = getattr(tc, "name", None) or (
                        tc.get("name") if isinstance(tc, dict) else ""
                    )
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
            framework = self._detect_agent_framework(
                headers_dict, ctx.body if isinstance(ctx.body, dict) else None
            )
            ctx.proc_result["agent_framework"] = framework
            matches = self._threat_matcher.scan_request(
                messages=messages,
                tools=tools,
                tool_calls=tool_calls,
                model=model,
                headers=headers_dict or None,
            )
            self._apply_threat_context_adjustments(messages, matches)
            matches = self._apply_framework_threat_overrides(matches, framework=framework)
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
        if self._adaptive_detection_v2 is not None:
            messages = ctx.body.get("messages", [])
            if not isinstance(messages, list):
                messages = []
            message_text: list[str] = []
            for item in messages:
                if isinstance(item, dict):
                    value = item.get("content", "")
                    if isinstance(value, str):
                        message_text.append(value)
            tool_names = [
                str(t.get("name", ""))
                for t in ctx.body.get("tools", [])
                if isinstance(t, dict) and t.get("name")
            ]
            parsed = ctx.parsed_req
            tool_calls: list[dict[str, Any]] = []
            if parsed and hasattr(parsed, "tool_calls"):
                for tc in parsed.tool_calls:
                    if isinstance(tc, dict):
                        tool_calls.append(
                            {
                                "name": str(tc.get("name", "")),
                                "input": tc.get("input", tc.get("params", {})),
                            }
                        )
                    else:
                        tool_calls.append(
                            {
                                "name": str(getattr(tc, "name", "") or ""),
                                "input": getattr(tc, "params", None) or getattr(tc, "input", {}),
                            }
                        )
            request_text = "\n".join(message_text + tool_names)
            detection_v2 = self._adaptive_detection_v2.detect(
                request_text,
                context={
                    "agent_id": str(ctx.behavior_agent_id or "unknown"),
                    "messages": messages,
                    "tools": tool_names,
                    "tool_calls": tool_calls,
                    "model": str(ctx.body.get("model", "")),
                    "session_risk_score": float(
                        ctx.proc_result.get("session_risk_score", 0.0) or 0.0
                    ),
                    "session_risk_level": str(ctx.proc_result.get("session_risk_level", "observe")),
                },
            )
            ctx.proc_result["adaptive_v2_layers_hit"] = list(detection_v2.layers_hit)
            ctx.proc_result["adaptive_v2_confidence"] = float(detection_v2.confidence)
            ctx.proc_result["adaptive_v2_triggered"] = bool(detection_v2.triggered)
            if (
                detection_v2.triggered
                and detection_v2.confidence >= self._adaptive_detection_v2_threshold
            ):
                existing = ctx.proc_result.get("threat_reasons")
                reasons = list(existing) if isinstance(existing, list) else []
                reasons.extend([f"adaptive_v2:{reason}" for reason in detection_v2.reasons])
                ctx.proc_result["threat_reasons"] = reasons
                ctx.session_headers["X-Orchesis-AdaptiveV2-Confidence"] = (
                    f"{detection_v2.confidence:.2f}"
                )
                ctx.session_headers["X-Orchesis-AdaptiveV2-Layers"] = ",".join(
                    detection_v2.layers_hit
                )
            _HTTP_PROXY_LOGGER.info(
                "adaptive_detection_v2 layers=%s confidence=%.3f",
                ",".join(detection_v2.layers_hit) if detection_v2.layers_hit else "-",
                float(detection_v2.confidence),
            )
        for match in matches:
            action = str(getattr(match, "action", "")).strip().lower()
            if action in {"block", "deny"}:
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
                    self._alert_manager.alert(
                        AlertEvent(
                            severity=AlertSeverity.CRITICAL,
                            event_type="threat_blocked",
                            title="Threat blocked",
                            details=f"{match.name} ({match.threat_id})",
                            session_id=ctx.session_id,
                        )
                    )
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
            ctx.handler.headers.get("X-Orchesis-Approval-Id") or ctx.body.get("approval_id") or ""
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
                    smart = ErrorResponseBuilder.build(
                        "tool_blocked",
                        tool=call.name,
                        agent=str(ctx.behavior_agent_id or "default"),
                        allowed="configured policy allow-list",
                    )
                    self._send_json(
                        ctx.handler,
                        403,
                        self._smart_error_payload(smart, "tool_policy_block"),
                        extra_headers={"X-Orchesis-Error": ErrorResponseBuilder.to_header(smart)},
                    )
                    return False
                if tp_decision.action == "approve":
                    smart = ErrorResponseBuilder.build(
                        "approval_required",
                        tool=call.name,
                        agent=str(ctx.behavior_agent_id or "default"),
                        approval_id=tp_decision.approval_id,
                    )
                    self._send_json(
                        ctx.handler,
                        202,
                        {
                            "status": "pending_approval",
                            "approval_id": tp_decision.approval_id,
                            "tool_name": call.name,
                            "reason": smart.reason,
                            "suggestion": smart.suggestion,
                            "code": smart.code,
                        },
                        extra_headers={"X-Orchesis-Error": ErrorResponseBuilder.to_header(smart)},
                    )
                    return False
                if tp_decision.action == "warn":
                    ctx.session_headers["X-Orchesis-Tool-Warn"] = (
                        f"{call.name}:{tp_decision.reason[:120]}"
                    )
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
                smart = ErrorResponseBuilder.build(
                    "tool_blocked",
                    tool=call.name,
                    agent=str(ctx.behavior_agent_id or "default"),
                    allowed="configured policy allow-list",
                )
                if reason:
                    smart.reason = f"{smart.reason}. {reason}"
                self._send_json(
                    ctx.handler,
                    403,
                    self._smart_error_payload(smart, "policy_violation"),
                    extra_headers={"X-Orchesis-Error": ErrorResponseBuilder.to_header(smart)},
                )
                return False
        return True

    def _get_available_models(self) -> list[str]:
        """Return list of available models from policy config."""
        models = self._policy.get("models", {})
        if isinstance(models, list):
            return [str(item) for item in models if isinstance(item, str)]
        if isinstance(models, dict):
            return [str(item) for item in models.keys()]
        return list(self._thompson_sampler.ARMS.keys()) if self._thompson_sampler else []

    def _phase_model_router(self, ctx: _RequestContext) -> bool:
        if self._spend_rate_detector is not None and self._spend_rate_detector.is_heartbeat_request(
            ctx.body
        ):
            ctx.heartbeat_detected = True
            ctx.proc_result["cascade_tier"] = "cheapest"
            heartbeat_models = self._routing_cfg.get("heartbeat_models", {})
            provider = ctx.parsed_req.provider or "openai"
            cheapest = (
                heartbeat_models.get(provider) or heartbeat_models.get("default") or "gpt-4o-mini"
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
            if (
                isinstance(routed_model, str)
                and routed_model
                and routed_model != ctx.parsed_req.model
            ):
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
            ctx.proc_result["mco"] = {
                "category": category,
                "selected_model": decision.selected_model,
                "reason": decision.reason,
                "confidence": float(decision.confidence),
                "sampled_scores": dict(decision.sampled_scores),
            }
        if self._thompson_sampler is not None:
            messages = ctx.body.get("messages")
            tools_used: list[str] = []
            tools = ctx.body.get("tools")
            if isinstance(tools, list):
                for item in tools:
                    if not isinstance(item, dict):
                        continue
                    fn = item.get("function")
                    if isinstance(fn, dict) and isinstance(fn.get("name"), str):
                        tools_used.append(str(fn.get("name")))
                    elif isinstance(item.get("name"), str):
                        tools_used.append(str(item.get("name")))
            task_type = (
                self._context_router.classify(messages, tools_used)
                if isinstance(messages, list)
                else "unknown"
            )
            available_models = self._get_available_models()
            selected_model = self._thompson_sampler.sample(task_type, available_models)
            if isinstance(selected_model, str) and selected_model:
                ctx.body["model"] = selected_model
                ctx.session_headers["X-Orchesis-TS-Model"] = selected_model
                ctx.proc_result["bandit_sampler"] = {
                    "task_type": task_type,
                    "selected_model": selected_model,
                    "available_models": available_models,
                }
        # ProviderAdapter dispatch: tag the chosen model with its adapter so
        # later phases (upstream/post_upstream) can use the adapter's wire
        # format helpers. Unknown models leave the tag empty — the legacy
        # path still runs unchanged.
        final_model = ctx.body.get("model") if isinstance(ctx.body, dict) else None
        if isinstance(final_model, str) and final_model:
            try:
                adapter = _adapter_for_model(final_model)
            except Exception:
                adapter = None
            if adapter is not None:
                ctx.proc_result["provider_adapter"] = adapter.name
                ctx.session_headers["X-Orchesis-Provider-Adapter"] = adapter.name
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
        assigned_priority = self._prioritizer.assign_priority(
            ctx.body if isinstance(ctx.body, dict) else {}
        )
        ctx.proc_result["priority"] = assigned_priority
        ctx.session_headers["X-Orchesis-Priority"] = assigned_priority
        messages = ctx.body.get("messages")
        if self._injection_protocol is not None and isinstance(messages, list):
            stats_obj = self.stats
            request_count = (
                int(getattr(stats_obj, "requests_total", 0) or 0)
                if not isinstance(stats_obj, dict)
                else int(stats_obj.get("requests_total", 0) or 0)
            )
            session_state = {
                "session_id": str(ctx.session_id or "default"),
                "request_count": request_count,
            }
            metrics = {
                "quality_score": float(ctx.proc_result.get("quality_score", 1.0) or 1.0),
                "budget_level": str(ctx.proc_result.get("context_budget_level", "normal")),
            }
            decision = self._injection_protocol.should_inject(session_state, metrics)
            if bool(decision.get("inject", False)):
                available_context = ctx.body.get("orchesis_context")
                context_pool = (
                    available_context
                    if isinstance(available_context, list)
                    else [
                        item
                        for item in messages
                        if isinstance(item, dict)
                        and str(item.get("role", "")).lower() in {"assistant", "system"}
                    ]
                )
                selected_content = self._injection_protocol.select_content(
                    context_pool,
                    int(self._injection_protocol.max_injection_tokens),
                )
                result = self._injection_protocol.inject(messages, selected_content)
                merged_messages = result.get("messages")
                if isinstance(merged_messages, list):
                    ctx.body["messages"] = validate_tool_chain(merged_messages)
                    messages = ctx.body.get("messages")
                ctx.proc_result["injection_protocol"] = {
                    "inject": bool(decision.get("inject", False)),
                    "reason": str(decision.get("reason", "")),
                    "urgency": str(decision.get("urgency", "low")),
                    "injected_count": int(result.get("injected_count", 0) or 0),
                    "tokens_injected": int(result.get("tokens_injected", 0) or 0),
                    "injection_id": str(result.get("injection_id", "")),
                }
        if (
            self._context_termination is not None
            and self._context_termination.enabled
            and isinstance(messages, list)
            and messages
        ):
            findings = self._context_termination.scan(messages)
            if findings:
                result = self._context_termination.remove(messages, findings)
                cleaned = result.get("messages")
                if isinstance(cleaned, list):
                    ctx.body["messages"] = validate_tool_chain(cleaned)
                    messages = ctx.body.get("messages")
                ctx.proc_result["context_termination"] = {
                    "removed_count": int(result.get("removed_count", 0) or 0),
                    "safety_checks_passed": bool(result.get("safety_checks_passed", False)),
                    "findings_count": len(findings),
                }
        if isinstance(messages, list) and messages:
            tools_used: list[str] = []
            tools = ctx.body.get("tools")
            if isinstance(tools, list):
                for item in tools:
                    if not isinstance(item, dict):
                        continue
                    fn = item.get("function")
                    if isinstance(fn, dict) and isinstance(fn.get("name"), str):
                        tools_used.append(str(fn.get("name")))
                    elif isinstance(item.get("name"), str):
                        tools_used.append(str(item.get("name")))
            task_type = self._context_router.classify(messages=messages, tools_used=tools_used)
            strategy = self._context_router.get_strategy(task_type)
            max_tokens = int(
                ctx.body.get("max_completion_tokens", ctx.body.get("max_tokens", 0)) or 0
            )
            routed_messages = self._context_router.apply_strategy(messages, strategy, max_tokens)
            ctx.body["messages"] = validate_tool_chain(routed_messages)
            ctx.proc_result["context_task_type"] = task_type
            ctx.proc_result["context_strategy"] = strategy
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
                ctx.proc_result["context_optimizations_applied"] = list(
                    opt_result.optimizations_applied
                )
        if self._cost_optimizer is not None:
            messages = ctx.body.get("messages")
            if isinstance(messages, list):
                optimized_messages, opt_stats = self._cost_optimizer.optimize(messages)
                ctx.body["messages"] = validate_tool_chain(optimized_messages)
                ctx.proc_result["cost_optimization"] = opt_stats
        if self._uci_compressor is not None:
            messages = ctx.body.get("messages")
            if isinstance(messages, list) and messages:
                budget_tokens = int(
                    ctx.body.get("max_completion_tokens", ctx.body.get("max_tokens", 0)) or 0
                )
                if budget_tokens <= 0:
                    budget_tokens = (
                        max(1, self._context_budget.estimate_tokens(messages))
                        if self._context_budget
                        else max(1, len(messages) * 80)
                    )
                result = self._uci_compressor.compress(messages, budget_tokens)
                compressed_messages = result.get("messages")
                if isinstance(compressed_messages, list):
                    ctx.body["messages"] = validate_tool_chain(compressed_messages)
                ctx.proc_result["content_ranker"] = result
        if self._context_window_optimizer is not None:
            messages = ctx.body.get("messages")
            if isinstance(messages, list) and messages:
                model = str(ctx.body.get("model", "") or "")
                result = self._context_window_optimizer.optimize_for_model(messages, model)
                optimized_messages = result.get("messages")
                if isinstance(optimized_messages, list):
                    ctx.body["messages"] = validate_tool_chain(optimized_messages)
                ctx.proc_result["context_window_optimizer"] = {
                    "model": str(result.get("model", model)),
                    "original_tokens": int(result.get("original_tokens", 0) or 0),
                    "optimized_tokens": int(result.get("optimized_tokens", 0) or 0),
                    "fits": bool(result.get("fits", False)),
                }
        if self._context_budget is not None and self._context_budget.enabled:
            messages = ctx.body.get("messages")
            if isinstance(messages, list) and messages:
                model = str(ctx.body.get("model", "") or "")
                model_windows = self._context_budget.model_context_windows
                max_window = (
                    int(model_windows.get(model, 0) or 0) if isinstance(model_windows, dict) else 0
                )
                used_tokens = self._context_budget.estimate_tokens(messages)
                level = self._context_budget.check_level(
                    used_tokens=used_tokens, max_tokens=max_window
                )
                if level != "normal":
                    degraded = self._context_budget.apply(
                        messages=messages, level=level, max_tokens=max_window
                    )
                    ctx.body["messages"] = validate_tool_chain(degraded)
                    ctx.session_headers["X-Orchesis-Context-Level"] = level
                    ctx.proc_result["context_budget_level"] = level
                    if self._compression_v2 is not None and level in ("L1", "L2"):
                        compressed = self._compression_v2.compress(
                            messages=ctx.body.get("messages", []),
                            budget_tokens=max_window,
                        )
                        compressed_messages = compressed.get("compressed_messages")
                        if isinstance(compressed_messages, list):
                            ctx.body["messages"] = validate_tool_chain(compressed_messages)
                        ctx.proc_result["compression_v2"] = compressed
                    _HTTP_PROXY_LOGGER.info(
                        "context budget degradation applied level=%s model=%s used_tokens=%s max_tokens=%s session_id=%s",
                        level,
                        model,
                        used_tokens,
                        max_window,
                        ctx.session_id,
                    )
        if self._context_engine is None or not self._context_engine.enabled:
            return True
        messages = ctx.body.get("messages")
        if not isinstance(messages, list) or not messages:
            return True
        max_tokens = int(ctx.body.get("max_completion_tokens", ctx.body.get("max_tokens", 0)) or 0)
        model = str(ctx.body.get("model", ""))
        result = self._context_engine.optimize(
            messages=messages,
            model=model,
            max_tokens=max_tokens,
        )
        ctx.body["messages"] = validate_tool_chain(result.messages)
        if result.tokens_saved > 0:
            ctx.session_headers["X-Orchesis-Context-Tokens-Saved"] = str(result.tokens_saved)
            ctx.session_headers["X-Orchesis-Context-Strategies"] = ",".join(
                result.strategies_applied
            )
        ctx.context_tokens_saved = result.tokens_saved
        ctx.context_strategies = result.strategies_applied
        return True

    def _is_streaming_request(self, ctx: _RequestContext) -> bool:
        return bool(
            self._streaming_enabled
            and isinstance(ctx.body, dict)
            and ctx.body.get("stream") is True
        )

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
            except json.JSONDecodeError:
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
    def _build_synthetic_response(
        events: list[str], text_parts: list[str], ctx: _RequestContext
    ) -> str:
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
            if "message_delta" not in event_str and '"usage"' not in event_str:
                continue
            for line in event_str.split("\n"):
                if not line.startswith("data: "):
                    continue
                try:
                    data = json.loads(line[6:])
                except json.JSONDecodeError:
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
        ctx.handler.send_header(
            "X-Orchesis-Cost", str(round(float(ctx.proc_result.get("cost", 0.0)), 6))
        )
        ctx.handler.send_header(
            "X-Orchesis-Cost-Velocity",
            str(round(float(self._cost_velocity.current_rate_per_hour()), 6)),
        )
        ctx.handler.send_header(
            "X-Orchesis-Daily-Total", str(round(self._cost_tracker.get_daily_total(), 4))
        )
        daily_budget = self._budget_cfg.get("daily")
        if isinstance(daily_budget, int | float):
            ctx.handler.send_header("X-Orchesis-Daily-Budget", f"{float(daily_budget):.4f}")
        ctx.handler.send_header("X-Orchesis-Saved", f"{float(ctx.request_saved_usd):.4f}")
        ctx.handler.send_header(
            "X-Orchesis-Session",
            str(ctx.session_id or ctx.proc_result.get("session_id", "unknown")),
        )
        if ctx.heartbeat_detected:
            ctx.handler.send_header("X-Orchesis-Heartbeat", "true")
        if ctx.content_loop_count > 1:
            ctx.handler.send_header("X-Orchesis-Loop-Count", str(ctx.content_loop_count))
        ctx.handler.send_header("X-Orchesis-Spend-Rate", f"{ctx.spend_rate_per_min:.4f}")
        ctx.handler.send_header(
            "X-Orchesis-Circuit", self._circuit_breaker.get_state().lower().replace("_", "-")
        )
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
        plugin_context = {
            "request_id": str(ctx.request_id or ""),
            "session_id": str(ctx.session_id or "unknown"),
            "path": str(ctx.handler.path),
            "provider": str(ctx.provider),
        }
        try:
            plugin_request = self._plugin_registry.run_request(dict(ctx.body), plugin_context)
            if isinstance(plugin_request, dict):
                ctx.body = plugin_request
            ctx.proc_result["plugins_request"] = plugin_context
        except Exception:
            # Plugin pipeline must not break request path.
            pass
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
                    ctx.session_headers["X-Orchesis-Cache-Similarity"] = (
                        f"{cache_result.similarity:.2f}"
                    )
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
        retries = (
            self._connection_pool._config.max_retries
            if self._connection_pool._config.retry_on_connection_error
            else 0
        )  # noqa: SLF001
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
                        {
                            "error": {
                                "type": "upstream_error",
                                "message": f"Failed to connect to upstream: {error}",
                            }
                        },
                    )
                    return False
                sleep_s = compute_upstream_retry_delay(
                    attempt,
                    base_delay=self._upstream_retry_base_delay,
                    max_delay=self._upstream_retry_max_delay,
                )
                if sleep_s > 0:
                    time.sleep(sleep_s)
        return False

    def _phase_post_upstream(self, ctx: _RequestContext) -> bool:
        plugin_context = {
            "request_id": str(ctx.request_id or ""),
            "session_id": str(ctx.session_id or "unknown"),
            "path": str(ctx.handler.path),
            "provider": str(ctx.provider),
        }
        try:
            plugin_response = self._plugin_registry.run_response(
                {
                    "status": int(ctx.resp_status),
                    "headers": dict(ctx.resp_headers),
                    "body": ctx.resp_body,
                },
                plugin_context,
            )
            if isinstance(plugin_response, dict):
                status_raw = plugin_response.get("status", ctx.resp_status)
                headers_raw = plugin_response.get("headers", ctx.resp_headers)
                body_raw = plugin_response.get("body", ctx.resp_body)
                ctx.resp_status = (
                    int(status_raw) if isinstance(status_raw, int | float) else int(ctx.resp_status)
                )
                ctx.resp_headers = (
                    dict(headers_raw) if isinstance(headers_raw, dict) else dict(ctx.resp_headers)
                )
                if isinstance(body_raw, bytes):
                    ctx.resp_body = body_raw
                elif isinstance(body_raw, str):
                    ctx.resp_body = body_raw.encode("utf-8")
            ctx.proc_result["plugins_response"] = plugin_context
        except Exception as exc:
            _HTTP_PROXY_LOGGER.debug("Suppressed: %s", exc)
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
                                "message": ctx.proc_result.get(
                                    "reason", "response contains secrets"
                                ),
                            }
                        },
                    )
                    return False
        except Exception as exc:
            _HTTP_PROXY_LOGGER.debug("Suppressed: %s", exc)
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
                    {
                        "error": {
                            "type": "upstream_error",
                            "message": f"Failed to connect to upstream: {error}",
                        }
                    },
                    ensure_ascii=False,
                ).encode("utf-8")
            ctx.cascade_decision = escalated_decision
            ctx.cascade_level_name = self._cascade_router.level_name(
                ctx.cascade_decision.cascade_level
            )
            try:
                decoded_retry = json.loads(ctx.resp_body.decode("utf-8"))
                if isinstance(decoded_retry, dict):
                    parsed_resp_retry = parse_response(decoded_retry, ctx.provider)
                    ctx.parsed_resp_obj = parsed_resp_retry
                    ctx.proc_result = self._response_processor.process(parsed_resp_retry)
            except Exception as exc:
                _HTTP_PROXY_LOGGER.debug("Suppressed: %s", exc)
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
                            if isinstance(message, dict) and isinstance(
                                message.get("content"), str
                            ):
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
            except Exception as exc:
                _HTTP_PROXY_LOGGER.debug("Suppressed: %s", exc)
        if (
            self._cascade_router is not None
            and ctx.cascade_decision is not None
            and ctx.parsed_resp_obj is not None
        ):
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
                    stop_reason = (
                        str(getattr(parsed, "stop_reason", "") or "").lower()
                        if parsed is not None
                        else ""
                    )
                    if stop_reason in {"length", "max_tokens"}:
                        error_type = "context_length"
            mast_findings = ctx.proc_result.get("mast_findings", [])
            has_injection = False
            if isinstance(mast_findings, list):
                for item in mast_findings:
                    if (
                        isinstance(item, dict)
                        and str(item.get("failure_mode", "")).upper() == "FM-3.1"
                    ):
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
        if self._thompson_sampler is not None:
            model = str(ctx.body.get("model", "") or "")
            if model:
                task_type = str(ctx.proc_result.get("context_task_type", "unknown") or "unknown")
                latency_ms = max(
                    0.0, (time.perf_counter() - float(ctx.request_started or 0.0)) * 1000.0
                )
                cost = max(0.0, float(ctx.proc_result.get("cost", 0.0) or 0.0))
                success = (
                    1.0
                    if bool(ctx.resp_status < 400 and ctx.proc_result.get("allowed", True))
                    else 0.0
                )
                quality = 0.7 + (0.3 * success)
                reward = (
                    quality
                    * (1.0 / (1.0 + (cost * 1000.0)))
                    * (1.0 / (1.0 + (latency_ms / 1000.0)))
                )
                self._thompson_sampler.update(model, task_type, reward)
        if self._agent_discovery is not None and self._agent_discovery.enabled:
            tools_used: list[str] = []
            for tool_call in getattr(ctx.parsed_req, "tool_calls", []):
                name = getattr(tool_call, "name", "")
                if isinstance(name, str) and name:
                    tools_used.append(name)
            parsed = ctx.parsed_resp_obj
            total_tokens = 0
            if parsed is not None:
                total_tokens = int(getattr(parsed, "input_tokens", 0)) + int(
                    getattr(parsed, "output_tokens", 0)
                )
            self._agent_discovery.record_request(
                agent_id=str(ctx.behavior_agent_id or "default"),
                request_data={
                    "session_id": ctx.session_id,
                    "model": str(ctx.body.get("model", "")),
                },
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
                tokens_in=int(getattr(ctx.parsed_resp_obj, "input_tokens", 0))
                if ctx.parsed_resp_obj is not None
                else 0,
                tokens_out=int(getattr(ctx.parsed_resp_obj, "output_tokens", 0))
                if ctx.parsed_resp_obj is not None
                else 0,
                cost_usd=float(ctx.proc_result.get("cost", 0.0)),
                latency_ms=(time.perf_counter() - ctx.request_started) * 1000.0,
                status="ok" if ctx.resp_status < 400 else "error",
                tool_calls=tool_calls_for_flow,
            )
        if self._experiment_manager:
            if ctx.experiment_id and ctx.variant_name:
                tokens_in = (
                    int(getattr(ctx.parsed_resp_obj, "input_tokens", 0))
                    if ctx.parsed_resp_obj
                    else 0
                )
                tokens_out = (
                    int(getattr(ctx.parsed_resp_obj, "output_tokens", 0))
                    if ctx.parsed_resp_obj
                    else 0
                )
                tool_count = (
                    len(getattr(ctx.parsed_resp_obj, "tool_calls", []))
                    if ctx.parsed_resp_obj
                    else 0
                )
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
                tokens_in=int(getattr(ctx.parsed_resp_obj, "input_tokens", 0))
                if ctx.parsed_resp_obj
                else 0,
                tokens_out=int(getattr(ctx.parsed_resp_obj, "output_tokens", 0))
                if ctx.parsed_resp_obj
                else 0,
                cost_usd=float(ctx.proc_result.get("cost", 0.0)),
                latency_ms=(time.perf_counter() - ctx.request_started) * 1000.0,
                tool_calls=len(getattr(ctx.parsed_resp_obj, "tool_calls", []))
                if ctx.parsed_resp_obj
                else 0,
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
                if (
                    state
                    and state.consecutive_errors
                    >= self._experiment_manager._task_tracker._config.consecutive_errors_threshold
                ):
                    should_finalize = True

            if should_finalize:
                outcome = self._experiment_manager._task_tracker.finalize_session(session_id)
                if ctx.experiment_id and ctx.variant_name:
                    self._experiment_manager.record_task_outcome(
                        ctx.experiment_id, ctx.variant_name, outcome
                    )
        tool_call_names: list[str] = []
        for tool_call in getattr(ctx.parsed_req, "tool_calls", []):
            name = getattr(tool_call, "name", "")
            if isinstance(name, str) and name:
                tool_call_names.append(name)

        prompt_length = (
            int(getattr(ctx.parsed_resp_obj, "input_tokens", 0))
            if ctx.parsed_resp_obj is not None
            else 0
        )
        if prompt_length <= 0:
            content_text = getattr(ctx.parsed_req, "content_text", "")
            if isinstance(content_text, str):
                prompt_length = len(content_text)

        retry_count = 0
        if isinstance(ctx.proc_result, dict):
            retry_raw = ctx.proc_result.get("retry_count", 0)
            if isinstance(retry_raw, int):
                retry_count = max(0, retry_raw)

        session_id_value = str(ctx.session_id or "default")
        agent_id_value = str(ctx.behavior_agent_id or "unknown")
        model_value = str(ctx.body.get("model", ctx.original_model))
        latency_ms_value = (time.perf_counter() - float(ctx.request_started or 0.0)) * 1000.0

        try:
            log_context_profile(
                session_id=session_id_value,
                agent_id=agent_id_value,
                prompt_length=prompt_length,
                tool_calls=tool_call_names,
                model=model_value,
                latency_ms=latency_ms_value,
                retry_count=retry_count,
                compression_ratio=1.0,
            )
        except Exception as exc:
            _HTTP_PROXY_LOGGER.debug("Suppressed: %s", exc)

        try:
            _evidence_ledger.record(
                {
                    "agent_id": str(ctx.behavior_agent_id or "unknown"),
                    "session_id": str(ctx.session_id or "default"),
                    "model": str(ctx.body.get("model", ctx.original_model)),
                    "decision": str(getattr(ctx, "final_decision", "FORWARD")),
                    "latency_ms": round(
                        (time.perf_counter() - float(ctx.request_started or 0.0)) * 1000.0, 2
                    ),
                    "retry_count": retry_count,
                }
            )
        except Exception as exc:
            _HTTP_PROXY_LOGGER.debug("Suppressed: %s", exc)

        cost_value = (
            float(ctx.proc_result.get("cost", 0.0)) if isinstance(ctx.proc_result, dict) else 0.0
        )
        if cost_value > 0.0:
            self._cost_velocity.record(cost_value)
        if self._spend_rate_detector is not None and cost_value > 0.0:
            # Record actual cost from upstream response. This updates the spend-rate
            # detector for future checks. See budget phase comment on eventual consistency.
            self._spend_rate_detector.record_spend(cost_value)
            spend_state = self._spend_rate_detector.check()
            ctx.spend_rate_per_min = float(spend_state.current_rate)
        if (
            self._spend_rate_detector is not None
            and self._spend_rate_detector.is_heartbeat_cost_high(ctx.body, cost_value)
        ):
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
                self._semantic_cache.store(
                    messages, model, tools or None, ctx.resp_body, tokens, cost
                )
        return True

    @staticmethod
    def _build_plugin_registry(policy: dict[str, Any]) -> PluginRegistry:
        registry = PluginRegistry()
        plugins_cfg = policy.get("plugins")
        if not isinstance(plugins_cfg, list):
            return registry
        for item in plugins_cfg:
            if not isinstance(item, dict):
                continue
            if not bool(item.get("enabled", True)):
                continue
            name = str(item.get("name", "")).strip()
            cfg = item.get("config")
            config = cfg if isinstance(cfg, dict) else {}
            if name == "request_logger":
                registry.register(RequestLoggerPlugin())
            elif name == "request_enricher":
                registry.register(RequestEnricherPlugin(config))
            elif name == "response_validator":
                registry.register(ResponseValidatorPlugin())
        return registry

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
            ctx.proc_result.setdefault(
                "model", str(ctx.original_model or ctx.body.get("model", ""))
            )
            ctx.proc_result.setdefault("model_used", str(ctx.body.get("model", ctx.original_model)))
            ctx.proc_result.setdefault("cache_hit", bool(ctx.from_semantic_cache))
            ctx.proc_result.setdefault(
                "cache_type", "semantic" if ctx.from_semantic_cache else "miss"
            )
            ctx.proc_result.setdefault("loop_detected", bool(ctx.was_loop_detected))
            ctx.proc_result.setdefault("loop_count", int(ctx.content_loop_count))
            ctx.proc_result.setdefault("heartbeat_detected", bool(ctx.heartbeat_detected))
            ctx.proc_result.setdefault("spend_rate_5min", float(ctx.spend_rate_per_min))
            ctx.proc_result.setdefault("cascaded", bool(ctx.was_escalated))
            ctx.proc_result.setdefault("cascade_reason", "escalated" if ctx.was_escalated else "")
        if not ctx.is_streaming:
            ctx.handler.send_response(ctx.resp_status)
            self._copy_upstream_headers(ctx.handler, ctx.resp_headers, len(ctx.resp_body))
            ctx.handler.send_header(
                "X-Orchesis-Cost", str(round(float(ctx.proc_result.get("cost", 0.0)), 6))
            )
            ctx.handler.send_header(
                "X-Orchesis-Cost-Velocity",
                str(round(float(self._cost_velocity.current_rate_per_hour()), 6)),
            )
            ctx.handler.send_header(
                "X-Orchesis-Daily-Total", str(round(self._cost_tracker.get_daily_total(), 4))
            )
            daily_budget = self._budget_cfg.get("daily")
            if isinstance(daily_budget, int | float):
                ctx.handler.send_header("X-Orchesis-Daily-Budget", f"{float(daily_budget):.4f}")
            ctx.handler.send_header("X-Orchesis-Saved", f"{float(ctx.request_saved_usd):.4f}")
            ctx.handler.send_header(
                "X-Orchesis-Session",
                str(ctx.session_id or ctx.proc_result.get("session_id", "unknown")),
            )
            ctx.handler.send_header(
                "X-Orchesis-Priority", str(ctx.proc_result.get("priority", "normal"))
            )
            ctx.handler.send_header("X-Orchesis-Cascade-Level", ctx.cascade_level_name)
            ctx.handler.send_header(
                "X-Orchesis-Cascade-Model", str(ctx.body.get("model", ctx.original_model))
            )
            if ctx.from_semantic_cache:
                ctx.handler.send_header(
                    "X-Orchesis-Cache", ctx.session_headers.get("X-Orchesis-Cache", "semantic")
                )
                ctx.handler.send_header(
                    "X-Orchesis-Cache-Similarity",
                    ctx.session_headers.get("X-Orchesis-Cache-Similarity", "1.00"),
                )
            else:
                ctx.handler.send_header("X-Orchesis-Cache", ctx.cascade_cache_state)
            ctx.handler.send_header(
                "X-Orchesis-Circuit", self._circuit_breaker.get_state().lower().replace("_", "-")
            )
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
                ctx.handler.send_header(
                    "X-Orchesis-Context-Tokens-Saved", str(ctx.context_tokens_saved)
                )
                ctx.handler.send_header(
                    "X-Orchesis-Context-Strategies", ",".join(ctx.context_strategies)
                )
            if ctx.threat_matches:
                ctx.handler.send_header(
                    "X-Orchesis-Threat-Detected", ",".join(m.threat_id for m in ctx.threat_matches)
                )
                ctx.handler.send_header(
                    "X-Orchesis-Threat-Severity", ctx.threat_matches[0].severity
                )
            if self._session_risk is not None:
                score = float(ctx.proc_result.get("session_risk_score", 0.0))
                if score > 0:
                    ctx.handler.send_header("X-Orchesis-Session-Risk", f"{score:.1f}")
            if self._behavioral_detector.enabled:
                ctx.handler.send_header("X-Orchesis-Behavior", ctx.behavior_header)
                if ctx.behavior_score_header:
                    ctx.handler.send_header("X-Orchesis-Anomaly-Score", ctx.behavior_score_header)
                if ctx.behavior_dims_header:
                    ctx.handler.send_header(
                        "X-Orchesis-Anomaly-Dimensions", ctx.behavior_dims_header
                    )
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
