"""Governance control-plane HTTP API."""

from __future__ import annotations

import json
import os
import time
import io
import zipfile
import hashlib
import threading
from contextlib import asynccontextmanager
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.routing import APIRoute
from fastapi.responses import JSONResponse, Response

from orchesis.auth import AgentAuthenticator, CredentialStore
from orchesis.ari import AgentReadinessIndex
from orchesis.agent_health import AgentHealthScore
from orchesis.audit import AuditEngine, AuditQuery
from orchesis.compliance_report import ComplianceReportGenerator
from orchesis.compliance_checker import RealTimeComplianceChecker
from orchesis.benchmark import BenchmarkSuite, ORCHESIS_BENCHMARK_V1
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
from orchesis.forensic_reconstruction import ForensicReconstructor
from orchesis.context_dna import ContextDNA
from orchesis.context_dna_store import ContextDNAStore
from orchesis.anomaly_alerts import AnomalyAlertManager
from orchesis.agent_profile import AgentIntelligenceProfile
from orchesis.agent_scorecard import AgentScorecard
from orchesis.pipeline import check_budget
from orchesis.evidence_record import EvidenceRecord
from orchesis.cost_analytics import CostAnalytics
from orchesis.cost_forecast import CostForecaster
from orchesis.cost_attribution import CostAttributionEngine
from orchesis.session_heatmap import SessionHeatmap
from orchesis.budget_advisor import BudgetAdvisor
from orchesis.session_replay import SessionReplay
from orchesis.session_groups import SessionGroupManager
from orchesis.community_intel import CommunityIntel
from orchesis.request_inspector import RequestInspector
from orchesis.pipeline_debugger import PipelineDebugger
from orchesis.tool_call_analyzer import ToolCallAnalyzer
from orchesis.memory_tracker import MemoryTracker
from orchesis.fleet_coordinator import FleetCoordinator
from orchesis.agent_compare import AgentComparer
from orchesis.context_timeline import ContextTimeline
from orchesis.persona_guardian import PersonaGuardian
try:
    from orchesis.vibe_audit import VibeCodeAuditor
except ModuleNotFoundError:
    class VibeCodeAuditor:  # type: ignore[no-redef]
        def audit_code(self, code: str, language: str) -> dict[str, Any]:
            _ = (code, language)
            return {
                "score": 0.0,
                "issues": [],
                "summary": "vibe_audit module unavailable",
            }
from orchesis.token_yield import TokenYieldTracker
from orchesis.token_yield_report import TokenYieldReportGenerator
from orchesis.threat_feed import ThreatFeed
from orchesis.threat_patterns import ThreatPatternLibrary
from orchesis.data_flywheel import DataFlywheel
from orchesis.signature_editor import SignatureEditor
from orchesis.alert_rules import AlertRule, AlertRulesEngine
from orchesis.agent_graph import AgentCollaborationGraph
from orchesis.agent_lifecycle import AgentLifecycleManager
from orchesis.geo_intel import GeoIntel
from orchesis.tenants import TenantManager
from orchesis.semantic_cache import SemanticCache
from orchesis.cache_warmer import CacheWarmer
from orchesis.api_rate_limiter import ApiRateLimiter
from orchesis.shadow_mode import ShadowModeRunner
from orchesis.intent_classifier import IntentClassifier
from orchesis.response_analyzer import ResponseAnalyzer
from orchesis.anomaly_predictor import AnomalyPredictor
from orchesis.policy_optimizer import PolicyOptimizer
from orchesis.byzantine_detector import ByzantineDetector
from orchesis.raft_context import RaftContextProtocol
from orchesis.gossip_protocol import GossipProtocol
from orchesis.incident_manager import IncidentManager
from orchesis.knowledge_base import OrchesisKnowledgeBase
from orchesis.quorum_sensing import QuorumSensor
from orchesis.pid_controller_v2 import PIDControllerV2
from orchesis.kalman_estimator import KalmanStateEstimator
from orchesis.kolmogorov_importance import KolmogorovImportance
from orchesis.otel_bridge import OpenTelemetryBridge
from orchesis.vickrey_allocator import VickreyBudgetAllocator
from orchesis.arc_readiness import AgentReadinessCertifier
from orchesis.are.framework import AREFramework
from orchesis.casura.incident_db import CASURAIncidentDB
from orchesis.casura.intelligence import IncidentIntelligence
from orchesis.aabb.benchmark import AABBBenchmark
from orchesis.monitoring.competitive import CompetitiveMonitor
from orchesis.monitoring.parsers import SocialMonitoringParsers
from orchesis.par_reasoning import PARReasoner
from orchesis.group_selection import GroupSelectionModel
from orchesis.relevance_theory import RelevanceScorer
from orchesis.cost_of_freedom import CostOfFreedomCalculator
from orchesis.agent_report_card import AgentReportCard
from orchesis.red_queen import RedQueenMonitor
from orchesis.double_loop_learning import DoubleLoopLearner
from orchesis.complement_cascade import ComplementCascade
from orchesis.agent_autopsy import AgentAutopsy
from orchesis.session_forensics import SessionForensics
from orchesis.weekly_report import WeeklyReportGenerator
from orchesis.mrac_controller import MRACController
from orchesis.keystone_agent import KeystoneDetector
from orchesis.criticality_control import CriticalityController
from orchesis.immune_memory import ImmuneMemory
from orchesis.homeostasis import HomeostasisController
from orchesis.adaptive_threshold import AdaptiveThresholdManager
from orchesis.system_health_report import SystemHealthReport
from orchesis.policy_impact_analyzer import PolicyImpactAnalyzer
from orchesis.request_explainer import RequestExplainer
from orchesis.insights import OrchesisInsights
from orchesis.channel_monitor import ChannelHealthMonitor
from orchesis.whatsapp_expiry import WhatsAppExpiryTracker
from orchesis.webchat_inject import WebChatInjector
from orchesis.h43_quantum import H43QuantumMVE
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
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        monitor = getattr(app.state, "mcp_monitor", None)
        if monitor is not None and hasattr(monitor, "stop"):
            monitor.stop()

    app = FastAPI(title="Orchesis Control API", docs_url=None, redoc_url=None, lifespan=lifespan)
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
    app.state.session_groups = SessionGroupManager(
        str(policy_file.parent / ".orchesis" / "session_groups.json")
    )
    app.state.compliance_checker = RealTimeComplianceChecker()
    app.state.incident_manager = IncidentManager()
    app.state.knowledge_base = OrchesisKnowledgeBase()
    app.state.agent_comparer = AgentComparer()
    app.state.context_timeline = ContextTimeline()
    app.state.forensic_reconstructor = ForensicReconstructor(decisions_log)
    persona_cfg = (
        current_version.policy.get("persona_guardian")
        if isinstance(current_version.policy, dict) and isinstance(current_version.policy.get("persona_guardian"), dict)
        else {}
    )
    app.state.persona_guardian = PersonaGuardian(persona_cfg)
    quorum_cfg = (
        current_version.policy.get("quorum_sensing")
        if isinstance(current_version.policy, dict) and isinstance(current_version.policy.get("quorum_sensing"), dict)
        else {}
    )
    app.state.quorum_sensor = QuorumSensor(quorum_cfg)
    pid_cfg = (
        current_version.policy.get("pid_controller_v2")
        if isinstance(current_version.policy, dict) and isinstance(current_version.policy.get("pid_controller_v2"), dict)
        else {}
    )
    app.state.pid_controller_v2 = PIDControllerV2(pid_cfg)
    kalman_cfg = (
        current_version.policy.get("kalman_estimator")
        if isinstance(current_version.policy, dict) and isinstance(current_version.policy.get("kalman_estimator"), dict)
        else {}
    )
    app.state.kalman_estimator = KalmanStateEstimator(kalman_cfg)
    kolmogorov_cfg = (
        current_version.policy.get("kolmogorov_importance")
        if isinstance(current_version.policy, dict)
        and isinstance(current_version.policy.get("kolmogorov_importance"), dict)
        else {}
    )
    app.state.kolmogorov_importance = KolmogorovImportance(kolmogorov_cfg)
    otel_bridge_cfg = (
        current_version.policy.get("otel_bridge")
        if isinstance(current_version.policy, dict) and isinstance(current_version.policy.get("otel_bridge"), dict)
        else {}
    )
    app.state.otel_bridge = OpenTelemetryBridge(otel_bridge_cfg)
    vickrey_cfg = (
        current_version.policy.get("vickrey_allocator")
        if isinstance(current_version.policy, dict) and isinstance(current_version.policy.get("vickrey_allocator"), dict)
        else {}
    )
    app.state.vickrey_allocator = VickreyBudgetAllocator(vickrey_cfg)
    mrac_cfg = (
        current_version.policy.get("mrac_controller")
        if isinstance(current_version.policy, dict) and isinstance(current_version.policy.get("mrac_controller"), dict)
        else {}
    )
    app.state.mrac_controller = MRACController(mrac_cfg)
    keystone_cfg = (
        current_version.policy.get("keystone_detector")
        if isinstance(current_version.policy, dict) and isinstance(current_version.policy.get("keystone_detector"), dict)
        else {}
    )
    app.state.keystone_detector = KeystoneDetector(keystone_cfg)
    criticality_cfg = (
        current_version.policy.get("criticality_control")
        if isinstance(current_version.policy, dict) and isinstance(current_version.policy.get("criticality_control"), dict)
        else {}
    )
    app.state.criticality_controller = CriticalityController(criticality_cfg)
    immune_cfg = (
        current_version.policy.get("immune_memory")
        if isinstance(current_version.policy, dict) and isinstance(current_version.policy.get("immune_memory"), dict)
        else {}
    )
    app.state.immune_memory = ImmuneMemory(immune_cfg)
    homeostasis_cfg = (
        current_version.policy.get("homeostasis")
        if isinstance(current_version.policy, dict) and isinstance(current_version.policy.get("homeostasis"), dict)
        else {}
    )
    app.state.homeostasis = HomeostasisController(homeostasis_cfg)
    threshold_cfg = (
        current_version.policy.get("adaptive_threshold")
        if isinstance(current_version.policy, dict) and isinstance(current_version.policy.get("adaptive_threshold"), dict)
        else {}
    )
    app.state.adaptive_threshold = AdaptiveThresholdManager(threshold_cfg)
    app.state.policy_impact_analyzer = PolicyImpactAnalyzer()
    app.state.request_explainer = RequestExplainer()
    app.state.arc_readiness = AgentReadinessCertifier()
    app.state.are = AREFramework()
    app.state.casura_db = CASURAIncidentDB()
    app.state.casura_intel = IncidentIntelligence()
    app.state.aabb_benchmark = AABBBenchmark()
    app.state.par_reasoner = PARReasoner()
    group_selection_cfg = (
        current_version.policy.get("group_selection")
        if isinstance(current_version.policy, dict) and isinstance(current_version.policy.get("group_selection"), dict)
        else {}
    )
    app.state.group_selection = GroupSelectionModel(group_selection_cfg)
    relevance_cfg = (
        current_version.policy.get("relevance_theory")
        if isinstance(current_version.policy, dict) and isinstance(current_version.policy.get("relevance_theory"), dict)
        else {}
    )
    app.state.relevance_scorer = RelevanceScorer(relevance_cfg)
    app.state.cost_of_freedom = CostOfFreedomCalculator()
    app.state.agent_report_card = AgentReportCard()
    app.state.competitive_monitor = CompetitiveMonitor()
    app.state.social_parsers = SocialMonitoringParsers()
    app.state.monitoring_items: list[dict[str, Any]] = []
    app.state.monitoring_opportunities: list[dict[str, Any]] = []
    app.state.weekly_report_generator = WeeklyReportGenerator()
    red_queen_cfg = (
        current_version.policy.get("red_queen")
        if isinstance(current_version.policy, dict) and isinstance(current_version.policy.get("red_queen"), dict)
        else {}
    )
    app.state.red_queen = RedQueenMonitor(red_queen_cfg)
    double_loop_cfg = (
        current_version.policy.get("double_loop_learning")
        if isinstance(current_version.policy, dict)
        and isinstance(current_version.policy.get("double_loop_learning"), dict)
        else {}
    )
    app.state.double_loop = DoubleLoopLearner(double_loop_cfg)
    complement_cfg = (
        current_version.policy.get("complement_cascade")
        if isinstance(current_version.policy, dict)
        and isinstance(current_version.policy.get("complement_cascade"), dict)
        else {}
    )
    app.state.complement_cascade = ComplementCascade(complement_cfg)
    app.state.agent_autopsy = AgentAutopsy()
    app.state.session_forensics = SessionForensics()
    cost_attribution_cfg = (
        current_version.policy.get("cost_attribution")
        if isinstance(current_version.policy, dict) and isinstance(current_version.policy.get("cost_attribution"), dict)
        else {}
    )
    app.state.cost_attribution = CostAttributionEngine(cost_attribution_cfg)
    feed_cfg = (
        current_version.policy.get("threat_feed")
        if isinstance(current_version.policy, dict) and isinstance(current_version.policy.get("threat_feed"), dict)
        else {}
    )
    app.state.threat_feed = ThreatFeed(feed_cfg)
    app.state.threat_patterns = ThreatPatternLibrary()
    app.state.signature_editor = SignatureEditor(str(policy_file.parent / ".orchesis" / "signatures.json"))
    app.state.tenant_manager = TenantManager(str(policy_file.parent / ".orchesis" / "tenants"))
    semantic_cfg = (
        current_version.policy.get("semantic_cache")
        if isinstance(current_version.policy, dict) and isinstance(current_version.policy.get("semantic_cache"), dict)
        else {}
    )
    app.state.semantic_cache = SemanticCache(semantic_cfg)
    cache_warming_cfg = (
        semantic_cfg.get("warming") if isinstance(semantic_cfg.get("warming"), dict) else {}
    )
    app.state.cache_warmer = CacheWarmer(app.state.semantic_cache, cache_warming_cfg)
    raw_alert_rules = (
        current_version.policy.get("alert_rules")
        if isinstance(current_version.policy, dict) and isinstance(current_version.policy.get("alert_rules"), list)
        else []
    )
    parsed_rules: list[AlertRule] = []
    for item in raw_alert_rules:
        if not isinstance(item, dict):
            continue
        try:
            parsed_rules.append(AlertRule(item))
        except ValueError:
            continue
    app.state.alert_rules_engine = AlertRulesEngine(parsed_rules)
    app.state.benchmark_results = {}
    app.state.dna_store = ContextDNAStore(str(policy_file.parent / ".orchesis" / "dna"))
    app.state.agent_scorecard = AgentScorecard()
    app.state.tool_call_analyzer = ToolCallAnalyzer()
    app.state.memory_tracker = MemoryTracker()
    app.state.fleet_coordinator = FleetCoordinator()
    app.state.vibe_auditor = VibeCodeAuditor()
    app.state.intent_classifier = IntentClassifier()
    app.state.response_analyzer = ResponseAnalyzer()
    app.state.anomaly_predictor = AnomalyPredictor()
    app.state.policy_optimizer = PolicyOptimizer()
    app.state.byzantine_detector = ByzantineDetector()
    app.state.raft_context = RaftContextProtocol()
    app.state.gossip_protocol = GossipProtocol()
    flywheel_cfg = (
        current_version.policy.get("data_flywheel")
        if isinstance(current_version.policy, dict) and isinstance(current_version.policy.get("data_flywheel"), dict)
        else {}
    )
    app.state.data_flywheel = DataFlywheel(flywheel_cfg)
    community_cfg = (
        current_version.policy.get("community")
        if isinstance(current_version.policy, dict) and isinstance(current_version.policy.get("community"), dict)
        else {}
    )
    app.state.community_intel = CommunityIntel(community_cfg)
    app.state.system_health_report = SystemHealthReport()
    app.state.orchesis_insights = OrchesisInsights()
    app.state.channel_monitor = ChannelHealthMonitor()
    app.state.webchat_injector = WebChatInjector()
    app.state.h43_quantum = H43QuantumMVE()
    app.state.whatsapp_expiry = WhatsAppExpiryTracker()
    app.state.notifications: list[dict[str, Any]] = []
    app.state.notifications_lock = threading.Lock()
    app.state.agent_lifecycle = AgentLifecycleManager()
    app.state.api_limiter = ApiRateLimiter()
    app.state.shadow_mode_enabled = False
    app.state.shadow_mode_log_divergences = True
    app.state.shadow_policy_path = ""
    app.state.shadow_runner = None
    if (
        hasattr(current_version, "registry")
        and hasattr(current_version.registry, "agents")
        and isinstance(current_version.registry.agents, dict)
    ):
        for agent_id in current_version.registry.agents.keys():
            if isinstance(agent_id, str) and agent_id.strip():
                app.state.fleet_coordinator.register_agent(agent_id, ["general"])
    anomaly_cfg = (
        current_version.policy.get("anomaly_alerts")
        if isinstance(current_version.policy, dict) and isinstance(current_version.policy.get("anomaly_alerts"), dict)
        else {}
    )
    app.state.anomaly_alerts = AnomalyAlertManager(app.state.dna_store, anomaly_cfg)
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

    def _api_rate_limit_config(candidate_policy: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(candidate_policy, dict):
            return {}
        cfg: dict[str, Any] = {}
        direct = candidate_policy.get("api_rate_limit")
        if isinstance(direct, dict):
            cfg.update(direct)
        api_cfg = candidate_policy.get("api")
        nested = api_cfg.get("rate_limit") if isinstance(api_cfg, dict) else None
        if isinstance(nested, dict):
            cfg.update(nested)
        return cfg

    def _sync_api_limiter(candidate_policy: dict[str, Any]) -> None:
        cfg = _api_rate_limit_config(candidate_policy)
        limiter = getattr(app.state, "api_limiter", None)
        if isinstance(limiter, ApiRateLimiter):
            limiter.configure(cfg)
        else:
            app.state.api_limiter = ApiRateLimiter(cfg)

    def _shadow_engine(request_payload: dict[str, Any], shadow_policy: dict[str, Any]) -> dict[str, Any]:
        payload = dict(request_payload) if isinstance(request_payload, dict) else {}
        tool_name = payload.get("tool_name")
        if not isinstance(tool_name, str) or not tool_name.strip():
            tool_name = payload.get("tool")
        params = payload.get("params")
        eval_payload = {
            "tool": str(tool_name or ""),
            "params": dict(params) if isinstance(params, dict) else {},
            "cost": payload.get("cost", 0.0),
            "context": dict(payload.get("context")) if isinstance(payload.get("context"), dict) else {},
        }
        decision = evaluate(
            eval_payload,
            shadow_policy,
            state=tracker,
            emitter=event_bus,
            registry=app.state.current_version.registry,
            plugins=app.state.plugins,
            session_type="shadow",
            channel=None,
            debug=False,
        )
        return {"decision": "ALLOW" if decision.allowed else "DENY", "allowed": bool(decision.allowed)}

    def _sync_shadow_mode(candidate_policy: dict[str, Any]) -> None:
        cfg = candidate_policy.get("shadow_mode") if isinstance(candidate_policy, dict) else None
        if not isinstance(cfg, dict):
            app.state.shadow_mode_enabled = False
            app.state.shadow_runner = None
            return
        app.state.shadow_mode_enabled = bool(cfg.get("enabled", False))
        app.state.shadow_mode_log_divergences = bool(cfg.get("log_divergences", True))
        shadow_policy_ref = str(cfg.get("shadow_policy", "shadow_policy.yaml") or "shadow_policy.yaml").strip()
        app.state.shadow_policy_path = shadow_policy_ref
        if not app.state.shadow_mode_enabled:
            app.state.shadow_runner = None
            return
        shadow_path = Path(shadow_policy_ref)
        if not shadow_path.is_absolute():
            shadow_path = (policy_file.parent / shadow_path).resolve()
        try:
            shadow_policy = load_policy(str(shadow_path))
        except Exception:
            shadow_policy = dict(app.state.current_version.policy)
        app.state.shadow_runner = ShadowModeRunner(shadow_policy, _shadow_engine)

    def _sync_data_flywheel(candidate_policy: dict[str, Any]) -> None:
        cfg = (
            candidate_policy.get("data_flywheel")
            if isinstance(candidate_policy, dict) and isinstance(candidate_policy.get("data_flywheel"), dict)
            else {}
        )
        flywheel = getattr(app.state, "data_flywheel", None)
        if not isinstance(flywheel, DataFlywheel):
            app.state.data_flywheel = DataFlywheel(cfg)
            return
        levels = cfg.get("levels")
        if isinstance(levels, list):
            cleaned = [str(item) for item in levels if str(item) in DataFlywheel.LEVELS]
            if cleaned:
                flywheel.enabled_levels = cleaned

    def _sync_are_from_policy(candidate_policy: dict[str, Any]) -> None:
        are_engine = AREFramework()
        defaults = [
            {"name": "availability", "sli": "availability", "target": 0.999, "window_days": 30},
            {"name": "security_rate", "sli": "security_rate", "target": 0.95, "window_days": 7},
        ]
        are_cfg = candidate_policy.get("are") if isinstance(candidate_policy, dict) else None
        slos = are_cfg.get("slos") if isinstance(are_cfg, dict) and isinstance(are_cfg.get("slos"), list) else defaults
        loaded = 0
        for row in slos:
            if not isinstance(row, dict):
                continue
            try:
                are_engine.define_slo(
                    name=str(row.get("name", "") or "").strip(),
                    sli=str(row.get("sli", "") or "").strip(),
                    target=float(row.get("target", 0.0) or 0.0),
                    window_days=int(row.get("window_days", 30) or 30),
                )
                loaded += 1
            except (ValueError, TypeError):
                continue
        if loaded == 0:
            for row in defaults:
                are_engine.define_slo(
                    name=row["name"],
                    sli=row["sli"],
                    target=row["target"],
                    window_days=row["window_days"],
                )
        app.state.are = are_engine

    def _refresh_current_version() -> None:
        app.state.current_version = store.current or store.load(str(policy_file))
        app.state.plugins = load_plugins_for_policy(
            app.state.current_version.policy,
            app.state.plugin_modules,
        )
        semantic_cfg_local = (
            app.state.current_version.policy.get("semantic_cache")
            if isinstance(app.state.current_version.policy, dict)
            and isinstance(app.state.current_version.policy.get("semantic_cache"), dict)
            else {}
        )
        app.state.semantic_cache = SemanticCache(semantic_cfg_local)
        cache_warming_cfg_local = (
            semantic_cfg_local.get("warming")
            if isinstance(semantic_cfg_local.get("warming"), dict)
            else {}
        )
        app.state.cache_warmer = CacheWarmer(app.state.semantic_cache, cache_warming_cfg_local)
        _sync_decision_emitter(app.state.current_version.policy)
        app.state.sync_server.set_current_version(app.state.current_version.version_id)
        _sync_alerts(app.state.current_version.policy)
        _sync_auth(app.state.current_version.policy)
        _sync_agent_teams_from_policy(app.state.current_version.policy)
        _sync_api_limiter(app.state.current_version.policy)
        _sync_shadow_mode(app.state.current_version.policy)
        _sync_data_flywheel(app.state.current_version.policy)
        _sync_are_from_policy(app.state.current_version.policy)

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
    _sync_api_limiter(current_version.policy)
    _sync_shadow_mode(current_version.policy)
    _sync_data_flywheel(current_version.policy)
    _sync_are_from_policy(current_version.policy)

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

    def _client_id_from_request(request: Request) -> str:
        forwarded = request.headers.get("x-forwarded-for")
        if isinstance(forwarded, str) and forwarded.strip():
            return forwarded.split(",", 1)[0].strip() or "unknown"
        client = request.client
        host = client.host if client is not None else None
        if isinstance(host, str) and host.strip():
            return host.strip()
        return "unknown"

    def _is_protected_api_request(request: Request) -> bool:
        path = request.url.path
        if not path.startswith("/api/v1/"):
            return False
        if path in {"/api/v1/status"}:
            return False
        expected = _required_token()
        if not isinstance(expected, str) or not expected.strip():
            return False
        authorization = request.headers.get("authorization")
        if not isinstance(authorization, str) or not authorization.startswith("Bearer "):
            return False
        provided = authorization.split(" ", 1)[1].strip()
        return provided == expected

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

    def _build_ari_payload(agent_id: str) -> dict[str, Any]:
        _refresh_current_version()
        policy = app.state.current_version.policy
        readiness_cfg = policy.get("agent_readiness", {}) if isinstance(policy, dict) else {}
        weights = readiness_cfg.get("weights") if isinstance(readiness_cfg, dict) else None
        thresholds = readiness_cfg.get("thresholds") if isinstance(readiness_cfg, dict) else None
        metrics: dict[str, Any] = {}
        metrics_store = readiness_cfg.get("metrics", {}) if isinstance(readiness_cfg, dict) else {}
        if isinstance(metrics_store, dict):
            selected = metrics_store.get(agent_id, {})
            if isinstance(selected, dict):
                metrics = selected
        ari = AgentReadinessIndex(weights=weights, thresholds=thresholds)
        result = ari.evaluate(agent_id=agent_id, metrics=metrics)
        by_name = {item.name: item for item in result.dimensions}
        security = by_name.get("security_posture")
        reliability = by_name.get("task_reliability")
        cost = by_name.get("cost_predictability")
        observability = by_name.get("observability")
        return {
            "agent_id": agent_id,
            "score": int(round(float(result.index))),
            "status": result.verdict,
            "dimensions": {
                "security": {
                    "score": int(round(float(security.score if security else 0.0))),
                    "weight": round((float(security.weight if security else 0.0) / 100.0), 4),
                },
                "reliability": {
                    "score": int(round(float(reliability.score if reliability else 0.0))),
                    "weight": round((float(reliability.weight if reliability else 0.0) / 100.0), 4),
                },
                "cost": {
                    "score": int(round(float(cost.score if cost else 0.0))),
                    "weight": round((float(cost.weight if cost else 0.0) / 100.0), 4),
                },
                "observability": {
                    "score": int(round(float(observability.score if observability else 0.0))),
                    "weight": round((float(observability.weight if observability else 0.0) / 100.0), 4),
                },
            },
            "blocking_gates": list(result.blocking_failures),
            "recommendations": list(result.recommendations),
        }

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

    def _build_export_zip() -> bytes:
        source = Path(app.state.decisions_log)
        events = read_events_from_jsonl(source) if source.exists() else []
        agent_ids = sorted(
            {
                str(getattr(event, "agent_id", "") or "__global__")
                for event in events
                if str(getattr(event, "agent_id", "") or "").strip()
            }
            | set(app.state.dna_store.list_agents())
        )
        if not agent_ids:
            agent_ids = ["__global__"]
        session_id = "__global__"
        for event in events:
            snapshot = getattr(event, "state_snapshot", {})
            if isinstance(snapshot, dict):
                candidate = _extract_session_id(snapshot)
                if isinstance(candidate, str) and candidate.strip():
                    session_id = candidate.strip()
                    break
        evidence_record = _build_evidence_record(session_id)
        compliance_report = _build_compliance_report(agent_ids[0])
        profile_builder = AgentIntelligenceProfile()
        profiles = [
            profile_builder.build(
                agent_id=agent_id,
                dna_store=app.state.dna_store,
                health_score={"agent_id": agent_id, "score": 0.0, "grade": "N/A"},
                decisions_log=app.state.decisions_log,
            )
            for agent_id in agent_ids
        ]
        benchmark_results = app.state.benchmark_results.get("latest", {})
        decisions_raw = source.read_text(encoding="utf-8") if source.exists() else ""
        manifest = {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "version": __version__,
            "decisions_count": len(events),
            "session_id": session_id,
            "agents_count": len(agent_ids),
            "files": [
                "decisions.jsonl",
                "evidence_record.json",
                "compliance_report.json",
                "agent_profiles.json",
                "benchmark_results.json",
                "export_manifest.json",
            ],
        }
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("decisions.jsonl", decisions_raw)
            zf.writestr("evidence_record.json", json.dumps(evidence_record, ensure_ascii=False, indent=2))
            zf.writestr("compliance_report.json", json.dumps(compliance_report, ensure_ascii=False, indent=2))
            zf.writestr("agent_profiles.json", json.dumps(profiles, ensure_ascii=False, indent=2))
            zf.writestr("benchmark_results.json", json.dumps(benchmark_results, ensure_ascii=False, indent=2))
            zf.writestr("export_manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
        return buffer.getvalue()

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

    def _cache_warm_candidates(limit: int | None = None) -> list[dict[str, Any]]:
        source = Path(app.state.decisions_log)
        events = read_events_from_jsonl(source) if source.exists() else []
        warmer = app.state.cache_warmer
        candidates = warmer.analyze_history(events)
        if isinstance(limit, int) and limit > 0:
            return candidates[:limit]
        return candidates

    def _build_cost_analytics_payload(period_hours: int) -> dict[str, Any]:
        source = Path(app.state.decisions_log)
        events = read_events_from_jsonl(source) if source.exists() else []
        return CostAnalytics().compute(events, period_hours=period_hours)

    def _build_hourly_cost_points(history_days: int = 7) -> list[dict[str, Any]]:
        source = Path(app.state.decisions_log)
        events = read_events_from_jsonl(source) if source.exists() else []
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(days=max(1, int(history_days)))
        buckets: dict[int, float] = {}
        for event in events:
            ts_raw = str(getattr(event, "timestamp", "") or "")
            ts = _parse_health_ts(ts_raw)
            if ts is None or ts < cutoff:
                continue
            hour_key = int(ts.replace(minute=0, second=0, microsecond=0).timestamp() // 3600)
            buckets[hour_key] = buckets.get(hour_key, 0.0) + float(getattr(event, "cost", 0.0) or 0.0)
        if not buckets:
            return []
        keys = sorted(buckets.keys())
        first = keys[0]
        points: list[dict[str, Any]] = []
        for idx, key in enumerate(keys):
            points.append(
                {
                    "hour_index": key - first if key >= first else idx,
                    "timestamp": datetime.fromtimestamp(key * 3600, tz=timezone.utc).isoformat(),
                    "cost": round(float(buckets[key]), 8),
                }
            )
        return points

    def _build_session_heatmap_payload(days: int = 7) -> dict[str, Any]:
        source = Path(app.state.decisions_log)
        events = read_events_from_jsonl(source) if source.exists() else []
        return SessionHeatmap().compute(events, days=days)

    def _build_session_heatmap_daily() -> list[dict[str, Any]]:
        source = Path(app.state.decisions_log)
        events = read_events_from_jsonl(source) if source.exists() else []
        return SessionHeatmap().get_daily_summary(events)

    def _period_hours(period: str) -> int:
        value = str(period or "24h").strip().lower()
        if value.endswith("h"):
            try:
                return max(1, min(24 * 31, int(value[:-1])))
            except ValueError:
                return 24
        if value.endswith("d"):
            try:
                return max(1, min(31, int(value[:-1]))) * 24
            except ValueError:
                return 24
        return 24

    def _build_token_yield_report(period: str) -> dict[str, Any]:
        source = Path(app.state.decisions_log)
        events = read_events_from_jsonl(source) if source.exists() else []
        cutoff = datetime.now(timezone.utc) - timedelta(hours=_period_hours(period))
        rows: list[dict[str, Any]] = []
        for event in events:
            ts = _parse_health_ts(str(getattr(event, "timestamp", "") or ""))
            if ts is None or ts < cutoff:
                continue
            snapshot = getattr(event, "state_snapshot", {})
            if not isinstance(snapshot, dict):
                snapshot = {}
            prompt = snapshot.get("prompt_tokens", snapshot.get("prompt_length", 0))
            completion = snapshot.get("completion_tokens", 0)
            rows.append(
                {
                    "session_id": str(snapshot.get("session_id", "__global__")),
                    "agent_id": str(getattr(event, "agent_id", "unknown") or "unknown"),
                    "model": str(snapshot.get("model", "unknown") or "unknown"),
                    "prompt_tokens": int(prompt) if isinstance(prompt, int | float) else 0,
                    "completion_tokens": int(completion) if isinstance(completion, int | float) else 0,
                    "cache_hit": bool(snapshot.get("cache_hit", False)),
                    "unique_content_ratio": (
                        float(snapshot.get("unique_content_ratio"))
                        if isinstance(snapshot.get("unique_content_ratio"), int | float)
                        else 1.0
                    ),
                    "cost": float(getattr(event, "cost", 0.0) or 0.0),
                    "context_collapse": bool(snapshot.get("context_collapse", False)),
                }
            )
        generator = TokenYieldReportGenerator()
        report = generator.generate(rows, period=period)
        report["benchmark_comparison"] = generator.get_benchmark_comparison(report)
        return report

    def _build_cost_attribution_payload() -> dict[str, Any]:
        source = Path(app.state.decisions_log)
        events = read_events_from_jsonl(source) if source.exists() else []
        return app.state.cost_attribution.attribute(events)

    def _build_budget_advice_payload() -> dict[str, Any]:
        source = Path(app.state.decisions_log)
        events = read_events_from_jsonl(source) if source.exists() else []
        policy = app.state.current_version.policy
        budgets_cfg = (
            policy.get("budgets", {})
            if isinstance(policy, dict) and isinstance(policy.get("budgets"), dict)
            else {}
        )
        budget_daily = policy.get("budget_daily", 0.0) if isinstance(policy, dict) else 0.0
        current_budget = {
            "daily_limit_usd": float(budgets_cfg.get("daily", budget_daily) or 0.0),
        }
        return BudgetAdvisor().analyze(events, current_budget)

    def _build_scorecard_payload(agent_id: str, period: str) -> dict[str, Any]:
        source = Path(app.state.decisions_log)
        events = read_events_from_jsonl(source) if source.exists() else []
        scorer = app.state.agent_scorecard
        return scorer.compute(agent_id=agent_id, decisions_log=events, period=period)

    def _build_scorecard_all_payload() -> list[dict[str, Any]]:
        source = Path(app.state.decisions_log)
        events = read_events_from_jsonl(source) if source.exists() else []
        scorer = app.state.agent_scorecard
        return scorer.compute_all(decisions_log=events)

    def _build_pipeline_debugger(policy: dict[str, Any] | None = None) -> PipelineDebugger:
        effective_policy = policy if isinstance(policy, dict) else current_version.policy
        return PipelineDebugger(engine=evaluate, policy=effective_policy)

    def _build_tool_session_payload(session_id: str) -> dict[str, Any]:
        source = Path(app.state.decisions_log)
        events = read_events_from_jsonl(source) if source.exists() else []
        analyzer = app.state.tool_call_analyzer
        return analyzer.get_session_tool_stats(session_id=session_id, decisions_log=events)

    def _build_vibe_audit_payload(code: str, language: str, severity: str = "low") -> dict[str, Any]:
        auditor = VibeCodeAuditor({"severity_threshold": str(severity or "low").lower()})
        return auditor.audit_code(code=code, language=language)

    def _build_vibe_audit_directory_payload(
        dir_path: str,
        summary: bool,
        extensions: list[str] | None = None,
        severity: str = "low",
    ) -> dict[str, Any]:
        auditor = VibeCodeAuditor({"severity_threshold": str(severity or "low").lower()})
        if summary:
            return auditor.audit_directory_summary(dir_path=dir_path, extensions=extensions)
        return auditor.audit_directory(dir_path=dir_path, extensions=extensions)

    def _hydrate_memory_session(session_id: str) -> None:
        tracker = app.state.memory_tracker
        current = tracker.get_memory_stats(session_id)
        if int(current.get("message_count", 0) or 0) > 0:
            return
        source = Path(app.state.decisions_log)
        events = read_events_from_jsonl(source) if source.exists() else []
        messages: list[dict[str, Any]] = []
        for event in events:
            snapshot = getattr(event, "state_snapshot", {})
            if not isinstance(snapshot, dict):
                snapshot = {}
            sid = str(snapshot.get("session_id", "") or "")
            if sid != str(session_id):
                continue
            embedded = snapshot.get("messages")
            if isinstance(embedded, list):
                for item in embedded:
                    if isinstance(item, dict):
                        messages.append(item)
            prompt = snapshot.get("prompt", snapshot.get("input"))
            if isinstance(prompt, str) and prompt.strip():
                messages.append({"role": "user", "content": prompt})
            tool_name = str(getattr(event, "tool", "") or "").strip()
            if tool_name:
                messages.append({"role": "assistant", "content": f"tool:{tool_name}"})
        if messages:
            tracker.record(str(session_id), messages)

    def _build_request_inspection(request_id: str) -> dict[str, Any]:
        source = Path(app.state.decisions_log)
        events = read_events_from_jsonl(source) if source.exists() else []
        inspector = RequestInspector()
        inspection = inspector.inspect(request_id=request_id, decisions_log=events)
        if not inspection:
            return {}
        payload = dict(inspection)
        payload["blocking_phase"] = inspector.find_blocking_phase(inspection)
        payload["timeline"] = inspector.get_timeline(inspection)
        return payload

    def _build_current_stats_by_agent(since_hours: int = 24) -> dict[str, dict[str, float]]:
        source = Path(app.state.decisions_log)
        events = read_events_from_jsonl(source) if source.exists() else []
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(hours=max(1, int(since_hours)))

        rows: dict[str, dict[str, float]] = {}
        for event in events:
            agent_id = str(getattr(event, "agent_id", "") or "unknown")
            ts = _parse_health_ts(str(getattr(event, "timestamp", "") or ""))
            if ts is None or ts < cutoff:
                continue
            snapshot = getattr(event, "state_snapshot", {})
            if not isinstance(snapshot, dict):
                snapshot = {}
            item = rows.setdefault(
                agent_id,
                {
                    "count": 0.0,
                    "cost_sum": 0.0,
                    "tool_sum": 0.0,
                    "prompt_sum": 0.0,
                    "duration_sum": 0.0,
                    "error_sum": 0.0,
                    "cache_sum": 0.0,
                    "cache_count": 0.0,
                },
            )
            item["count"] += 1.0
            item["cost_sum"] += float(getattr(event, "cost", 0.0) or 0.0)
            item["tool_sum"] += 1.0 if str(getattr(event, "tool", "") or "").strip() else 0.0
            prompt_len = snapshot.get("prompt_length", snapshot.get("prompt_tokens", 0))
            item["prompt_sum"] += float(prompt_len or 0.0)
            duration_ms = snapshot.get("session_duration_ms")
            if duration_ms is None:
                duration_ms = float(getattr(event, "evaluation_duration_us", 0) or 0.0) / 1000.0
            item["duration_sum"] += float(duration_ms or 0.0)
            decision = str(getattr(event, "decision", "") or "").upper()
            item["error_sum"] += 1.0 if decision == "DENY" else 0.0
            cache = snapshot.get("cache_hit_rate")
            if isinstance(cache, int | float):
                item["cache_sum"] += float(cache)
                item["cache_count"] += 1.0

        out: dict[str, dict[str, float]] = {}
        for agent_id, agg in rows.items():
            count = max(1.0, float(agg.get("count", 0.0)))
            cache_count = float(agg.get("cache_count", 0.0))
            out[agent_id] = {
                "cost_per_request": float(agg.get("cost_sum", 0.0)) / count,
                "tool_call_frequency": float(agg.get("tool_sum", 0.0)) / count,
                "avg_prompt_length": float(agg.get("prompt_sum", 0.0)) / count,
                "session_duration_avg": float(agg.get("duration_sum", 0.0)) / count,
                "error_rate": float(agg.get("error_sum", 0.0)) / count,
                "cache_hit_rate": (
                    float(agg.get("cache_sum", 0.0)) / cache_count if cache_count > 0.0 else 0.0
                ),
            }
        return out

    def _refresh_anomaly_alerts() -> None:
        manager = app.state.anomaly_alerts
        current = _build_current_stats_by_agent(since_hours=24)
        for agent_id, stats in current.items():
            manager.check(agent_id, stats)

    def _build_search_payload(query: str, limit: int) -> dict[str, Any]:
        q = str(query or "").strip().lower()
        safe_limit = max(1, min(200, int(limit)))
        empty = {"query": q, "results": {"agents": [], "sessions": [], "threats": []}, "total": 0}
        if not q:
            return empty
        source = Path(app.state.decisions_log)
        events = read_events_from_jsonl(source) if source.exists() else []
        now = datetime.now(timezone.utc)

        agents_latest: dict[str, datetime] = {}
        sessions_latest: dict[str, dict[str, Any]] = {}
        threats: list[dict[str, Any]] = []

        for event in events:
            agent_id = str(getattr(event, "agent_id", "") or "unknown")
            timestamp_raw = str(getattr(event, "timestamp", "") or "")
            ts = _parse_health_ts(timestamp_raw)
            if ts is None:
                ts = now - timedelta(hours=24)

            snapshot = getattr(event, "state_snapshot", {})
            if not isinstance(snapshot, dict):
                snapshot = {}
            session_id = _extract_session_id(snapshot) or str(snapshot.get("session_id") or "__default__")

            if q in agent_id.lower():
                prev = agents_latest.get(agent_id)
                if prev is None or ts > prev:
                    agents_latest[agent_id] = ts

            if q in session_id.lower() or q in agent_id.lower():
                prev_s = sessions_latest.get(session_id)
                if prev_s is None or ts > prev_s["ts"]:
                    sessions_latest[session_id] = {"id": session_id, "agent": agent_id, "ts": ts}

            reasons = getattr(event, "reasons", [])
            reason_text = " ".join(str(item) for item in reasons) if isinstance(reasons, list) else str(reasons or "")
            decision = str(getattr(event, "decision", "") or "")
            threat_blob = f"{reason_text} {decision} {agent_id} {session_id}".lower()
            if decision.upper() == "DENY" and q in threat_blob:
                threat_type = "policy_violation"
                first_reason = reason_text.split(",")[0].strip() if reason_text else ""
                if ":" in first_reason:
                    threat_type = first_reason.split(":", 1)[0].strip() or threat_type
                elif first_reason:
                    threat_type = first_reason.split(" ", 1)[0].strip() or threat_type
                threats.append(
                    {
                        "type": threat_type,
                        "timestamp": timestamp_raw,
                        "agent": agent_id,
                    }
                )

        agents: list[dict[str, Any]] = []
        for agent_id, ts in sorted(agents_latest.items(), key=lambda item: item[0]):
            age = max(0.0, (now - ts).total_seconds())
            status = "offline"
            if age <= 60.0:
                status = "working"
            elif age <= 300.0:
                status = "idle"
            agents.append({"id": agent_id, "status": status})

        sessions = [
            {"id": row["id"], "agent": row["agent"]}
            for row in sorted(sessions_latest.values(), key=lambda item: item["ts"], reverse=True)
        ]
        threats = sorted(threats, key=lambda item: str(item.get("timestamp", "")), reverse=True)

        agents = agents[:safe_limit]
        sessions = sessions[:safe_limit]
        threats = threats[:safe_limit]
        total = len(agents) + len(sessions) + len(threats)
        return {"query": q, "results": {"agents": agents, "sessions": sessions, "threats": threats}, "total": total}

    def _default_rate_limit_per_minute(policy: dict[str, Any]) -> int:
        rules = policy.get("rules", [])
        if not isinstance(rules, list):
            return 60
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            value = rule.get("max_requests_per_minute")
            if isinstance(value, int) and value > 0:
                return value
        return 60

    def _build_rate_limit_status_payload() -> dict[str, Any]:
        tracker = app.state.tracker
        tracker.flush()
        path = Path(getattr(tracker, "persist_path", "") or "")
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(seconds=60)
        hour_start = now - timedelta(hours=1)
        events_per_agent: dict[str, int] = defaultdict(int)
        minute_buckets: dict[str, int] = defaultdict(int)
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                row = line.strip()
                if not row:
                    continue
                try:
                    payload = json.loads(row)
                except json.JSONDecodeError:
                    continue
                if payload.get("event") != "rate":
                    continue
                agent_id = str(payload.get("agent_id") or "__global__")
                ts_raw = payload.get("timestamp")
                if not isinstance(ts_raw, str):
                    continue
                try:
                    ts = datetime.fromisoformat(ts_raw)
                except ValueError:
                    continue
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                else:
                    ts = ts.astimezone(timezone.utc)
                if ts >= window_start:
                    events_per_agent[agent_id] += 1
                if ts >= hour_start:
                    minute_key = ts.replace(second=0, microsecond=0).isoformat()
                    minute_buckets[minute_key] += 1

        _refresh_current_version()
        registry = app.state.current_version.registry
        agents_seen = set(events_per_agent.keys()) | set(registry.agents.keys())
        default_limit = _default_rate_limit_per_minute(app.state.current_version.policy)
        reset_at = (now.replace(second=0, microsecond=0) + timedelta(minutes=1)).isoformat()
        agent_payload: dict[str, Any] = {}
        for agent_id in sorted(agents_seen):
            identity = registry.agents.get(agent_id)
            limit = (
                int(identity.rate_limit_per_minute)
                if identity is not None and isinstance(identity.rate_limit_per_minute, int) and identity.rate_limit_per_minute > 0
                else default_limit
            )
            used = int(events_per_agent.get(agent_id, 0))
            percent = (used / float(limit) * 100.0) if limit > 0 else 0.0
            status = "ok"
            if percent >= 100.0:
                status = "throttled"
            elif percent >= 80.0:
                status = "warning"
            agent_payload[agent_id] = {
                "requests_this_minute": used,
                "limit_per_minute": int(limit),
                "percent_used": round(percent, 2),
                "status": status,
                "reset_at": reset_at,
            }

        global_requests = sum(events_per_agent.values())
        peak_this_hour = max(minute_buckets.values()) if minute_buckets else 0
        return {
            "agents": agent_payload,
            "global": {
                "requests_this_minute": int(global_requests),
                "peak_this_hour": int(peak_this_hour),
            },
        }

    def _build_agent_graph_model() -> AgentCollaborationGraph:
        graph = AgentCollaborationGraph()
        _refresh_current_version()
        for agent_id in sorted(app.state.current_version.registry.agents.keys()):
            graph.record_agent(agent_id, requests=0, cost=0.0)
        source = Path(app.state.decisions_log)
        if not source.exists():
            return graph
        for event in read_events_from_jsonl(source):
            actor = str(getattr(event, "agent_id", "") or "").strip()
            raw_cost = getattr(event, "cost", 0.0)
            try:
                cost = float(raw_cost)
            except (TypeError, ValueError):
                cost = 0.0
            if actor:
                graph.record_agent(actor, requests=1, cost=cost)
            snapshot = event.state_snapshot if isinstance(event.state_snapshot, dict) else {}
            interaction_type = (
                str(snapshot.get("interaction_type")).strip()
                if isinstance(snapshot.get("interaction_type"), str) and str(snapshot.get("interaction_type")).strip()
                else "context_share"
            )
            targets: list[str] = []
            for key in (
                "to_agent",
                "target_agent",
                "called_agent",
                "peer_agent",
                "collaborator",
                "interaction_with",
            ):
                value = snapshot.get(key)
                if isinstance(value, str) and value.strip():
                    targets.append(value.strip())
            shared_with = snapshot.get("shared_with")
            if isinstance(shared_with, list):
                for value in shared_with:
                    if isinstance(value, str) and value.strip():
                        targets.append(value.strip())
            if actor:
                for target in targets:
                    if target and target != actor:
                        graph.record_interaction(actor, target, interaction_type=interaction_type)
        return graph

    def _default_alert_metrics() -> dict[str, Any]:
        stats = metrics.snapshot()
        cache_hit = _cache_hit_rate_from_metrics(stats)
        source = Path(app.state.decisions_log)
        events = read_events_from_jsonl(source) if source.exists() else []
        now = datetime.now(timezone.utc)
        day_ago = now - timedelta(hours=24)
        cost_today = 0.0
        blocked_count = 0
        loop_count = 0
        for event in events:
            ts = _parse_health_ts(str(getattr(event, "timestamp", "") or ""))
            if ts is None or ts < day_ago:
                continue
            cost_today += float(getattr(event, "cost", 0.0) or 0.0)
            reasons = getattr(event, "reasons", [])
            decision = str(getattr(event, "decision", "") or "").upper()
            if decision == "DENY":
                blocked_count += 1
            if isinstance(reasons, list):
                joined = " ".join(str(item) for item in reasons).lower()
                if "loop" in joined:
                    loop_count += 1
        audit = _audit_engine()
        stats_1h = audit.stats(AuditQuery(since_hours=1, limit=1_000_000))
        return {
            "cost_today": round(cost_today, 6),
            "blocked_count": int(blocked_count),
            "cache_hit_rate": float(cache_hit),
            "error_rate": float(stats_1h.deny_rate),
            "active_agents": int(stats_1h.unique_agents),
            "loop_count": int(loop_count),
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
        if _is_protected_api_request(request):
            client_id = _client_id_from_request(request)
            limit_result = app.state.api_limiter.check(client_id)
            if not bool(limit_result.get("allowed", False)):
                retry_after = int(limit_result.get("retry_after") or 1)
                app.state.api_limiter.note_blocked(client_id)
                return JSONResponse(
                    status_code=429,
                    headers={"Retry-After": str(max(1, retry_after))},
                    content={"error": "rate_limit_exceeded"},
                )
            app.state.api_limiter.record(client_id)
            request.state.rate_limit_client_id = client_id
        trace = TraceContext.from_headers(dict(request.headers))
        request.state.trace_context = trace
        response = await call_next(request)
        if _is_protected_api_request(request):
            client_id = str(getattr(request.state, "rate_limit_client_id", "") or _client_id_from_request(request))
            limit_status = app.state.api_limiter.check(client_id)
            response.headers["X-RateLimit-Remaining"] = str(int(limit_status.get("remaining", 0) or 0))
            reset_at = limit_status.get("reset_at")
            if isinstance(reset_at, str) and reset_at:
                response.headers["X-RateLimit-Reset"] = reset_at
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

    @app.post("/api/v1/policy/simulate-impact")
    def policy_simulate_impact(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        current_policy = payload.get("current_policy", {})
        new_policy = payload.get("new_policy", {})
        sample_requests = payload.get("sample_requests", [])
        if not isinstance(current_policy, dict) or not isinstance(new_policy, dict):
            raise HTTPException(status_code=400, detail={"error": "current_policy and new_policy must be objects"})
        if not isinstance(sample_requests, list):
            raise HTTPException(status_code=400, detail={"error": "sample_requests must be a list"})
        return app.state.policy_impact_analyzer.simulate(current_policy, new_policy, sample_requests)

    @app.get("/api/v1/policy/impact-stats")
    def policy_impact_stats(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.policy_impact_analyzer.get_stats()

    @app.post("/api/v1/explain/decision")
    def explain_decision(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        return app.state.request_explainer.explain(payload)

    @app.post("/api/v1/explain/session")
    def explain_session(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        decisions = payload.get("decisions", [])
        if not isinstance(decisions, list):
            raise HTTPException(status_code=400, detail={"error": "decisions must be a list"})
        return app.state.request_explainer.explain_session(decisions)

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

    @app.get("/api/v1/sessions/{session_id}/replay")
    def replay_session_endpoint(
        session_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        replayer = SessionReplay(app.state.decisions_log)
        result = replayer.replay(session_id=session_id, policy=app.state.current_version.policy)
        return asdict(result)

    @app.post("/api/v1/sessions/{session_id}/replay")
    def replay_session_with_policy_endpoint(
        session_id: str,
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        policy = body.get("policy") if isinstance(body, dict) else None
        effective_policy = policy if isinstance(policy, dict) else (body if isinstance(body, dict) else None)
        replayer = SessionReplay(app.state.decisions_log)
        result = replayer.replay(session_id=session_id, policy=effective_policy)
        return asdict(result)

    @app.get("/api/v1/session-groups")
    def session_groups_list(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return {"groups": app.state.session_groups.list_groups()}

    @app.post("/api/v1/session-groups")
    def session_groups_create(
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        name = body.get("name") if isinstance(body, dict) else None
        description = body.get("description", "") if isinstance(body, dict) else ""
        if not isinstance(name, str) or not name.strip():
            raise HTTPException(status_code=400, detail={"error": "name is required"})
        return app.state.session_groups.create_group(name=name.strip(), description=str(description or ""))

    @app.get("/api/v1/session-groups/{group_id}")
    def session_groups_get(
        group_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        source = Path(app.state.decisions_log)
        events = read_events_from_jsonl(source) if source.exists() else []
        row = app.state.session_groups.get_group_stats(group_id, events)
        if not row:
            raise HTTPException(status_code=404, detail={"error": "group not found"})
        return row

    @app.post("/api/v1/session-groups/{group_id}/sessions")
    def session_groups_add_session(
        group_id: str,
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        session_id = body.get("session_id") if isinstance(body, dict) else None
        if not isinstance(session_id, str) or not session_id.strip():
            raise HTTPException(status_code=400, detail={"error": "session_id is required"})
        ok = app.state.session_groups.add_session(group_id, session_id.strip())
        if not ok:
            raise HTTPException(status_code=404, detail={"error": "group not found"})
        return {"ok": True, "group_id": group_id, "session_id": session_id.strip()}

    @app.delete("/api/v1/session-groups/{group_id}/sessions/{session_id}")
    def session_groups_remove_session(
        group_id: str,
        session_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        ok = app.state.session_groups.remove_session(group_id, session_id)
        if not ok:
            raise HTTPException(status_code=404, detail={"error": "group or session not found"})
        return {"ok": True, "group_id": group_id, "session_id": session_id}

    @app.delete("/api/v1/session-groups/{group_id}")
    def session_groups_delete(
        group_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        ok = app.state.session_groups.delete_group(group_id)
        if not ok:
            raise HTTPException(status_code=404, detail={"error": "group not found"})
        return {"ok": True, "group_id": group_id}

    @app.post("/api/v1/compliance/check-policy")
    def compliance_check_policy(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        candidate = payload.get("policy")
        if not isinstance(candidate, dict):
            candidate = app.state.current_version.policy
        return app.state.compliance_checker.check_policy(candidate)

    @app.post("/api/v1/compliance/check-request")
    def compliance_check_request(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        request_payload = payload.get("request") if isinstance(payload.get("request"), dict) else payload
        candidate = payload.get("policy")
        if not isinstance(candidate, dict):
            candidate = app.state.current_version.policy
        return app.state.compliance_checker.check_request(request_payload, candidate)

    @app.get("/api/v1/compliance/certificate")
    def compliance_certificate(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        result = app.state.compliance_checker.check_policy(app.state.current_version.policy)
        return {
            "compliant": bool(result.get("compliant", False)),
            "score": float(result.get("score", 0.0)),
            "certificate": result.get("certificate"),
        }

    @app.get("/api/v1/kb/search")
    def kb_search(q: str = "", authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        results = app.state.knowledge_base.search(q)
        return {"query": q, "results": results, "total": len(results)}

    @app.get("/api/v1/kb/articles")
    def kb_articles(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        rows = [
            article
            for article in (
                app.state.knowledge_base.get_article(article_id)
                for article_id in sorted(app.state.knowledge_base._articles.keys())
            )
            if isinstance(article, dict)
        ]
        return {"articles": rows, "total": len(rows)}

    @app.get("/api/v1/kb/articles/{article_id}")
    def kb_article(article_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        row = app.state.knowledge_base.get_article(article_id)
        if row is None:
            raise HTTPException(status_code=404, detail={"error": "article not found"})
        return row

    @app.get("/api/v1/kb/tags/{tag}")
    def kb_by_tag(tag: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        rows = app.state.knowledge_base.list_by_tag(tag)
        return {"tag": tag, "articles": rows, "total": len(rows)}

    @app.post("/api/v1/kb/suggest-for-error")
    def kb_suggest_for_error(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        message = str(payload.get("error_message", payload.get("error", "")) or "")
        rows = app.state.knowledge_base.suggest_for_error(message)
        return {"error_message": message, "suggestions": rows, "total": len(rows)}

    @app.post("/api/v1/par/observe")
    def par_observe(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        app.state.par_reasoner.observe(payload)
        return {"ok": True, "observations": int(app.state.par_reasoner.get_stats().get("observations", 0))}

    @app.post("/api/v1/par/abduce")
    def par_abduce(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        return app.state.par_reasoner.abduce(payload)

    @app.get("/api/v1/par/causal-graph")
    def par_causal_graph(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.par_reasoner.get_causal_graph()

    @app.get("/api/v1/par/stats")
    def par_stats(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.par_reasoner.get_stats()

    @app.post("/api/v1/immune/expose")
    def immune_expose(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        threat_pattern = str(payload.get("threat_pattern", "") or "")
        severity = payload.get("severity", 0.5)
        if not threat_pattern:
            raise HTTPException(status_code=400, detail={"error": "threat_pattern is required"})
        if not isinstance(severity, int | float):
            raise HTTPException(status_code=400, detail={"error": "severity must be numeric"})
        return app.state.immune_memory.expose(threat_pattern=threat_pattern, severity=float(severity))

    @app.post("/api/v1/immune/recall")
    def immune_recall(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        threat_pattern = str(payload.get("threat_pattern", "") or "")
        if not threat_pattern:
            raise HTTPException(status_code=400, detail={"error": "threat_pattern is required"})
        row = app.state.immune_memory.recall(threat_pattern)
        if row is None:
            return {"found": False, "memory": None}
        return {"found": True, "memory": row}

    @app.get("/api/v1/immune/stats")
    def immune_stats(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.immune_memory.get_memory_stats()

    @app.post("/api/v1/homeostasis/measure")
    def homeostasis_measure(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        cqs = payload.get("cqs")
        if not isinstance(cqs, int | float):
            raise HTTPException(status_code=400, detail={"error": "cqs must be numeric"})
        return app.state.homeostasis.measure(float(cqs))

    @app.get("/api/v1/homeostasis/stats")
    def homeostasis_stats(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.homeostasis.get_equilibrium_stats()

    @app.post("/api/v1/threshold/feedback")
    def threshold_feedback(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        detector = str(payload.get("detector", "") or "").strip()
        predicted = payload.get("predicted")
        actual = payload.get("actual")
        if not detector:
            raise HTTPException(status_code=400, detail={"error": "detector is required"})
        if not isinstance(predicted, bool) or not isinstance(actual, bool):
            raise HTTPException(status_code=400, detail={"error": "predicted and actual must be boolean"})
        app.state.adaptive_threshold.record_feedback(detector=detector, predicted=predicted, actual=actual)
        return {"ok": True, "detector": detector}

    @app.post("/api/v1/threshold/adapt/{detector}")
    def threshold_adapt(
        detector: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.adaptive_threshold.adapt(detector)

    @app.get("/api/v1/threshold/stats")
    def threshold_stats(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.adaptive_threshold.get_stats()

    @app.get("/api/v1/threshold/{detector}")
    def threshold_get(detector: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        value = app.state.adaptive_threshold.get_threshold(detector)
        return {"detector": detector, "threshold": round(float(value), 4)}

    @app.post("/api/v1/group-selection/register")
    def group_selection_register(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        agent_id = str(payload.get("agent_id", "") or "").strip()
        group_id = str(payload.get("group_id", "") or "").strip()
        if not agent_id or not group_id:
            raise HTTPException(status_code=400, detail={"error": "agent_id and group_id are required"})
        app.state.group_selection.register_agent(agent_id=agent_id, group_id=group_id)
        return {"ok": True, "agent_id": agent_id, "group_id": group_id}

    @app.post("/api/v1/group-selection/interaction")
    def group_selection_interaction(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        agent_id = str(payload.get("agent_id", "") or "").strip()
        if not agent_id:
            raise HTTPException(status_code=400, detail={"error": "agent_id is required"})
        cooperative = bool(payload.get("cooperative", True))
        try:
            outcome = float(payload.get("outcome", 0.0))
        except (TypeError, ValueError) as error:
            raise HTTPException(status_code=400, detail={"error": "outcome must be numeric"}) from error
        result = app.state.group_selection.record_interaction(
            agent_id=agent_id,
            cooperative=cooperative,
            outcome=outcome,
        )
        if "error" in result:
            raise HTTPException(status_code=404, detail=result)
        return result

    @app.get("/api/v1/group-selection/group/{group_id}")
    def group_selection_group(
        group_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.group_selection.get_group_fitness(group_id)

    @app.get("/api/v1/group-selection/fittest")
    def group_selection_fittest(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        row = app.state.group_selection.get_fittest_group()
        if row is None:
            return {"group": None}
        return {"group": row}

    @app.get("/api/v1/group-selection/stats")
    def group_selection_stats(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.group_selection.get_stats()

    @app.get("/api/v1/quorum/status")
    def quorum_status(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.quorum_sensor.get_stats()

    @app.get("/api/v1/quorum/active")
    def quorum_active(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        rows = app.state.quorum_sensor.detect_quorum()
        return {"quorums": rows, "total": len(rows)}

    @app.post("/api/v1/quorum/register-task")
    def quorum_register_task(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        agent_id = str(payload.get("agent_id", "") or "").strip()
        task_fingerprint = str(payload.get("task_fingerprint", "") or "").strip()
        if not agent_id or not task_fingerprint:
            raise HTTPException(status_code=400, detail={"error": "agent_id and task_fingerprint are required"})
        app.state.quorum_sensor.register_task(agent_id=agent_id, task_fingerprint=task_fingerprint)
        return {"ok": True, "active_quorums": len(app.state.quorum_sensor.detect_quorum())}

    @app.get("/api/v1/quorum/{quorum_id}/context")
    def quorum_get_context(
        quorum_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        row = app.state.quorum_sensor.get_shared_context(quorum_id)
        if row is None:
            raise HTTPException(status_code=404, detail={"error": "quorum not found"})
        return row

    @app.post("/api/v1/quorum/{quorum_id}/contribute")
    def quorum_contribute(
        quorum_id: str,
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        agent_id = str(payload.get("agent_id", "") or "").strip()
        context = payload.get("context")
        if not agent_id or not isinstance(context, dict):
            raise HTTPException(status_code=400, detail={"error": "agent_id and context are required"})
        ok = app.state.quorum_sensor.contribute_context(quorum_id=quorum_id, agent_id=agent_id, context=context)
        if not ok:
            raise HTTPException(status_code=404, detail={"error": "quorum not found"})
        return {"ok": True, "quorum_id": quorum_id, "agent_id": agent_id}

    @app.post("/api/v1/pid/update")
    def pid_update(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        current_value = payload.get("current_value")
        setpoint = payload.get("setpoint")
        if not isinstance(current_value, int | float) or not isinstance(setpoint, int | float):
            raise HTTPException(status_code=400, detail={"error": "current_value and setpoint must be numbers"})
        correction = app.state.pid_controller_v2.update(float(current_value), float(setpoint))
        return {"correction": float(correction)}

    @app.post("/api/v1/pid/check-ews")
    def pid_check_ews(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        values = payload.get("values", [])
        if not isinstance(values, list):
            raise HTTPException(status_code=400, detail={"error": "values must be a list"})
        return app.state.pid_controller_v2.check_ews_tau(values)

    @app.post("/api/v1/pid/check-zipf-drift")
    def pid_check_zipf(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        values = payload.get("token_frequencies", [])
        if not isinstance(values, list):
            raise HTTPException(status_code=400, detail={"error": "token_frequencies must be a list"})
        return app.state.pid_controller_v2.check_zipf_drift(values)

    @app.post("/api/v1/pid/check-latency")
    def pid_check_latency(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        values = payload.get("latencies_ms", [])
        if not isinstance(values, list):
            raise HTTPException(status_code=400, detail={"error": "latencies_ms must be a list"})
        return app.state.pid_controller_v2.check_latency_zscore(values)

    @app.get("/api/v1/pid/{session_id}/warning-level")
    def pid_warning_level(
        session_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        source = Path(app.state.decisions_log)
        events = read_events_from_jsonl(source) if source.exists() else []
        values: list[float] = []
        token_freq: list[int] = []
        latencies: list[float] = []
        for event in events:
            snapshot = getattr(event, "state_snapshot", {})
            if not isinstance(snapshot, dict):
                snapshot = {}
            sid = str(snapshot.get("session_id", "__global__"))
            if sid != session_id:
                continue
            prompt_len = snapshot.get("prompt_length", snapshot.get("prompt_tokens", 0))
            if isinstance(prompt_len, int | float):
                values.append(float(prompt_len))
                token_freq.append(int(max(1, int(prompt_len))))
            dur_us = getattr(event, "evaluation_duration_us", 0)
            if isinstance(dur_us, int | float):
                latencies.append(float(dur_us) / 1000.0)
        metrics = {"values": values[-30:], "token_frequencies": token_freq[-30:], "latencies_ms": latencies[-30:]}
        return app.state.pid_controller_v2.get_warning_level(session_id=session_id, metrics=metrics)

    @app.post("/api/v1/kalman/{session_id}/update")
    def kalman_update(
        session_id: str,
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        tracker = app.state.kalman_estimator
        tracker.predict(session_id)
        state = tracker.update(session_id, payload)
        return {"session_id": session_id, "state": state, "alert": tracker.get_alert_level(session_id)}

    @app.get("/api/v1/kalman/{session_id}/state")
    def kalman_state(
        session_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        tracker = app.state.kalman_estimator
        return {"session_id": session_id, "state": tracker.get_state(session_id)}

    @app.get("/api/v1/kalman/{session_id}/alert")
    def kalman_alert(
        session_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        tracker = app.state.kalman_estimator
        return {
            "session_id": session_id,
            "alert": tracker.get_alert_level(session_id),
            "state": tracker.get_state(session_id),
        }

    @app.get("/api/v1/kalman/sessions")
    def kalman_sessions(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        tracker = app.state.kalman_estimator
        sessions = tracker.get_all_sessions()
        return {"sessions": sessions, "total": len(sessions)}

    @app.get("/api/v1/otel/metrics")
    def otel_metrics(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.otel_bridge.export_otlp_json()

    @app.post("/api/v1/otel/flush")
    def otel_flush(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return {"flushed": int(app.state.otel_bridge.flush())}

    @app.get("/api/v1/otel/stats")
    def otel_stats(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.otel_bridge.get_stats()

    @app.post("/api/v1/kolmogorov/estimate")
    def kolmogorov_estimate(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        message = payload.get("message")
        if isinstance(message, dict):
            return app.state.kolmogorov_importance.compute_importance(message)
        text = payload.get("text")
        if isinstance(text, str):
            return app.state.kolmogorov_importance.compute_importance({"role": "user", "content": text})
        raise HTTPException(status_code=400, detail={"error": "message or text is required"})

    @app.post("/api/v1/kolmogorov/record-correlation")
    def kolmogorov_record_correlation(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        k_score = payload.get("k_score")
        uci_score = payload.get("uci_score")
        decision = payload.get("decision", "ALLOW")
        if not isinstance(k_score, int | float) or not isinstance(uci_score, int | float):
            raise HTTPException(status_code=400, detail={"error": "k_score and uci_score must be numbers"})
        app.state.kolmogorov_importance.record_correlation(float(k_score), float(uci_score), str(decision))
        return app.state.kolmogorov_importance.get_stats()

    @app.get("/api/v1/kolmogorov/stats")
    def kolmogorov_stats(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.kolmogorov_importance.get_stats()

    @app.get("/api/v1/kolmogorov/rho")
    def kolmogorov_rho(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return {"rho": app.state.kolmogorov_importance.compute_rho()}

    @app.get("/api/v1/nlce/metrics")
    def nlce_metrics(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        active_modules = [
            name
            for name in (
                "quorum_sensor",
                "pid_controller_v2",
                "kalman_estimator",
                "kolmogorov_importance",
                "relevance_scorer",
                "par_reasoning",
                "criticality_controller",
                "hgt_protocol",
                "keystone_detector",
                "token_yield",
                "fleet_coordinator",
            )
            if hasattr(app.state, name)
        ]
        pid_state = app.state.pid_controller_v2.get_warning_level(
            session_id="__global__",
            metrics={"values": [], "token_frequencies": [], "latencies_ms": []},
        )
        return {
            "version": "NLCE v2.0",
            "confirmed_results": {
                "zipf_alpha": 1.672,
                "zipf_r2": 0.980,
                "n_star": 16,
                "proxy_overhead": 0.008,
                "context_collapse_factor": 12,
                "retry_reduction": 3.52,
            },
            "pipeline_state": {
                "phases": 17,
                "active_modules": active_modules,
                "crystallinity_psi": float(0.92),
                "current_phase": "stabilized",
            },
            "token_yield": app.state.token_yield.get_global_stats(),
            "uci_stats": app.state.kolmogorov_importance.get_stats(),
            "pid_warning_level": str(pid_state.get("level", "green")),
        }

    @app.get("/api/v1/nlce/impossibility-theorems")
    def nlce_impossibility_theorems(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return {
            "theorems": [
                {"id": "T1", "statement": "SDK cannot compute fleet-level metrics without O(n^2) overhead"},
                {"id": "T2", "statement": "Compromised agent cannot detect own compromise"},
                {
                    "id": "T3",
                    "statement": "Single-agent trace cannot recover cross-agent causal graph",
                },
                {"id": "T4", "statement": "Local policy checks cannot guarantee global coherence under partition"},
                {"id": "T5", "statement": "PAR theorem: abductive mode when N < 2^k"},
            ]
        }

    @app.post("/api/v1/relevance/score")
    def relevance_score(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        message = payload.get("message")
        context = payload.get("context", [])
        if not isinstance(message, dict):
            raise HTTPException(status_code=400, detail={"error": "message is required"})
        if not isinstance(context, list):
            raise HTTPException(status_code=400, detail={"error": "context must be a list"})
        return app.state.relevance_scorer.score(message, context)

    @app.post("/api/v1/relevance/rank")
    def relevance_rank(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        messages = payload.get("messages", [])
        if not isinstance(messages, list):
            raise HTTPException(status_code=400, detail={"error": "messages must be a list"})
        rows = app.state.relevance_scorer.rank_messages(messages)
        return {"messages": rows, "total": len(rows)}

    @app.get("/api/v1/relevance/stats")
    def relevance_stats(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.relevance_scorer.get_stats()

    @app.post("/api/v1/vickrey/bid")
    def vickrey_bid(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        agent_id = str(payload.get("agent_id", "") or "").strip()
        bid_tokens = payload.get("bid_tokens", 0)
        task_priority = str(payload.get("task_priority", "medium") or "medium")
        if not agent_id or not isinstance(bid_tokens, int | float):
            raise HTTPException(status_code=400, detail={"error": "agent_id and bid_tokens are required"})
        return app.state.vickrey_allocator.submit_bid(
            agent_id=agent_id,
            bid_tokens=int(bid_tokens),
            task_priority=task_priority,
        )

    @app.post("/api/v1/vickrey/auction")
    def vickrey_auction(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.vickrey_allocator.run_auction()

    @app.get("/api/v1/vickrey/stats")
    def vickrey_stats(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.vickrey_allocator.get_auction_stats()

    @app.get("/api/v1/vickrey/{agent_id}/allocation")
    def vickrey_allocation(
        agent_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return {"agent_id": agent_id, "allocation": app.state.vickrey_allocator.get_allocation(agent_id)}

    @app.post("/api/v1/mrac/update")
    def mrac_update(
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        agent_id = str(body.get("agent_id", "")).strip()
        if not agent_id:
            raise HTTPException(status_code=400, detail={"error": "agent_id is required"})
        try:
            actual_cqs = float(body.get("actual_cqs", 0.0))
        except (TypeError, ValueError) as error:
            raise HTTPException(status_code=400, detail={"error": "actual_cqs must be numeric"}) from error
        return app.state.mrac_controller.update(agent_id=agent_id, actual_cqs=actual_cqs)

    @app.get("/api/v1/mrac/agents")
    def mrac_agents(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        rows = app.state.mrac_controller.get_all_agents()
        return {"agents": rows, "total": len(rows)}

    @app.get("/api/v1/mrac/stats")
    def mrac_stats(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.mrac_controller.get_stats()

    @app.get("/api/v1/mrac/{agent_id}/gains")
    def mrac_gains(
        agent_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return {"agent_id": agent_id, **app.state.mrac_controller.get_gains(agent_id)}

    @app.post("/api/v1/keystone/record-uci")
    def keystone_record_uci(
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        agent_id = str(body.get("agent_id", "")).strip()
        if not agent_id:
            raise HTTPException(status_code=400, detail={"error": "agent_id is required"})
        try:
            uci_score = float(body.get("uci_score", 0.0))
        except (TypeError, ValueError) as error:
            raise HTTPException(status_code=400, detail={"error": "uci_score must be numeric"}) from error
        app.state.keystone_detector.record_uci(agent_id=agent_id, uci_score=uci_score)
        return {"ok": True, "agent_id": agent_id}

    @app.get("/api/v1/keystone/all")
    def keystone_all(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        rows = app.state.keystone_detector.get_all_keystones()
        return {"keystones": rows, "total": len(rows)}

    @app.get("/api/v1/keystone/{agent_id}/score")
    def keystone_score(
        agent_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.keystone_detector.compute_keystone_score(agent_id)

    @app.get("/api/v1/keystone/{agent_id}/cascade")
    def keystone_cascade(
        agent_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.keystone_detector.get_trophic_cascade(agent_id)

    @app.post("/api/v1/criticality/control")
    def criticality_control(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        psi = payload.get("psi")
        if not isinstance(psi, int | float):
            raise HTTPException(status_code=400, detail={"error": "psi must be numeric"})
        return app.state.criticality_controller.compute_control(float(psi))

    @app.post("/api/v1/criticality/mrac-update")
    def criticality_mrac_update(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        psi_actual = payload.get("psi_actual")
        psi_predicted = payload.get("psi_predicted")
        if not isinstance(psi_actual, int | float) or not isinstance(psi_predicted, int | float):
            raise HTTPException(status_code=400, detail={"error": "psi_actual and psi_predicted must be numeric"})
        updated = app.state.criticality_controller.mrac_update(float(psi_actual), float(psi_predicted))
        return {"adaptive_gain": round(float(updated), 4)}

    @app.get("/api/v1/criticality/stats")
    def criticality_stats(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.criticality_controller.get_stats()

    @app.post("/api/v1/arc/certify/{agent_id}")
    def arc_certify(
        agent_id: str,
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        policy = app.state.current_version.policy if isinstance(app.state.current_version.policy, dict) else {}
        readiness_cfg = policy.get("agent_readiness", {}) if isinstance(policy.get("agent_readiness"), dict) else {}
        metrics_store = readiness_cfg.get("metrics", {}) if isinstance(readiness_cfg.get("metrics"), dict) else {}
        policy_metrics = metrics_store.get(agent_id, {}) if isinstance(metrics_store.get(agent_id), dict) else {}
        provided_metrics = payload.get("metrics", {})
        merged_metrics = dict(policy_metrics)
        if isinstance(provided_metrics, dict):
            merged_metrics.update(provided_metrics)
        return app.state.arc_readiness.certify(agent_id=agent_id, metrics=merged_metrics, policy=policy)

    @app.get("/api/v1/arc/{agent_id}/certificate")
    def arc_certificate(
        agent_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        matches = [item for item in app.state.arc_readiness.list_certificates() if item.get("agent_id") == agent_id]
        if not matches:
            raise HTTPException(status_code=404, detail={"error": "certificate not found"})
        return matches[-1]

    @app.get("/api/v1/arc/certificates")
    def arc_certificates(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        rows = app.state.arc_readiness.list_certificates()
        return {"certificates": rows, "total": len(rows)}

    @app.get("/api/v1/casura/incidents/stats")
    def casura_incident_stats(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.casura_db.get_stats()

    @app.post("/api/v1/casura/incidents/search")
    def casura_incident_search(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        query = str(payload.get("query", "") or "")
        filters = payload.get("filters", {})
        rows = app.state.casura_db.search(query=query, filters=filters if isinstance(filters, dict) else None)
        return {"incidents": rows, "total": len(rows)}

    @app.get("/api/v1/casura/incidents")
    def casura_incidents(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        rows = app.state.casura_db.search(query="")
        return {"incidents": rows, "total": len(rows)}

    @app.post("/api/v1/casura/incidents")
    def casura_create_incident(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        return app.state.casura_db.create_incident(payload)

    @app.get("/api/v1/casura/incidents/{incident_id}")
    def casura_get_incident(
        incident_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        item = app.state.casura_db._incidents.get(incident_id)
        if not isinstance(item, dict):
            raise HTTPException(status_code=404, detail={"error": "incident not found"})
        return dict(item)

    @app.get("/api/v1/casura/intelligence/patterns")
    def casura_intel_patterns(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        incidents = app.state.casura_db.search(query="")
        return app.state.casura_intel.analyze_patterns(incidents)

    @app.get("/api/v1/casura/intelligence/mitre-coverage")
    def casura_mitre_coverage(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        incidents = app.state.casura_db.search(query="")
        return app.state.casura_intel.get_mitre_coverage(incidents)

    @app.get("/api/v1/aabb/leaderboard")
    def aabb_leaderboard(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        rows = app.state.aabb_benchmark.get_leaderboard()
        return {"leaderboard": rows, "total": len(rows)}

    @app.post("/api/v1/aabb/run/{agent_id}")
    def aabb_run(
        agent_id: str,
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        proxy_url = str(payload.get("proxy_url", "http://localhost:8080") or "http://localhost:8080")
        return app.state.aabb_benchmark.run_suite(agent_id=agent_id, proxy_url=proxy_url)

    @app.get("/api/v1/aabb/stats")
    def aabb_stats(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.aabb_benchmark.get_benchmark_stats()

    @app.get("/api/v1/aabb/compare/{agent_a}/{agent_b}")
    def aabb_compare(
        agent_a: str,
        agent_b: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.aabb_benchmark.compare_agents(agent_a, agent_b)

    @app.post("/api/v1/compare/metric")
    def compare_record_metric(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        agent_id = str(payload.get("agent_id", "") or "").strip()
        metric = str(payload.get("metric", "") or "").strip()
        value = payload.get("value")
        if not agent_id or not metric or not isinstance(value, int | float):
            raise HTTPException(status_code=400, detail={"error": "agent_id, metric, value are required"})
        app.state.agent_comparer.record_metric(agent_id=agent_id, metric=metric, value=float(value))
        return {"ok": True, "stats": app.state.agent_comparer.get_stats()}

    @app.get("/api/v1/compare/ranking")
    def compare_ranking(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        ranking = app.state.agent_comparer.rank_all()
        return {"ranking": ranking, "total": len(ranking)}

    @app.get("/api/v1/compare/{agent_a}/{agent_b}")
    def compare_agents(
        agent_a: str,
        agent_b: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.agent_comparer.compare(agent_a=agent_a, agent_b=agent_b)

    @app.post("/api/v1/report-card/{agent_id}")
    def report_card_generate(
        agent_id: str,
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        return app.state.agent_report_card.generate(agent_id=agent_id, metrics=payload)

    @app.get("/api/v1/report-card/{agent_id}")
    def report_card_get(
        agent_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        card = app.state.agent_report_card._cards.get(agent_id)
        if not isinstance(card, dict):
            raise HTTPException(status_code=404, detail={"error": "report card not found"})
        return card

    @app.get("/api/v1/report-card/compare/{agent_a}/{agent_b}")
    def report_card_compare(
        agent_a: str,
        agent_b: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        result = app.state.agent_report_card.compare_grades(agent_a=agent_a, agent_b=agent_b)
        if "error" in result:
            raise HTTPException(status_code=404, detail=result)
        return result

    @app.post("/api/v1/timeline/{session_id}/record")
    def timeline_record(
        session_id: str,
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        app.state.context_timeline.record(session_id=session_id, snapshot=payload)
        timeline = app.state.context_timeline.get_timeline(session_id)
        return {"ok": True, "session_id": session_id, "points": len(timeline)}

    @app.get("/api/v1/timeline/{session_id}")
    def timeline_get(
        session_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        points = app.state.context_timeline.get_timeline(session_id)
        return {"session_id": session_id, "timeline": points, "points": len(points)}

    @app.get("/api/v1/timeline/{session_id}/phases")
    def timeline_phases(
        session_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        transitions = app.state.context_timeline.get_phase_transitions(session_id)
        return {"session_id": session_id, "transitions": transitions, "count": len(transitions)}

    @app.get("/api/v1/timeline/{session_id}/summary")
    def timeline_summary(
        session_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.context_timeline.summarize(session_id)

    @app.post("/api/v1/persona/baseline")
    def persona_baseline(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        identity_files = payload.get("identity_files")
        files = [str(item) for item in identity_files if isinstance(item, str) and item.strip()] if isinstance(identity_files, list) else []
        return app.state.persona_guardian.initialize_baseline(files)

    @app.post("/api/v1/persona/check")
    def persona_check(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        identity_files = payload.get("identity_files")
        files = [str(item) for item in identity_files if isinstance(item, str) and item.strip()] if isinstance(identity_files, list) else []
        findings = app.state.persona_guardian.check_identity_files(files)
        alert = app.state.persona_guardian.check_zenity_pattern()
        return {"findings": findings, "count": len(findings), "alert": alert}

    @app.post("/api/v1/persona/cron-event")
    def persona_cron_event(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        cron_expression = str(payload.get("cron_expression", "") or "").strip()
        source = str(payload.get("source", "unknown") or "unknown").strip() or "unknown"
        if not cron_expression:
            raise HTTPException(status_code=400, detail={"error": "cron_expression is required"})
        event = app.state.persona_guardian.record_cron_event(cron_expression=cron_expression, source=source)
        alert = app.state.persona_guardian.check_zenity_pattern()
        return {"event": event, "alert": alert}

    @app.get("/api/v1/persona/zenity-check")
    def persona_zenity_check(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        alert = app.state.persona_guardian.check_zenity_pattern()
        return {"detected": alert is not None, "alert": alert}

    @app.get("/api/v1/persona/stats")
    def persona_stats(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.persona_guardian.get_stats()

    @app.post("/api/v1/persona/restore/{file_path:path}")
    def persona_restore(
        file_path: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.persona_guardian.auto_restore(str(file_path or ""))

    @app.get("/api/v1/persona/steganography")
    def persona_steganography(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        results = app.state.persona_guardian.scan_all_identity_files()
        return {"results": results, "count": len(results)}

    @app.post("/api/v1/persona/steganography/scan")
    def persona_steganography_scan(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        file_path = str(payload.get("file_path", "") or "").strip()
        if not file_path:
            raise HTTPException(status_code=400, detail={"error": "file_path is required"})
        return app.state.persona_guardian.scan_steganography(file_path)

    @app.post("/api/v1/are/slo")
    def are_define_slo(
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        name = str(body.get("name", "")).strip()
        sli = str(body.get("sli", "")).strip()
        target = body.get("target")
        window_days = body.get("window_days", 30)
        if not name or not sli or target is None:
            raise HTTPException(status_code=400, detail={"error": "name, sli, target are required"})
        try:
            row = app.state.are.define_slo(
                name=name,
                sli=sli,
                target=float(target),
                window_days=int(window_days),
            )
        except (ValueError, TypeError) as error:
            raise HTTPException(status_code=400, detail={"error": str(error)}) from error
        return {"slo": row}

    @app.post("/api/v1/are/sli/{slo_name}")
    def are_record_sli(
        slo_name: str,
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        if "value" not in body:
            raise HTTPException(status_code=400, detail={"error": "value is required"})
        try:
            app.state.are.record_sli(slo_name, float(body.get("value")))
        except KeyError as error:
            raise HTTPException(status_code=404, detail={"error": str(error)}) from error
        except (TypeError, ValueError) as error:
            raise HTTPException(status_code=400, detail={"error": str(error)}) from error
        return {"ok": True, "slo_name": slo_name}

    @app.get("/api/v1/are/budget/{slo_name}")
    def are_budget(
        slo_name: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        try:
            return app.state.are.get_error_budget(slo_name)
        except KeyError as error:
            raise HTTPException(status_code=404, detail={"error": str(error)}) from error

    @app.get("/api/v1/are/report")
    def are_report(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.are.get_reliability_report()

    @app.get("/api/v1/are/alerts")
    def are_alerts(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        report = app.state.are.get_reliability_report()
        alerts: list[dict[str, Any]] = []
        for row in report.get("slos", []):
            if not isinstance(row, dict):
                continue
            slo_name = str(row.get("slo_name", "")).strip()
            if not slo_name:
                continue
            alert = app.state.are.get_burn_rate_alert(slo_name)
            if isinstance(alert, dict):
                alerts.append(alert)
        return {"alerts": alerts, "count": len(alerts)}

    @app.get("/api/v1/competitive/latest")
    def competitive_latest(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        incidents = app.state.casura_db.search(query="")
        changes = app.state.competitive_monitor.detect_ecosystem_changes(
            incidents if isinstance(incidents, list) else []
        )
        leaderboard = app.state.aabb_benchmark.get_leaderboard()
        competitor_alerts: list[dict[str, Any]] = []
        if isinstance(leaderboard, list):
            for row in leaderboard[:5]:
                if not isinstance(row, dict):
                    continue
                agent_name = str(row.get("agent_id", "") or "")
                score = float(row.get("score", 0.0) or 0.0)
                if score >= 0.8:
                    competitor_alerts.append(
                        {
                            "event": "competitor_stars_spike",
                            "title": f"High-performing competitor signal: {agent_name}",
                            "severity": "medium",
                            "score": score,
                        }
                    )
        alerts = changes + competitor_alerts
        return {"alerts": alerts, "count": len(alerts)}

    @app.get("/api/v1/monitoring/parse-hn")
    async def monitoring_parse_hn(
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = await request.json() if request is not None else {}
        if not isinstance(payload, dict):
            payload = {}
        item = payload.get("item", {})
        if not isinstance(item, dict):
            raise HTTPException(status_code=400, detail={"error": "item must be an object"})
        parsed = app.state.social_parsers.parse_hn_item(item)
        app.state.monitoring_items.append(parsed)
        if len(app.state.monitoring_items) > 1000:
            app.state.monitoring_items = app.state.monitoring_items[-1000:]
        app.state.monitoring_opportunities = app.state.social_parsers.extract_opportunities(
            app.state.monitoring_items[-200:]
        )
        return {"parsed": parsed}

    @app.get("/api/v1/monitoring/opportunities")
    def monitoring_opportunities(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        rows = app.state.monitoring_opportunities[-20:]
        return {"opportunities": rows, "count": len(rows)}

    @app.get("/api/v1/monitoring/weekly-report")
    def monitoring_weekly_report(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        feed_items = app.state.monitoring_items[-200:]
        report = app.state.competitive_monitor.generate_weekly_report(
            {
                "competitors": {},
                "feed": feed_items,
            }
        )
        return report

    @app.get("/api/v1/weekly-report")
    def weekly_report_endpoint(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        blocked_requests = 0
        total_cost_usd = 0.0
        tracker = getattr(app.state, "tracker", None)
        if tracker is not None:
            blocked_requests = int(getattr(tracker, "blocked_requests", 0) or 0)
            total_cost_usd = float(getattr(tracker, "total_cost_usd", 0.0) or 0.0)
        compliance = app.state.compliance_checker.check_policy(app.state.current_version.policy)
        competitive = app.state.competitive_monitor.generate_weekly_report(
            {"competitors": {}, "feed": app.state.monitoring_items[-200:]}
        )
        arc_stats_fn = getattr(app.state.arc_readiness, "get_stats", None)
        arc_stats = arc_stats_fn() if callable(arc_stats_fn) else {}
        data = {
            "security": {
                "blocked": blocked_requests,
                "new_sigs": 0,
                "ari": float(app.state.red_queen.compute_arms_race_index().get("ari", 0.0) or 0.0),
            },
            "cost": {
                "cost": total_cost_usd,
                "savings": 0.0,
                "yield": float(getattr(app.state.token_yield, "yield_percent", 0.0) or 0.0),
            },
            "compliance": {
                "eu_score": float(compliance.get("score", 0.0) or 0.0),
                "arc_count": int(arc_stats.get("certified_agents", 0) or 0),
                "incidents": blocked_requests,
            },
            "competitive": {
                "threats": len(competitive.get("threats", [])) if isinstance(competitive.get("threats"), list) else 0,
                "opportunities": (
                    len(competitive.get("opportunities", []))
                    if isinstance(competitive.get("opportunities"), list)
                    else 0
                ),
            },
            "research": {
                "experiments": 0,
                "confirmed": 0,
            },
        }
        return app.state.weekly_report_generator.generate(data)

    @app.post("/api/v1/monitoring/score-relevance")
    def monitoring_score_relevance(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        text = str(payload.get("text", "") or "")
        score = app.state.social_parsers.score_relevance(text)
        return {"text": text, "relevance_score": score}

    @app.post("/api/v1/cost-of-freedom/calculate")
    def cost_of_freedom_calculate(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        result = app.state.cost_of_freedom.calculate(payload)
        return {
            **result,
            "summary": app.state.cost_of_freedom.get_summary_text(result),
        }

    @app.get("/api/v1/cost-of-freedom/benchmarks")
    def cost_of_freedom_benchmarks(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return {"benchmarks": dict(app.state.cost_of_freedom.benchmarks)}

    @app.post("/api/v1/red-queen/attack")
    def red_queen_attack_endpoint(
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        app.state.red_queen.record_attack(body if isinstance(body, dict) else {})
        return {"status": "recorded", "kind": "attack", "stats": app.state.red_queen.get_stats()}

    @app.post("/api/v1/red-queen/detection")
    def red_queen_detection_endpoint(
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        app.state.red_queen.record_detection(body if isinstance(body, dict) else {})
        return {"status": "recorded", "kind": "detection", "stats": app.state.red_queen.get_stats()}

    @app.get("/api/v1/red-queen/ari")
    def red_queen_ari_endpoint(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.red_queen.compute_arms_race_index()

    @app.get("/api/v1/red-queen/emerging-patterns")
    def red_queen_emerging_patterns_endpoint(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        patterns = app.state.red_queen.get_emerging_patterns()
        return {"patterns": patterns, "count": len(patterns)}

    @app.post("/api/v1/double-loop/error")
    def double_loop_error_endpoint(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        error_type = str(payload.get("error_type", "unknown") or "unknown")
        magnitude = payload.get("magnitude", 0.0)
        if not isinstance(magnitude, int | float):
            raise HTTPException(status_code=400, detail={"error": "magnitude must be numeric"})
        context = payload.get("context", {})
        app.state.double_loop.record_error(
            error_type=error_type,
            magnitude=float(magnitude),
            context=context if isinstance(context, dict) else {},
        )
        return {"status": "recorded", "error_type": error_type}

    @app.post("/api/v1/double-loop/adapt")
    def double_loop_adapt_endpoint(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        error_rate = payload.get("error_rate", 0.0)
        if not isinstance(error_rate, int | float):
            raise HTTPException(status_code=400, detail={"error": "error_rate must be numeric"})
        loop = app.state.double_loop.determine_loop(float(error_rate))
        if loop == "single":
            rule = str(payload.get("rule", "compression_aggressiveness") or "compression_aggressiveness")
            delta = payload.get("delta", 0.0)
            if not isinstance(delta, int | float):
                raise HTTPException(status_code=400, detail={"error": "delta must be numeric"})
            result = app.state.double_loop.single_loop_adapt(rule=rule, delta=float(delta))
            if "error" in result:
                raise HTTPException(status_code=400, detail=result)
            return {"loop": loop, "adaptation": result}
        if loop == "double":
            strategy = str(payload.get("new_strategy", "reframe_context_strategy") or "reframe_context_strategy")
            rationale = str(payload.get("rationale", "error rate above double-loop threshold") or "")
            return {
                "loop": loop,
                "adaptation": app.state.double_loop.double_loop_adapt(strategy, rationale),
            }
        return {"loop": "none", "adaptation": None}

    @app.get("/api/v1/double-loop/stats")
    def double_loop_stats_endpoint(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.double_loop.get_learning_stats()

    @app.get("/api/v1/double-loop/rules")
    def double_loop_rules_endpoint(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        stats = app.state.double_loop.get_learning_stats()
        return {"governing_rules": stats.get("governing_rules", {})}

    @app.post("/api/v1/complement/activate")
    def complement_activate_endpoint(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        threat_signal = payload.get("threat_signal", 0.0)
        if not isinstance(threat_signal, int | float):
            raise HTTPException(status_code=400, detail={"error": "threat_signal must be numeric"})
        threat_type = str(payload.get("threat_type", "unknown") or "unknown")
        return app.state.complement_cascade.activate(float(threat_signal), threat_type)

    @app.get("/api/v1/complement/stats")
    def complement_stats_endpoint(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.complement_cascade.get_cascade_stats()

    @app.get("/api/v1/ecosystem/summary")
    def ecosystem_summary(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        casura_stats = app.state.casura_db.get_stats()
        leaderboard = app.state.aabb_benchmark.get_leaderboard()
        are_payload = app.state.are.get_reliability_report()
        competitive_payload = competitive_latest(authorization)
        return {
            "casura": casura_stats,
            "aabb": {
                "leaderboard": leaderboard[:5] if isinstance(leaderboard, list) else [],
                "total": len(leaderboard) if isinstance(leaderboard, list) else 0,
            },
            "are": are_payload,
            "competitive": competitive_payload,
        }

    @app.post("/api/v1/channels/{channel}/event")
    def channels_record_event(
        channel: str,
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        event_type = str(payload.get("event_type", "") or "").strip().lower()
        if event_type not in {"inbound", "outbound"}:
            raise HTTPException(status_code=400, detail={"error": "event_type must be inbound or outbound"})
        metadata = payload.get("metadata", {})
        app.state.channel_monitor.record_event(
            channel=str(channel or "").strip().lower(),
            event_type=event_type,
            metadata=metadata if isinstance(metadata, dict) else {},
        )
        return {"ok": True, "channel": channel, "event_type": event_type}

    @app.get("/api/v1/channels/health")
    def channels_health(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.channel_monitor.check_health()

    @app.get("/api/v1/channels/stats")
    def channels_stats(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.channel_monitor.get_stats()

    @app.get("/api/v1/channels/{channel}/status")
    def channels_status(channel: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        payload = app.state.channel_monitor.get_channel_status(str(channel or "").strip().lower())
        if not payload:
            raise HTTPException(status_code=404, detail={"error": "unknown channel"})
        return payload

    @app.post("/api/v1/whatsapp/session")
    def whatsapp_register_session(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        session_id = str(payload.get("session_id", "") or "").strip()
        started_at_raw = payload.get("started_at")
        started_at = str(started_at_raw).strip() if isinstance(started_at_raw, str) and started_at_raw.strip() else None
        if not session_id:
            raise HTTPException(status_code=400, detail={"error": "session_id is required"})
        return app.state.whatsapp_expiry.register_session(session_id=session_id, started_at=started_at)

    @app.get("/api/v1/whatsapp/{session_id}/expiry")
    def whatsapp_session_expiry(
        session_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.whatsapp_expiry.check_expiry(session_id)

    @app.get("/api/v1/whatsapp/sessions/at-risk")
    def whatsapp_sessions_at_risk(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        sessions = app.state.whatsapp_expiry.get_sessions_needing_alert()
        return {"sessions": sessions, "count": len(sessions)}

    @app.get("/api/v1/whatsapp/stats")
    def whatsapp_stats(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.whatsapp_expiry.get_stats()

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

    @app.get("/api/v1/cache/warm/candidates")
    def cache_warm_candidates_endpoint(
        limit: int = 20,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        safe_limit = max(1, min(int(limit), 500))
        candidates = _cache_warm_candidates(safe_limit)
        return {"total": len(candidates), "candidates": candidates}

    @app.post("/api/v1/cache/warm")
    def cache_warm_endpoint(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        limit = payload.get("limit", 50)
        safe_limit = max(1, min(int(limit), 500))
        candidates = _cache_warm_candidates(safe_limit)
        report = app.state.cache_warmer.warm(candidates)
        return {
            **report,
            "candidates_considered": len(candidates),
            "cache_stats": app.state.semantic_cache.get_stats(),
        }

    @app.get("/api/v1/cache/warm/report")
    def cache_warm_report_endpoint(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return {
            **app.state.cache_warmer.get_warming_report(),
            "cache_stats": app.state.semantic_cache.get_stats(),
        }

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

    @app.get("/api/v1/agents/graph")
    def agents_graph(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return _build_agent_graph_model().get_graph()

    @app.get("/api/v1/agents/graph/stats")
    def agents_graph_stats(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return _build_agent_graph_model().get_stats()

    @app.get("/api/v1/agents/clusters")
    def agents_clusters(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return {"clusters": _build_agent_graph_model().get_clusters()}

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

    @app.get("/api/v1/scorecard/leaderboard")
    def get_scorecard_leaderboard(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        source = Path(app.state.decisions_log)
        events = read_events_from_jsonl(source) if source.exists() else []
        board = app.state.agent_scorecard.get_leaderboard(events)
        return {"leaderboard": board}

    @app.get("/api/v1/scorecard/all")
    def get_scorecard_all(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        cards = _build_scorecard_all_payload()
        return {"scorecards": cards}

    @app.get("/api/v1/scorecard/{agent_id}")
    def get_scorecard(
        agent_id: str,
        period: str = "7d",
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return _build_scorecard_payload(agent_id, period)

    @app.post("/api/v1/debug/request")
    def debug_request_endpoint(
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        request_payload = body.get("request") if isinstance(body.get("request"), dict) else body
        debugger = _build_pipeline_debugger()
        return debugger.debug_request(request_payload)

    @app.post("/api/v1/debug/explain")
    def debug_explain_endpoint(
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        debugger = _build_pipeline_debugger()
        decision = body.get("decision") if isinstance(body.get("decision"), dict) else {}
        if not decision:
            request_payload = body.get("request") if isinstance(body.get("request"), dict) else {}
            decision = debugger.debug_request(request_payload)
        return {"explanation": debugger.explain_decision(decision)}

    @app.post("/api/v1/debug/compare-policies")
    def debug_compare_policies_endpoint(
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        request_payload = body.get("request") if isinstance(body.get("request"), dict) else {}
        policy_a = body.get("policy_a") if isinstance(body.get("policy_a"), dict) else {}
        policy_b = body.get("policy_b") if isinstance(body.get("policy_b"), dict) else {}
        debugger = _build_pipeline_debugger()
        return debugger.compare_policies(request_payload, policy_a, policy_b)

    @app.post("/api/v1/intent/classify")
    def classify_intent_endpoint(
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        text = body.get("text", "")
        if not isinstance(text, str):
            text = str(text)
        return app.state.intent_classifier.classify(text)

    @app.post("/api/v1/intent/batch")
    def classify_intent_batch_endpoint(
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        messages = body.get("messages", [])
        if not isinstance(messages, list):
            messages = []
        classifications = app.state.intent_classifier.batch_classify(messages)
        return {
            "classifications": classifications,
            "session_risk": app.state.intent_classifier.get_session_risk(classifications),
        }

    @app.get("/api/v1/intent/stats")
    def intent_stats_endpoint(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.intent_classifier.get_stats()

    @app.post("/api/v1/response/analyze")
    def response_analyze_endpoint(
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body.get("response") if isinstance(body.get("response"), dict) else body
        return app.state.response_analyzer.analyze(payload if isinstance(payload, dict) else {})

    @app.post("/api/v1/response/check-leakage")
    def response_check_leakage_endpoint(
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body.get("response") if isinstance(body.get("response"), dict) else body
        response_payload = payload if isinstance(payload, dict) else {}
        return {"issues": app.state.response_analyzer.check_for_leakage(response_payload)}

    @app.post("/api/v1/response/check-hallucination")
    def response_check_hallucination_endpoint(
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body.get("response") if isinstance(body.get("response"), dict) else body
        response_payload = payload if isinstance(payload, dict) else {}
        return app.state.response_analyzer.check_for_hallucination_signals(response_payload)

    @app.post("/api/v1/predict/anomaly")
    def predict_anomaly_endpoint(
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        recent_metrics = body.get("recent_metrics", [])
        if not isinstance(recent_metrics, list):
            recent_metrics = []
        prediction = app.state.anomaly_predictor.predict(recent_metrics)
        agent_id = body.get("agent_id")
        if isinstance(agent_id, str) and agent_id.strip():
            app.state.anomaly_predictor.record_prediction(agent_id.strip(), prediction)
        return prediction

    @app.get("/api/v1/predict/{agent_id}/warning")
    def predict_warning_endpoint(
        agent_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        source = Path(app.state.decisions_log)
        events = read_events_from_jsonl(source) if source.exists() else []
        return app.state.anomaly_predictor.early_warning(agent_id, events)

    @app.get("/api/v1/predict/history")
    def predict_history_endpoint(
        agent_id: str | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        if isinstance(agent_id, str) and agent_id.strip():
            return {"agent_id": agent_id.strip(), "history": app.state.anomaly_predictor.get_predictions_history(agent_id.strip())}
        return {"history": app.state.anomaly_predictor.get_all_history()}

    @app.post("/api/v1/policy/optimize")
    def policy_optimize_endpoint(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        source = Path(app.state.decisions_log)
        events = read_events_from_jsonl(source) if source.exists() else []
        current_policy = payload.get("policy")
        if not isinstance(current_policy, dict):
            current_policy = app.state.current_version.policy if isinstance(app.state.current_version.policy, dict) else {}
        return app.state.policy_optimizer.analyze(events, current_policy)

    @app.get("/api/v1/policy/suggestions")
    def policy_suggestions_endpoint(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        source = Path(app.state.decisions_log)
        events = read_events_from_jsonl(source) if source.exists() else []
        current_policy = app.state.current_version.policy if isinstance(app.state.current_version.policy, dict) else {}
        analysis = app.state.policy_optimizer.analyze(events, current_policy)
        return {"suggested_changes": analysis.get("suggested_changes", [])}

    @app.post("/api/v1/policy/apply-suggestion")
    def policy_apply_suggestion_endpoint(
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        policy = body.get("policy")
        suggestions = body.get("suggestions")
        if not isinstance(policy, dict):
            policy = app.state.current_version.policy if isinstance(app.state.current_version.policy, dict) else {}
        if not isinstance(suggestions, list):
            suggestions = []
        updated = app.state.policy_optimizer.apply_suggestions(policy, suggestions)
        return {"policy": updated}

    @app.post("/api/v1/byzantine/observe")
    def byzantine_observe_endpoint(
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        agent_id = body.get("agent_id")
        metrics = body.get("metrics")
        if not isinstance(agent_id, str) or not agent_id.strip():
            raise HTTPException(status_code=400, detail="agent_id is required")
        if not isinstance(metrics, dict):
            metrics = {}
        app.state.byzantine_detector.observe(agent_id.strip(), metrics)
        return {
            "ok": True,
            "agent_id": agent_id.strip(),
            "observations": len(app.state.byzantine_detector._observations.get(agent_id.strip(), [])),
        }

    @app.get("/api/v1/byzantine/detect")
    def byzantine_detect_endpoint(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return {"results": app.state.byzantine_detector.detect()}

    @app.get("/api/v1/byzantine/fleet-health")
    def byzantine_fleet_health_endpoint(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.byzantine_detector.get_fleet_health()

    @app.post("/api/v1/byzantine/cross-validate")
    def byzantine_cross_validate_endpoint(
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        agent_a = str(body.get("agent_a", "")).strip()
        agent_b = str(body.get("agent_b", "")).strip()
        query = str(body.get("query", "")).strip()
        if not agent_a or not agent_b:
            raise HTTPException(status_code=400, detail="agent_a and agent_b are required")
        return app.state.byzantine_detector.cross_validate(agent_a=agent_a, agent_b=agent_b, query=query)

    @app.post("/api/v1/raft/append")
    def raft_append_endpoint(
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        key = str(body.get("key", "")).strip()
        value = str(body.get("value", ""))
        agent_id = str(body.get("agent_id", "")).strip()
        if not key:
            raise HTTPException(status_code=400, detail="key is required")
        if not agent_id:
            raise HTTPException(status_code=400, detail="agent_id is required")
        return app.state.raft_context.append_entry(key=key, value=value, agent_id=agent_id)

    @app.post("/api/v1/raft/acknowledge")
    def raft_acknowledge_endpoint(
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        agent_id = str(body.get("agent_id", "")).strip()
        index = body.get("index", 0)
        if not agent_id:
            raise HTTPException(status_code=400, detail="agent_id is required")
        try:
            idx = int(index)
        except (TypeError, ValueError) as error:
            raise HTTPException(status_code=400, detail="index must be an integer") from error
        ok = app.state.raft_context.acknowledge(agent_id=agent_id, index=idx)
        return {"ok": ok}

    @app.get("/api/v1/raft/divergent")
    def raft_divergent_endpoint(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return {"agents": app.state.raft_context.get_divergent_agents()}

    @app.get("/api/v1/raft/{agent_id}/context")
    def raft_context_endpoint(
        agent_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.raft_context.get_consistent_context(agent_id=agent_id)

    @app.post("/api/v1/raft/{agent_id}/sync")
    def raft_sync_endpoint(
        agent_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.raft_context.sync_agent(agent_id=agent_id)

    @app.get("/api/v1/raft/stats")
    def raft_stats_endpoint(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.raft_context.get_raft_stats()

    @app.post("/api/v1/gossip/broadcast")
    def gossip_broadcast_endpoint(
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        key = str(body.get("key", "")).strip()
        value = str(body.get("value", ""))
        source_agent = str(body.get("source_agent", "")).strip()
        if not key:
            raise HTTPException(status_code=400, detail="key is required")
        if not source_agent:
            raise HTTPException(status_code=400, detail="source_agent is required")
        message_id = app.state.gossip_protocol.broadcast(
            key=key,
            value=value,
            source_agent=source_agent,
        )
        return {"message_id": message_id}

    @app.post("/api/v1/gossip/propagate")
    def gossip_propagate_endpoint(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return {"propagated": app.state.gossip_protocol.propagate()}

    @app.get("/api/v1/gossip/convergence")
    def gossip_convergence_endpoint(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.gossip_protocol.get_convergence_status()

    @app.get("/api/v1/gossip/{agent_id}/messages")
    def gossip_messages_endpoint(
        agent_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return {"messages": app.state.gossip_protocol.receive(agent_id)}

    @app.post("/api/v1/tools/analyze")
    def analyze_tools_endpoint(
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        tool_calls = body.get("tool_calls") if isinstance(body.get("tool_calls"), list) else []
        return app.state.tool_call_analyzer.analyze(tool_calls)

    @app.get("/api/v1/tools/risk/{tool_name}")
    def get_tool_risk_endpoint(
        tool_name: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        level = app.state.tool_call_analyzer.get_tool_risk(tool_name)
        return {"tool": tool_name, "risk_level": level}

    @app.get("/api/v1/tools/session/{session_id}")
    def get_session_tool_stats_endpoint(
        session_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return _build_tool_session_payload(session_id)

    @app.get("/api/v1/memory/{session_id}/stats")
    def get_memory_stats_endpoint(
        session_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        _hydrate_memory_session(session_id)
        return app.state.memory_tracker.get_memory_stats(session_id)

    @app.get("/api/v1/memory/{session_id}/pressure")
    def get_memory_pressure_endpoint(
        session_id: str,
        model: str = "gpt-4o-mini",
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        _hydrate_memory_session(session_id)
        payload = app.state.memory_tracker.get_context_pressure(session_id, model)
        payload["session_id"] = session_id
        payload["model"] = model
        return payload

    @app.post("/api/v1/memory/{session_id}/check-poisoning")
    def check_memory_poisoning_endpoint(
        session_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        _hydrate_memory_session(session_id)
        payload = app.state.memory_tracker.detect_poisoning(session_id)
        payload["session_id"] = session_id
        return payload

    @app.delete("/api/v1/memory/{session_id}")
    def clear_memory_session_endpoint(
        session_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        app.state.memory_tracker.clear_session(session_id)
        return {"ok": True, "session_id": session_id}

    @app.get("/api/v1/fleet/status")
    def get_fleet_status_endpoint(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.fleet_coordinator.get_fleet_status()

    @app.get("/api/v1/fleet/distribution")
    def get_fleet_distribution_endpoint(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.fleet_coordinator.get_load_distribution()

    @app.post("/api/v1/fleet/assign")
    def fleet_assign_endpoint(
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        task = body.get("task") if isinstance(body.get("task"), dict) else body
        agent_id = app.state.fleet_coordinator.assign_task(task)
        if not agent_id:
            raise HTTPException(status_code=404, detail="no_eligible_agent")
        return {"assigned_agent": agent_id}

    @app.post("/api/v1/fleet/share-context")
    def fleet_share_context_endpoint(
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        shared = app.state.fleet_coordinator.share_context(
            from_agent=str(body.get("from_agent", "") or ""),
            to_agent=str(body.get("to_agent", "") or ""),
            context_key=str(body.get("context_key", "") or ""),
        )
        return {"shared": bool(shared)}

    @app.post("/api/v1/fleet/rebalance")
    def fleet_rebalance_endpoint(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.fleet_coordinator.rebalance()

    @app.post("/api/v1/vibe-audit/code")
    def vibe_audit_code_endpoint(
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        code = str(body.get("code", "") or "")
        language = str(body.get("language", "python") or "python")
        severity = str(body.get("severity", "low") or "low")
        return _build_vibe_audit_payload(code, language, severity=severity)

    @app.post("/api/v1/vibe-audit/analyze")
    def vibe_audit_analyze_endpoint(
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        code = str(body.get("code", "") or "")
        language = str(body.get("language", "python") or "python")
        severity = str(body.get("severity", "low") or "low")
        report = _build_vibe_audit_payload(code, language, severity=severity)
        checks = body.get("checks")
        if isinstance(checks, list) and checks:
            allow = {str(item).strip() for item in checks if str(item).strip()}
            report["findings"] = [
                item for item in report.get("findings", []) if str(item.get("check", "")) in allow
            ]
            report["critical_count"] = sum(
                1 for item in report["findings"] if str(item.get("severity", "")) == "critical"
            )
            report["high_count"] = sum(
                1 for item in report["findings"] if str(item.get("severity", "")) == "high"
            )
        return report

    @app.post("/api/v1/vibe-audit/directory")
    def vibe_audit_directory_endpoint(
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        dir_path = str(body.get("dir", ".") or ".")
        summary = bool(body.get("summary", True))
        severity = str(body.get("severity", "low") or "low")
        ext_raw = body.get("extensions")
        extensions = [str(item) for item in ext_raw if str(item).strip()] if isinstance(ext_raw, list) else None
        return _build_vibe_audit_directory_payload(
            dir_path=dir_path,
            summary=summary,
            extensions=extensions,
            severity=severity,
        )

    @app.get("/api/v1/ari/{agent_id}")
    def get_ari(
        agent_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return _build_ari_payload(agent_id)

    @app.get("/api/v1/ari/{agent_id}/report")
    def get_ari_report(
        agent_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = _build_ari_payload(agent_id)
        payload["report_generated_at"] = datetime.now(timezone.utc).isoformat()
        return payload

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

    @app.get("/api/v1/system/health-report")
    def system_health_report_endpoint(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.system_health_report.generate(app.state)

    @app.get("/api/v1/insights")
    def insights(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.orchesis_insights.generate(app.state)

    @app.get("/api/v1/insights/one-liner")
    def insights_one_liner(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return {"one_liner": app.state.orchesis_insights.get_one_liner()}

    @app.get("/api/v1/insights/pitch")
    def insights_pitch(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return {"pitch": app.state.orchesis_insights.get_elevator_pitch()}

    @app.get("/api/v1/cost-analytics")
    def cost_analytics(
        period: int = 24,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        safe_period = max(1, min(24 * 7, int(period)))
        return _build_cost_analytics_payload(safe_period)

    @app.get("/api/v1/cost-forecast")
    def cost_forecast(
        hours: int = 24,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        cfg = (
            app.state.current_version.policy.get("cost_forecast")
            if isinstance(app.state.current_version.policy, dict)
            and isinstance(app.state.current_version.policy.get("cost_forecast"), dict)
            else {}
        )
        model = CostForecaster(cfg)
        points = _build_hourly_cost_points(model.history_days)
        model.fit(points)
        return model.predict(hours_ahead=max(1, min(24 * 30, int(hours))))

    @app.get("/api/v1/cost-forecast/monthly")
    def cost_forecast_monthly(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        cfg = (
            app.state.current_version.policy.get("cost_forecast")
            if isinstance(app.state.current_version.policy, dict)
            and isinstance(app.state.current_version.policy.get("cost_forecast"), dict)
            else {}
        )
        model = CostForecaster(cfg)
        points = _build_hourly_cost_points(model.history_days)
        model.fit(points)
        return model.predict_monthly()

    @app.get("/api/v1/cost-forecast/breakeven")
    def cost_forecast_breakeven(
        budget: float,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        cfg = (
            app.state.current_version.policy.get("cost_forecast")
            if isinstance(app.state.current_version.policy, dict)
            and isinstance(app.state.current_version.policy.get("cost_forecast"), dict)
            else {}
        )
        model = CostForecaster(cfg)
        points = _build_hourly_cost_points(model.history_days)
        model.fit(points)
        return model.get_breakeven(monthly_budget=float(budget))

    @app.get("/api/v1/cost-attribution")
    def cost_attribution(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return _build_cost_attribution_payload()

    @app.get("/api/v1/cost-attribution/chargebacks")
    def cost_attribution_chargebacks(
        period: str = "month",
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        _build_cost_attribution_payload()
        return {"period": period, "chargebacks": app.state.cost_attribution.get_chargebacks(period=period)}

    @app.get("/api/v1/cost-attribution/teams/{team}")
    def cost_attribution_team(
        team: str,
        days_ahead: int = 30,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        _build_cost_attribution_payload()
        return {
            "team": team,
            "budget_status": app.state.cost_attribution.get_budget_status(team),
            "forecast": app.state.cost_attribution.forecast_by_team(team, days_ahead=max(1, int(days_ahead))),
        }

    @app.post("/api/v1/cost-attribution/rules")
    def cost_attribution_add_rule(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        app.state.cost_attribution.add_rule(payload)
        return {"ok": True, "rule": payload}

    @app.get("/api/v1/heatmap")
    def session_heatmap(
        days: int = 7,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        safe_days = max(1, min(31, int(days)))
        return _build_session_heatmap_payload(days=safe_days)

    @app.get("/api/v1/heatmap/daily")
    def session_heatmap_daily(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return {"days": 7, "summary": _build_session_heatmap_daily()}

    @app.get("/api/v1/budget/advice")
    def budget_advice(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return _build_budget_advice_payload()

    @app.get("/api/v1/budget/quick-wins")
    def budget_quick_wins(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        analysis = _build_budget_advice_payload()
        return {"quick_wins": BudgetAdvisor().get_quick_wins(analysis)}

    @app.get("/api/v1/requests/{request_id}/inspect")
    def request_inspect(
        request_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = _build_request_inspection(request_id)
        if not payload:
            raise HTTPException(status_code=404, detail={"error": "request not found"})
        return payload

    @app.get("/api/v1/requests/recent")
    def request_recent(
        limit: int = 20,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        safe_limit = max(1, min(200, int(limit)))
        source = Path(app.state.decisions_log)
        events = read_events_from_jsonl(source) if source.exists() else []
        rows: list[dict[str, Any]] = []
        for event in reversed(events):
            event_id = str(getattr(event, "event_id", "") or "")
            if not event_id:
                continue
            rows.append(
                {
                    "request_id": event_id,
                    "timestamp": str(getattr(event, "timestamp", "")),
                    "agent_id": str(getattr(event, "agent_id", "__global__") or "__global__"),
                    "tool": str(getattr(event, "tool", "")),
                    "final_decision": str(getattr(event, "decision", "ALLOW") or "ALLOW"),
                }
            )
            if len(rows) >= safe_limit:
                break
        return {"requests": rows, "count": len(rows)}

    @app.get("/api/v1/anomaly/alerts")
    def anomaly_alerts(
        since: float | None = None,
        limit: int = 50,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        _refresh_anomaly_alerts()
        rows = app.state.anomaly_alerts.get_alerts(since=since, limit=limit)
        return {"alerts": rows, "count": len(rows)}

    @app.get("/api/v1/anomaly/alerts/{agent_id}")
    def anomaly_alerts_by_agent(
        agent_id: str,
        since: float | None = None,
        limit: int = 50,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        _refresh_anomaly_alerts()
        rows = app.state.anomaly_alerts.get_alerts(agent_id=agent_id, since=since, limit=limit)
        return {"agent_id": agent_id, "alerts": rows, "count": len(rows)}

    @app.post("/api/v1/anomaly/dismiss/{alert_id}")
    def anomaly_dismiss(
        alert_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        ok = app.state.anomaly_alerts.dismiss(alert_id)
        return {"dismissed": bool(ok), "alert_id": alert_id}

    @app.get("/api/v1/anomaly/summary")
    def anomaly_summary(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        _refresh_anomaly_alerts()
        return app.state.anomaly_alerts.get_summary()

    @app.get("/api/v1/search")
    def search(
        q: str = "",
        limit: int = 25,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return _build_search_payload(q, limit)

    @app.get("/api/v1/notifications")
    def get_notifications(
        since: float = 0.0,
        limit: int = 50,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        safe_limit = max(1, min(200, int(limit)))
        safe_since = float(since or 0.0)
        with app.state.notifications_lock:
            records = list(app.state.notifications)
        if safe_since > 0:
            records = [item for item in records if float(item.get("timestamp", 0.0) or 0.0) > safe_since]
        records = records[-safe_limit:]
        return {"notifications": records, "count": len(records)}

    @app.post("/api/v1/notifications/dismiss/{notification_id}")
    def dismiss_notification(
        notification_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        target = str(notification_id)
        with app.state.notifications_lock:
            before = len(app.state.notifications)
            app.state.notifications = [
                item for item in app.state.notifications if str(item.get("id", "")) != target
            ]
            removed = before - len(app.state.notifications)
        return {"status": "dismissed", "id": target, "removed": removed}

    @app.get("/api/v1/token-yield/{session_id}")
    def token_yield_session(
        session_id: str,
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        token = str(session_id).strip().lower()
        if token == "global":
            return app.state.token_yield.get_global_stats()
        if token == "report":
            period = str(request.query_params.get("period", "24h"))
            return _build_token_yield_report(period)
        return app.state.token_yield.get_yield(session_id)

    @app.get("/api/v1/token-yield/global")
    def token_yield_global(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.token_yield.get_global_stats()

    @app.get("/api/v1/token-yield/report")
    def token_yield_report(
        period: str = "24h",
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return _build_token_yield_report(period)

    @app.get("/api/v1/token-yield/report/markdown")
    def token_yield_report_markdown(
        period: str = "24h",
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        generator = TokenYieldReportGenerator()
        report = _build_token_yield_report(period)
        return {"period": period, "markdown": generator.export_markdown(report)}

    @app.post("/api/v1/lifecycle/register")
    def lifecycle_register(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        agent_id = str(payload.get("agent_id", "")).strip()
        metadata = payload.get("metadata")
        try:
            return app.state.agent_lifecycle.register(agent_id, metadata if isinstance(metadata, dict) else None)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail={"error": str(exc)}) from exc

    @app.get("/api/v1/lifecycle/{agent_id}")
    def lifecycle_get_state(
        agent_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        try:
            return app.state.agent_lifecycle.get_state(agent_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail={"error": "agent not found"}) from exc

    @app.post("/api/v1/lifecycle/{agent_id}/transition")
    def lifecycle_transition(
        agent_id: str,
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        new_state = str(payload.get("new_state", "")).strip()
        reason = str(payload.get("reason", ""))
        if not new_state:
            raise HTTPException(status_code=400, detail={"error": "new_state is required"})
        ok = app.state.agent_lifecycle.transition(agent_id, new_state, reason)
        if not ok:
            raise HTTPException(status_code=400, detail={"error": "transition not allowed"})
        return app.state.agent_lifecycle.get_state(agent_id)

    @app.get("/api/v1/lifecycle/state/{state}")
    def lifecycle_list_by_state(
        state: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        rows = app.state.agent_lifecycle.list_by_state(state)
        return {"state": state, "agents": rows, "count": len(rows)}

    @app.post("/api/v1/lifecycle/{agent_id}/retire")
    def lifecycle_retire(
        agent_id: str,
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        reason = str(payload.get("reason", "retire"))
        ok = app.state.agent_lifecycle.retire(agent_id, reason)
        if not ok:
            raise HTTPException(status_code=400, detail={"error": "transition not allowed"})
        return app.state.agent_lifecycle.get_state(agent_id)

    @app.post("/api/v1/lifecycle/{agent_id}/ban")
    def lifecycle_ban(
        agent_id: str,
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        reason = str(payload.get("reason", "ban"))
        ok = app.state.agent_lifecycle.ban(agent_id, reason)
        if not ok:
            raise HTTPException(status_code=400, detail={"error": "transition not allowed"})
        return app.state.agent_lifecycle.get_state(agent_id)

    @app.get("/api/v1/changelog")
    def changelog_endpoint() -> dict[str, Any]:
        return {
            "current_version": "0.2.1",
            "entries": [
                {
                    "version": "0.2.1",
                    "date": "2026-03-17",
                    "highlights": ["83% threat block rate", "40+ new modules", "3,300+ tests"],
                    "changes": [
                        "Live policy hot reload",
                        "Context DNA behavioral fingerprint",
                        "Agent Health Score dashboard widget",
                        "Evidence Record - EU AI Act Article 12",
                        "Auto-healing 6 levels L1-L6",
                        "Per-team budget attribution",
                        "Session replay against new policy",
                        "orchesis doctor --fix --json",
                    ],
                }
            ],
        }

    @app.get("/api/v1/threat-patterns")
    def list_threat_patterns(
        category: str | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        library = app.state.threat_patterns
        if isinstance(category, str) and category.strip():
            rows = library.list_by_category(category)
        else:
            rows = []
            for pattern_id in sorted(library.PATTERNS.keys()):
                item = library.get_pattern(pattern_id)
                if isinstance(item, dict):
                    rows.append(item)
        return {"patterns": rows, "count": len(rows), "stats": library.get_stats()}

    @app.get("/api/v1/threat-patterns/{pattern_id}")
    def get_threat_pattern(
        pattern_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        row = app.state.threat_patterns.get_pattern(pattern_id)
        if row is None:
            raise HTTPException(status_code=404, detail={"error": "pattern not found"})
        return row

    @app.post("/api/v1/threat-patterns/match")
    def match_threat_patterns(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        text = payload.get("text")
        if not isinstance(text, str):
            raise HTTPException(status_code=400, detail={"error": "text is required"})
        matches = app.state.threat_patterns.match(text)
        return {"matches": matches, "count": len(matches)}

    @app.get("/api/v1/threat-feed/status")
    def threat_feed_status(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.threat_feed.get_stats()

    @app.post("/api/v1/threat-feed/update")
    def threat_feed_update(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        added = app.state.threat_feed.fetch()
        return {"added": len(added), "signatures": added}

    @app.get("/api/v1/threat-feed/signatures")
    def threat_feed_signatures(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return {"signatures": list(app.state.threat_feed._signatures)}

    @app.get("/api/v1/signatures")
    def list_signatures(
        category: str | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return {"signatures": app.state.signature_editor.list_all(category=category)}

    @app.post("/api/v1/signatures")
    def create_signature(
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        try:
            return app.state.signature_editor.create(body)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail={"error": str(exc)}) from exc

    @app.post("/api/v1/signatures/test-pattern")
    def test_signature_pattern(
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        pattern = str(payload.get("pattern", ""))
        test_text = str(payload.get("test_text", ""))
        return app.state.signature_editor.test_pattern(pattern, test_text)

    @app.get("/api/v1/signatures/{sig_id}")
    def get_signature(
        sig_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        rows = app.state.signature_editor.list_all()
        for row in rows:
            if str(row.get("id", "")) == str(sig_id):
                return row
        raise HTTPException(status_code=404, detail={"error": "signature not found"})

    @app.put("/api/v1/signatures/{sig_id}")
    def update_signature(
        sig_id: str,
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        try:
            return app.state.signature_editor.update(sig_id, body)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail={"error": "signature not found"}) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail={"error": str(exc)}) from exc

    @app.delete("/api/v1/signatures/{sig_id}")
    def delete_signature(
        sig_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        deleted = app.state.signature_editor.delete(sig_id)
        if not deleted:
            raise HTTPException(status_code=404, detail={"error": "signature not found"})
        return {"deleted": True, "id": sig_id}

    @app.get("/api/v1/alert-rules")
    def alert_rules_list(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        rows = app.state.alert_rules_engine.list_rules()
        return {"rules": rows, "count": len(rows)}

    @app.post("/api/v1/alert-rules")
    def alert_rules_add(
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        try:
            rule = app.state.alert_rules_engine.add_rule(body)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail={"error": str(exc)}) from exc
        return rule.to_dict()

    @app.delete("/api/v1/alert-rules/{name}")
    def alert_rules_remove(
        name: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        ok = app.state.alert_rules_engine.remove_rule(name)
        if not ok:
            raise HTTPException(status_code=404, detail={"error": "rule not found"})
        return {"deleted": True, "name": name}

    @app.post("/api/v1/alert-rules/evaluate")
    def alert_rules_evaluate(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        metrics_input = payload.get("metrics")
        metric_values = metrics_input if isinstance(metrics_input, dict) else _default_alert_metrics()
        fired = app.state.alert_rules_engine.evaluate(metric_values)
        return {"fired": fired, "count": len(fired), "metrics": metric_values}

    @app.get("/api/v1/flywheel/stats")
    def flywheel_stats(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        app.state.data_flywheel.extract_patterns()
        return app.state.data_flywheel.get_flywheel_stats()

    @app.get("/api/v1/flywheel/leaderboard")
    def flywheel_leaderboard(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        rows = app.state.data_flywheel.get_leaderboard()
        return {"leaderboard": rows, "count": len(rows)}

    @app.post("/api/v1/flywheel/signal")
    def flywheel_signal(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        app.state.data_flywheel.collect_signal(payload)
        return {"status": "accepted", "stored": True}

    @app.post("/api/v1/flywheel/calibrate")
    def flywheel_calibrate(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        community_data = payload.get("community_data")
        rows = community_data if isinstance(community_data, list) else []
        return app.state.data_flywheel.calibrate_signatures(rows)

    @app.get("/api/v1/tenants")
    def list_tenants(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        rows = app.state.tenant_manager.list_tenants()
        return {"tenants": rows, "count": len(rows)}

    @app.post("/api/v1/tenants")
    def create_tenant(
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        tenant_id = payload.get("tenant_id")
        policy = payload.get("policy")
        try:
            row = app.state.tenant_manager.create_tenant(str(tenant_id or ""), policy)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail={"error": str(exc)}) from exc
        return row

    @app.get("/api/v1/tenants/{tenant_id}")
    def get_tenant(
        tenant_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        policy = app.state.tenant_manager.get_policy(tenant_id)
        if policy is None:
            raise HTTPException(status_code=404, detail={"error": "tenant not found"})
        resolved = app.state.tenant_manager.resolve_policy(tenant_id, app.state.current_version.policy)
        return {"tenant_id": tenant_id, "policy": policy, "resolved_policy": resolved}

    @app.put("/api/v1/tenants/{tenant_id}/policy")
    def update_tenant_policy(
        tenant_id: str,
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        policy = payload.get("policy")
        try:
            row = app.state.tenant_manager.update_policy(tenant_id, policy)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail={"error": "tenant not found"}) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail={"error": str(exc)}) from exc
        return row

    @app.delete("/api/v1/tenants/{tenant_id}")
    def delete_tenant(
        tenant_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        ok = app.state.tenant_manager.delete_tenant(tenant_id)
        if not ok:
            raise HTTPException(status_code=404, detail={"error": "tenant not found"})
        return {"deleted": True, "tenant_id": tenant_id}

    @app.get("/api/v1/community/status")
    def community_status(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        stats = app.state.community_intel.get_stats()
        return {
            "enabled": bool(stats.get("enabled", False)),
            "privacy_badge": "zero_pii_shared",
            "last_sync": stats.get("last_sync", ""),
        }

    @app.post("/api/v1/community/enable")
    def community_enable(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        app.state.community_intel.enabled = True
        return {"status": "enabled", "enabled": True}

    @app.post("/api/v1/community/disable")
    def community_disable(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        app.state.community_intel.enabled = False
        return {"status": "disabled", "enabled": False}

    @app.get("/api/v1/community/stats")
    def community_stats(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.community_intel.get_stats()

    @app.get("/api/v1/rate-limits/status")
    def rate_limits_status(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return _build_rate_limit_status_payload()

    @app.get("/api/v1/rate-limit/status")
    def api_rate_limit_status(
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        client_id = _client_id_from_request(request)
        status = app.state.api_limiter.check(client_id)
        return {"client_id": client_id, **status}

    @app.get("/api/v1/rate-limit/clients")
    def api_rate_limit_clients(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.api_limiter.get_stats()

    @app.post("/api/v1/rate-limit/reset/{client_id}")
    def api_rate_limit_reset(
        client_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        app.state.api_limiter.reset(client_id)
        return {"reset": True, "client_id": str(client_id)}

    @app.get("/api/v1/shadow/status")
    def shadow_status(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        runner = getattr(app.state, "shadow_runner", None)
        report = runner.get_divergence_report() if isinstance(runner, ShadowModeRunner) else {}
        recommendation = runner.get_recommendation() if isinstance(runner, ShadowModeRunner) else "disabled"
        return {
            "enabled": bool(getattr(app.state, "shadow_mode_enabled", False)),
            "shadow_policy": str(getattr(app.state, "shadow_policy_path", "")),
            "log_divergences": bool(getattr(app.state, "shadow_mode_log_divergences", True)),
            "report": report,
            "recommendation": recommendation,
        }

    @app.get("/api/v1/shadow/divergences")
    def shadow_divergences(
        limit: int = 100,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        runner = getattr(app.state, "shadow_runner", None)
        if not isinstance(runner, ShadowModeRunner):
            return {"enabled": False, "report": {}, "items": []}
        return {
            "enabled": True,
            "report": runner.get_divergence_report(),
            "items": runner.get_divergences(limit=limit),
        }

    @app.post("/api/v1/shadow/enable")
    def shadow_enable(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        _refresh_current_version()
        app.state.shadow_mode_enabled = True
        runner = getattr(app.state, "shadow_runner", None)
        if not isinstance(runner, ShadowModeRunner):
            app.state.shadow_runner = ShadowModeRunner(dict(app.state.current_version.policy), _shadow_engine)
        return {"enabled": True}

    @app.post("/api/v1/shadow/disable")
    def shadow_disable(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        app.state.shadow_mode_enabled = False
        return {"enabled": False}

    @app.get("/api/v1/geo/classify")
    def geo_classify(
        ip: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return GeoIntel().classify_ip(ip)

    @app.post("/api/v1/geo/scan-ssrf")
    def geo_scan_ssrf(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        text = payload.get("text")
        if isinstance(text, str):
            source = text
        else:
            source = json.dumps(payload, ensure_ascii=False)
        return GeoIntel().scan_for_ssrf(source)

    @app.get("/api/v1/benchmark/cases")
    def benchmark_cases(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        cases = [
            {
                "id": case.id,
                "category": case.category,
                "subcategory": case.subcategory,
                "description": case.description,
                "expected_action": case.expected_action,
                "severity": case.severity,
                "tags": list(case.tags),
                "reference": case.reference,
            }
            for case in ORCHESIS_BENCHMARK_V1
        ]
        return {"total": len(cases), "cases": cases}

    @app.get("/api/v1/benchmark/run/{case_id}")
    def benchmark_run_case(
        case_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        selected = [case for case in ORCHESIS_BENCHMARK_V1 if case.id == case_id]
        if not selected:
            raise HTTPException(status_code=404, detail={"error": "benchmark case not found"})
        suite = BenchmarkSuite(cases=selected, policy=app.state.current_version.policy)
        report = suite.run()
        payload = asdict(report)
        payload["comparison"] = suite.compare_to_baseline(payload)
        app.state.benchmark_results[case_id] = payload
        app.state.benchmark_results["latest"] = payload
        return payload

    @app.post("/api/v1/benchmark/run-all")
    def benchmark_run_all(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        suite = BenchmarkSuite(policy=app.state.current_version.policy)
        report = suite.run()
        payload = asdict(report)
        payload["comparison"] = suite.compare_to_baseline(payload)
        app.state.benchmark_results["run_all"] = payload
        app.state.benchmark_results["latest"] = payload
        return payload

    @app.get("/api/v1/benchmark/results")
    def benchmark_results(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        latest = app.state.benchmark_results.get("latest")
        if isinstance(latest, dict):
            return {"results": latest, "saved_runs": len(app.state.benchmark_results)}
        return {"results": None, "saved_runs": 0}

    @app.get("/api/v1/export/all")
    def export_all(authorization: str | None = Header(default=None)) -> Response:
        _require_auth(authorization)
        payload = _build_export_zip()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        headers = {"Content-Disposition": f'attachment; filename="orchesis-export-{stamp}.zip"'}
        return Response(content=payload, media_type="application/zip", headers=headers)

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

    @app.get("/api/v1/flow/timeline")
    def flow_timeline(
        session_id: str,
        limit: int = 50,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        safe_limit = max(1, min(500, int(limit)))
        decisions_raw = app.state.flow_decisions.get(session_id, [])
        decisions = [dict(item) for item in decisions_raw if isinstance(item, dict)][-safe_limit:]
        phase_order = [
            "parse",
            "flow_xray",
            "cascade",
            "circuit_breaker",
            "loop_detection",
            "behavioral",
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
            "send",
        ]
        color_map = {"pass": "#00FF41", "warn": "#fbbf24", "block": "#ef4444"}
        requests: list[dict[str, Any]] = []
        for idx, item in enumerate(decisions):
            allowed = bool(item.get("allowed", False))
            reasons = item.get("reasons", [])
            reason_list = list(reasons) if isinstance(reasons, list) else []
            if not allowed:
                decision_state = "block"
            elif reason_list:
                decision_state = "warn"
            else:
                decision_state = "pass"
            phase_cells = [
                {
                    "phase": phase,
                    "phase_index": i + 1,
                    "decision": decision_state,
                    "color": color_map[decision_state],
                    "tool_name": str(item.get("tool_name", "")),
                    "reasons": reason_list,
                }
                for i, phase in enumerate(phase_order)
            ]
            requests.append(
                {
                    "request_index": idx,
                    "timestamp": str(item.get("timestamp", "")),
                    "decision": str(item.get("decision", "ALLOW")),
                    "allowed": allowed,
                    "tool_name": str(item.get("tool_name", "")),
                    "phases": phase_cells,
                }
            )
        return {
            "session_id": session_id,
            "limit": safe_limit,
            "phase_count": len(phase_order),
            "phase_order": phase_order,
            "decision_colors": color_map,
            "requests": requests,
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
        if bool(getattr(app.state, "shadow_mode_enabled", False)):
            runner = getattr(app.state, "shadow_runner", None)
            if isinstance(runner, ShadowModeRunner):
                try:
                    runner.shadow_evaluate(body, response)
                except Exception:
                    pass
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

    @app.post("/api/v1/forensic/reconstruct")
    def forensic_reconstruct(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        request_id = str(payload.get("request_id", "") or "").strip()
        if not request_id:
            raise HTTPException(status_code=400, detail={"error": "request_id is required"})
        source = Path(app.state.decisions_log)
        events = read_events_from_jsonl(source) if source.exists() else []
        decisions: list[dict[str, Any]] = []
        for event in events:
            if hasattr(event, "__dict__"):
                row = dict(getattr(event, "__dict__", {}))
            elif isinstance(event, dict):
                row = dict(event)
            else:
                continue
            row.setdefault("request_id", row.get("event_id"))
            decisions.append(row)
        return app.state.forensic_reconstructor.reconstruct(request_id, decisions)

    @app.post("/api/v1/forensic/causal-chain")
    def forensic_causal_chain(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        request_id = str(payload.get("request_id", "") or "").strip()
        if not request_id:
            raise HTTPException(status_code=400, detail={"error": "request_id is required"})
        source = Path(app.state.decisions_log)
        events = read_events_from_jsonl(source) if source.exists() else []
        decisions: list[dict[str, Any]] = []
        for event in events:
            if hasattr(event, "__dict__"):
                row = dict(getattr(event, "__dict__", {}))
            elif isinstance(event, dict):
                row = dict(event)
            else:
                continue
            row.setdefault("request_id", row.get("event_id"))
            decisions.append(row)
        causal_chain = app.state.forensic_reconstructor.find_causal_chain(request_id, decisions)
        return {"request_id": request_id, "causal_chain": causal_chain, "chain_length": len(causal_chain)}

    @app.post("/api/v1/forensic/report")
    def forensic_report(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        request_id = str(payload.get("request_id", "") or "").strip()
        if not request_id:
            raise HTTPException(status_code=400, detail={"error": "request_id is required"})
        source = Path(app.state.decisions_log)
        events = read_events_from_jsonl(source) if source.exists() else []
        decisions: list[dict[str, Any]] = []
        for event in events:
            if hasattr(event, "__dict__"):
                row = dict(getattr(event, "__dict__", {}))
            elif isinstance(event, dict):
                row = dict(event)
            else:
                continue
            row.setdefault("request_id", row.get("event_id"))
            decisions.append(row)
        return app.state.forensic_reconstructor.generate_forensic_report(request_id, decisions)

    @app.get("/api/v1/forensic/stats")
    def forensic_stats(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.forensic_reconstructor.get_stats()

    def _load_autopsy_decisions_rows() -> list[dict[str, Any]]:
        source = Path(app.state.decisions_log)
        if not source.exists():
            return []
        rows: list[dict[str, Any]] = []
        for line in source.read_text(encoding="utf-8").splitlines():
            raw = line.strip()
            if not raw:
                continue
            try:
                row = json.loads(raw)
            except Exception:
                continue
            if not isinstance(row, dict):
                continue
            state = row.get("state_snapshot", {})
            if not isinstance(state, dict):
                state = {}
            session_id = str(
                row.get("session_id")
                or state.get("session_id")
                or "__global__"
            )
            tokens = row.get("tokens")
            if not isinstance(tokens, int | float):
                tokens = state.get("prompt_tokens", state.get("prompt_length", 0))
            reasons = row.get("reasons", [])
            if not isinstance(reasons, list):
                reasons = []
            rows.append(
                {
                    "session_id": session_id,
                    "timestamp": str(row.get("timestamp", "")),
                    "decision": str(row.get("decision", "")),
                    "reasons": [str(item) for item in reasons],
                    "tokens": int(tokens) if isinstance(tokens, int | float) else 0,
                    "state_snapshot": state,
                }
            )
        return rows

    @app.post("/api/v1/autopsy/{session_id}")
    def autopsy_perform_endpoint(
        session_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        rows = _load_autopsy_decisions_rows()
        report = app.state.agent_autopsy.perform(session_id=session_id, decisions_log=rows)
        if "error" in report:
            raise HTTPException(status_code=404, detail={"error": report["error"]})
        return report

    @app.get("/api/v1/autopsy/{session_id}")
    def autopsy_get_endpoint(
        session_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        if session_id == "list":
            rows = app.state.agent_autopsy.list_recent(limit=20)
            return {"autopsies": rows, "count": len(rows)}
        existing = app.state.agent_autopsy.get(session_id)
        if isinstance(existing, dict):
            return existing
        rows = _load_autopsy_decisions_rows()
        report = app.state.agent_autopsy.perform(session_id=session_id, decisions_log=rows)
        if "error" in report:
            raise HTTPException(status_code=404, detail={"error": report["error"]})
        return report

    @app.get("/api/v1/autopsy/list")
    def autopsy_list_endpoint(
        limit: int = 20,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        rows = app.state.agent_autopsy.list_recent(limit=max(1, min(500, int(limit))))
        return {"autopsies": rows, "count": len(rows)}

    @app.post("/api/v1/forensics/session/{session_id}/analyze")
    def session_forensics_analyze_endpoint(
        session_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        events = [row for row in _load_autopsy_decisions_rows() if str(row.get("session_id", "")) == session_id]
        result = app.state.session_forensics.analyze(session_id=session_id, events=events)
        if "error" in result:
            raise HTTPException(status_code=404, detail={"error": result["error"]})
        return result

    @app.get("/api/v1/forensics/session/{session_id}")
    def session_forensics_get_endpoint(
        session_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        existing = app.state.session_forensics.get(session_id)
        if isinstance(existing, dict):
            return existing
        events = [row for row in _load_autopsy_decisions_rows() if str(row.get("session_id", "")) == session_id]
        result = app.state.session_forensics.analyze(session_id=session_id, events=events)
        if "error" in result:
            raise HTTPException(status_code=404, detail={"error": result["error"]})
        return result

    @app.get("/api/v1/forensics/stats")
    def session_forensics_stats_endpoint(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.session_forensics.get_stats()

    @app.get("/api/v1/incidents")
    def incidents_list(
        since: str | None = None,
        status: str | None = None,
        severity: str | None = None,
        agent_id: str | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        manager = app.state.incident_manager
        has_managed = len(manager.list_incidents()) > 0
        if has_managed or status is not None or agent_id is not None:
            incidents = manager.list_incidents(status=status, severity=severity, agent_id=agent_id)
            return {"incidents": incidents, "total": len(incidents)}
        engine = ForensicsEngine(decisions_path=app.state.decisions_log)
        incidents = engine.detect_incidents(since=since, severity_filter=severity)
        return {"incidents": [incident.__dict__ for incident in incidents], "total": len(incidents)}

    @app.post("/api/v1/incidents")
    def incidents_create(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        threat = payload.get("threat")
        if not isinstance(threat, dict):
            threat = payload
        agent_id = str(payload.get("agent_id", threat.get("agent_id", "unknown")) or "unknown")
        return app.state.incident_manager.create(threat=threat, agent_id=agent_id)

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

    @app.get("/api/v1/incidents/metrics")
    def incidents_metrics(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.incident_manager.get_metrics()

    @app.put("/api/v1/incidents/{incident_id}/status")
    def incidents_update_status(
        incident_id: str,
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        status = str(payload.get("status", "") or "")
        note = str(payload.get("note", "") or "")
        ok = app.state.incident_manager.update_status(incident_id=incident_id, status=status, note=note)
        if not ok:
            raise HTTPException(status_code=404, detail={"error": "incident not found"})
        return {"ok": True, "incident_id": incident_id, "status": status}

    @app.post("/api/v1/incidents/{incident_id}/mitigations")
    def incidents_add_mitigation(
        incident_id: str,
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        action = str(payload.get("action", "") or "")
        ok = app.state.incident_manager.add_mitigation(incident_id=incident_id, action=action)
        if not ok:
            raise HTTPException(status_code=404, detail={"error": "incident not found"})
        return {"ok": True, "incident_id": incident_id, "action": action}

    @app.get("/api/v1/incidents/{incident_id}")
    def incident_detail(
        incident_id: str,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        managed = app.state.incident_manager.get_incident(incident_id)
        if isinstance(managed, dict):
            return managed
        engine = ForensicsEngine(decisions_path=app.state.decisions_log)
        incident = engine.get_incident(incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail={"error": "incident not found"})
        return incident.__dict__

    @app.get("/api/v1/webchat/stats")
    def webchat_stats(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.webchat_injector.get_stats()

    @app.post("/api/v1/webchat/alert/{session_id}")
    def webchat_queue_alert(
        session_id: str,
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        alert_type = str(payload.get("alert_type", payload.get("type", "info")) or "info")
        message = str(payload.get("message", "") or "")
        if not message:
            raise HTTPException(status_code=400, detail={"error": "message is required"})
        alert = app.state.webchat_injector.queue_alert(session_id, alert_type, message)
        return {"queued": True, "alert": alert}

    @app.get("/api/v1/webchat/{session_id}/pending")
    def webchat_pending(session_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        pending = app.state.webchat_injector.get_pending(session_id)
        return {"session_id": session_id, "pending": pending, "count": len(pending)}

    @app.post("/api/v1/webchat/{session_id}/inject")
    def webchat_inject(
        session_id: str,
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        response_payload = payload.get("response")
        response = dict(response_payload) if isinstance(response_payload, dict) else dict(payload)
        injected = app.state.webchat_injector.inject_into_response(session_id, response)
        return {"session_id": session_id, "response": injected}

    @app.post("/api/v1/h43/trial")
    def h43_record_trial(
        body: dict[str, Any] | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _require_auth(authorization)
        payload = body if isinstance(body, dict) else {}
        order = str(payload.get("order", "") or "")
        if order not in {"security_first", "task_first"}:
            raise HTTPException(status_code=400, detail={"error": "order must be security_first or task_first"})
        security_score = float(payload.get("security_score", 0.0))
        task_score = float(payload.get("task_score", 0.0))
        trial = app.state.h43_quantum.record_trial(order=order, security_score=security_score, task_score=task_score)
        return {"ok": True, "trial": trial}

    @app.get("/api/v1/h43/results")
    def h43_results(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.h43_quantum.compute_delta_bar()

    @app.get("/api/v1/h43/stats")
    def h43_stats(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _require_auth(authorization)
        return app.state.h43_quantum.get_stats()

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
