"""Module Registry - catalog of all Orchesis modules."""

from __future__ import annotations

from typing import Any

REGISTRY = {
    "core": ["proxy", "engine", "config", "scanner", "api", "cli", "dashboard"],
    "pipeline_layer2": [
        "content_ranker",
        "pid_controller_v2",
        "state_estimator",
        "quality_control",
        "injection_protocol",
        "message_consistency",
        "context_compression_v2",
        "behavior_sync",
    ],
    "fleet": [
        "fleet_consensus",
        "byzantine_detector",
        "context_sync",
        "gossip_protocol",
        "bandit_sampler",
        "budget_allocator",
        "fleet_coordinator",
        "critical_agent",
    ],
    "security": [
        "intent_classifier",
        "response_analyzer",
        "tool_call_analyzer",
        "memory_tracker",
        "context_termination",
        "fallback_reasoner",
        "adversarial_tracker",
        "threat_history",
        "layered_defense",
        "adaptive_detection_v2",
    ],
    "research": [
        "efficiency_metric",
        "solution_space",
        "content_importance",
        "throughput_estimate",
        "relevance_theory",
        "adaptive_learning",
        "fleet_selection",
        "forensic_reconstruction",
        "state_balancer",
    ],
    "ecosystem": [
        "casura.incident_db",
        "casura.intelligence",
        "aabb.benchmark",
        "are.framework",
        "monitoring.parsers",
        "monitoring.competitive",
    ],
    "tools": [
        "agent_diagnostics",
        "session_forensics",
        "arc_readiness",
        "vibe_audit",
        "generate_paper",
        "arxiv_validator",
        "weekly_report",
        "config_validator",
        "system_health_report",
        "coverage_report",
    ],
    "sdk": ["sdk", "otel_bridge", "session_fp"],
}


class ModuleRegistry:
    def get_all_modules(self) -> list[str]:
        return [item for modules in REGISTRY.values() for item in modules]

    def get_by_category(self, category: str) -> list[str]:
        return list(REGISTRY.get(category, []))

    def get_categories(self) -> list[str]:
        return list(REGISTRY.keys())

    def count(self) -> dict[str, Any]:
        per_category = {category: len(modules) for category, modules in REGISTRY.items()}
        return per_category | {"total": sum(len(modules) for modules in REGISTRY.values())}
