"""Module Registry - catalog of all Orchesis modules."""

from __future__ import annotations

from typing import Any

REGISTRY = {
    "core": ["proxy", "engine", "config", "scanner", "api", "cli", "dashboard"],
    "nlce_layer2": [
        "uci_compression",
        "pid_controller_v2",
        "kalman_estimator",
        "criticality_control",
        "injection_protocol",
        "discourse_coherence",
        "context_compression_v2",
        "hgt_protocol",
    ],
    "fleet": [
        "quorum_sensing",
        "byzantine_detector",
        "raft_context",
        "gossip_protocol",
        "thompson_sampling",
        "vickrey_allocator",
        "fleet_coordinator",
        "keystone_agent",
    ],
    "security": [
        "intent_classifier",
        "response_analyzer",
        "tool_call_analyzer",
        "memory_tracker",
        "apoptosis",
        "par_reasoning",
        "red_queen",
        "immune_memory",
        "complement_cascade",
        "adaptive_detection_v2",
    ],
    "research": [
        "carnot_efficiency",
        "fitness_landscape",
        "kolmogorov_importance",
        "shannon_hartley",
        "relevance_theory",
        "double_loop_learning",
        "group_selection",
        "forensic_reconstruction",
        "homeostasis",
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
        "agent_autopsy",
        "session_forensics",
        "arc_readiness",
        "vibe_audit",
        "nlce_paper",
        "arxiv_validator",
        "weekly_report",
        "config_validator",
        "system_health_report",
        "coverage_report",
    ],
    "sdk": ["sdk", "otel_bridge", "context_dna"],
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
