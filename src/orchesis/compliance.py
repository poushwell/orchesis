"""Compliance report generation from policy and runtime artifacts."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

import yaml


class Framework(Enum):
    OWASP_LLM_TOP_10 = "owasp_llm_top10_2025"
    NIST_AI_RMF = "nist_ai_rmf_1_0"
    NIST_AI_AGENT = "nist_ai_agent_2026"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass(frozen=True)
class FrameworkItem:
    """One item in a compliance framework (e.g., OWASP LLM01)."""

    framework: Framework
    item_id: str
    name: str
    description: str
    url: str
    severity: Severity


@dataclass(frozen=True)
class ComplianceMapping:
    """Maps an Orchesis capability to a framework item."""

    framework_item: FrameworkItem
    orchesis_module: str
    orchesis_feature: str
    coverage: str
    description: str


@dataclass
class ComplianceFinding:
    """A specific finding mapped to compliance frameworks."""

    finding_id: str
    timestamp: str
    source_module: str
    source_detail: str
    description: str
    severity: Severity
    framework_mappings: list[tuple[str, str]]
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""


OWASP_LLM_TOP_10: list[FrameworkItem] = [
    FrameworkItem(
        framework=Framework.OWASP_LLM_TOP_10,
        item_id="LLM01",
        name="Prompt Injection",
        description="Manipulating LLM via crafted inputs to cause unintended actions",
        url="https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
        severity=Severity.CRITICAL,
    ),
    FrameworkItem(
        framework=Framework.OWASP_LLM_TOP_10,
        item_id="LLM02",
        name="Sensitive Information Disclosure",
        description="LLM inadvertently revealing confidential data",
        url="https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/",
        severity=Severity.HIGH,
    ),
    FrameworkItem(
        framework=Framework.OWASP_LLM_TOP_10,
        item_id="LLM03",
        name="Supply Chain Vulnerabilities",
        description="Risks from third-party components, models, and data",
        url="https://genai.owasp.org/llmrisk/llm03-supply-chain-vulnerabilities/",
        severity=Severity.HIGH,
    ),
    FrameworkItem(
        framework=Framework.OWASP_LLM_TOP_10,
        item_id="LLM04",
        name="Data and Model Poisoning",
        description="Tampering with training data or model to introduce vulnerabilities",
        url="https://genai.owasp.org/llmrisk/llm04-data-and-model-poisoning/",
        severity=Severity.HIGH,
    ),
    FrameworkItem(
        framework=Framework.OWASP_LLM_TOP_10,
        item_id="LLM05",
        name="Improper Output Handling",
        description="Failing to validate/sanitize LLM outputs before downstream use",
        url="https://genai.owasp.org/llmrisk/llm05-improper-output-handling/",
        severity=Severity.HIGH,
    ),
    FrameworkItem(
        framework=Framework.OWASP_LLM_TOP_10,
        item_id="LLM06",
        name="Excessive Agency",
        description="LLM-based system granted too many permissions or autonomy",
        url="https://genai.owasp.org/llmrisk/llm06-excessive-agency/",
        severity=Severity.HIGH,
    ),
    FrameworkItem(
        framework=Framework.OWASP_LLM_TOP_10,
        item_id="LLM07",
        name="System Prompt Leakage",
        description="Risk of exposing system prompts containing sensitive instructions",
        url="https://genai.owasp.org/llmrisk/llm07-system-prompt-leakage/",
        severity=Severity.MEDIUM,
    ),
    FrameworkItem(
        framework=Framework.OWASP_LLM_TOP_10,
        item_id="LLM08",
        name="Vector and Embedding Weaknesses",
        description="Vulnerabilities in RAG pipelines and vector stores",
        url="https://genai.owasp.org/llmrisk/llm08-vector-and-embedding-weaknesses/",
        severity=Severity.MEDIUM,
    ),
    FrameworkItem(
        framework=Framework.OWASP_LLM_TOP_10,
        item_id="LLM09",
        name="Misinformation",
        description="LLM generating false or misleading information",
        url="https://genai.owasp.org/llmrisk/llm09-misinformation/",
        severity=Severity.MEDIUM,
    ),
    FrameworkItem(
        framework=Framework.OWASP_LLM_TOP_10,
        item_id="LLM10",
        name="Unbounded Consumption",
        description="Excessive resource usage through uncontrolled LLM operations",
        url="https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/",
        severity=Severity.HIGH,
    ),
]

NIST_AI_RMF_FUNCTIONS: list[FrameworkItem] = [
    FrameworkItem(
        framework=Framework.NIST_AI_RMF,
        item_id="GOVERN",
        name="Governance",
        description="Policies and accountability",
        url="https://www.nist.gov/itl/ai-risk-management-framework",
        severity=Severity.INFO,
    ),
    FrameworkItem(
        framework=Framework.NIST_AI_RMF,
        item_id="MAP",
        name="Map",
        description="Context and risk identification",
        url="https://www.nist.gov/itl/ai-risk-management-framework",
        severity=Severity.INFO,
    ),
    FrameworkItem(
        framework=Framework.NIST_AI_RMF,
        item_id="MEASURE",
        name="Measure",
        description="Risk analysis and monitoring",
        url="https://www.nist.gov/itl/ai-risk-management-framework",
        severity=Severity.INFO,
    ),
    FrameworkItem(
        framework=Framework.NIST_AI_RMF,
        item_id="MANAGE",
        name="Manage",
        description="Risk response and mitigation",
        url="https://www.nist.gov/itl/ai-risk-management-framework",
        severity=Severity.INFO,
    ),
]


def _get_owasp(item_id: str) -> FrameworkItem:
    for item in OWASP_LLM_TOP_10:
        if item.item_id == item_id:
            return item
    raise KeyError(item_id)


def _get_nist(item_id: str) -> FrameworkItem:
    for item in NIST_AI_RMF_FUNCTIONS:
        if item.item_id == item_id:
            return item
    raise KeyError(item_id)


ORCHESIS_OWASP_MAPPINGS: list[ComplianceMapping] = [
    ComplianceMapping(_get_owasp("LLM01"), "engine", "prompt_injection_scanner", "full", "Scans incoming messages for prompt injection patterns."),
    ComplianceMapping(_get_owasp("LLM01"), "flow_xray", "suspicious_tool_chains", "partial", "Detects post-injection tool-chain exfiltration patterns."),
    ComplianceMapping(_get_owasp("LLM02"), "engine", "pii_detector", "full", "Detects and optionally redacts PII in requests and responses."),
    ComplianceMapping(_get_owasp("LLM02"), "engine", "secret_scanner", "full", "Detects API keys, tokens, and secret material."),
    ComplianceMapping(_get_owasp("LLM03"), "engine", "integrity_monitor", "partial", "Monitors for unauthorized tool or policy changes."),
    ComplianceMapping(_get_owasp("LLM04"), "behavioral", "anomaly_detection", "detect_only", "Detects behavioral drift that may indicate poisoning."),
    ComplianceMapping(_get_owasp("LLM05"), "engine", "content_filter", "partial", "Filters dangerous output patterns before agent consumption."),
    ComplianceMapping(_get_owasp("LLM05"), "engine", "yara_engine", "partial", "YARA pattern matching for malicious output signatures."),
    ComplianceMapping(_get_owasp("LLM06"), "engine", "tool_allowlist", "full", "Policy-based tool allowlist/denylist enforcement."),
    ComplianceMapping(_get_owasp("LLM06"), "rate_limiter", "per_tool_rate_limiting", "partial", "Limits excessive tool invocations."),
    ComplianceMapping(_get_owasp("LLM06"), "flow_xray", "pattern_detection", "partial", "Finds excessive agency patterns and dead-end behavior."),
    ComplianceMapping(_get_owasp("LLM07"), "engine", "prompt_injection_scanner", "partial", "Detects system prompt extraction attempts."),
    ComplianceMapping(_get_owasp("LLM09"), "recorder", "session_recording", "detect_only", "Enables post-hoc fact-checking and audit."),
    ComplianceMapping(_get_owasp("LLM10"), "cost_tracker", "budget_enforcement", "full", "Budget limits and model cascade reduce runaway spend."),
    ComplianceMapping(_get_owasp("LLM10"), "circuit_breaker", "circuit_breaker", "full", "Prevents cascading failures and retry storms."),
    ComplianceMapping(_get_owasp("LLM10"), "loop_detector", "loop_detection", "full", "Detects and blocks infinite agent loops."),
    ComplianceMapping(_get_owasp("LLM10"), "rate_limiter", "rate_limiting", "full", "Global and per-tool request throttling."),
]

ORCHESIS_NIST_MAPPINGS: list[ComplianceMapping] = [
    ComplianceMapping(_get_nist("GOVERN"), "config", "policy_as_code", "full", "YAML policy defines controls, budgets, and scanner behavior."),
    ComplianceMapping(_get_nist("GOVERN"), "recorder", "audit_trail", "full", "Session recording provides accountability and audit trails."),
    ComplianceMapping(_get_nist("MAP"), "flow_xray", "topology_analysis", "partial", "Maps agent flows and highlights risk vectors."),
    ComplianceMapping(_get_nist("MAP"), "behavioral", "agent_profiling", "partial", "Agent DNA profiles baseline behavior and drift."),
    ComplianceMapping(_get_nist("MEASURE"), "engine", "scanning", "full", "Multiple scanners continuously measure security posture."),
    ComplianceMapping(_get_nist("MEASURE"), "cost_tracker", "cost_measurement", "full", "Tracks cost by request/session/tool/model."),
    ComplianceMapping(_get_nist("MANAGE"), "circuit_breaker", "automated_response", "full", "Automated mitigation via circuit breaker and guards."),
    ComplianceMapping(_get_nist("MANAGE"), "cascade", "cost_management", "full", "Adaptive model cascade manages cost and risk."),
]


@dataclass(frozen=True)
class ComplianceCheck:
    id: str
    framework: str
    requirement: str
    status: str
    evidence: str
    recommendation: str


@dataclass(frozen=True)
class ComplianceReport:
    framework: str
    generated_at: str
    policy_version: str
    checks: list[ComplianceCheck]
    score: float
    pass_count: int
    fail_count: int
    partial_count: int
    summary: str


FRAMEWORK_CHECKS: dict[str, list[dict[str, str]]] = {
    "hipaa": [
        {
            "id": "HIPAA-164.312-a-1",
            "requirement": "Access Control: Unique user identification",
            "check": "agents_have_unique_ids",
            "description": "Each AI agent must have a unique identifier",
        },
        {
            "id": "HIPAA-164.312-a-2",
            "requirement": "Access Control: Emergency access procedure",
            "check": "force_sync_available",
            "description": "Must be able to override agent access in emergencies",
        },
        {
            "id": "HIPAA-164.312-b",
            "requirement": "Audit Controls: Record and examine activity",
            "check": "audit_logging_enabled",
            "description": "All agent activity must be logged",
        },
        {
            "id": "HIPAA-164.312-c",
            "requirement": "Integrity: Protect data from improper alteration",
            "check": "write_restrictions_exist",
            "description": "Write operations must be restricted",
        },
        {
            "id": "HIPAA-164.312-d",
            "requirement": "Authentication: Verify agent identity",
            "check": "agent_authentication_configured",
            "description": "Agents must authenticate before accessing data",
        },
        {
            "id": "HIPAA-164.312-e",
            "requirement": "Transmission Security: Guard data in transit",
            "check": "pii_detection_enabled",
            "description": "PII must be detected and protected in transit",
        },
        {
            "id": "HIPAA-164.308-a-1",
            "requirement": "Risk Analysis: Conduct accurate risk assessment",
            "check": "risk_profiles_available",
            "description": "Agent risk profiles must be computed",
        },
        {
            "id": "HIPAA-164.308-a-5",
            "requirement": "Security Awareness: Incident procedures",
            "check": "incident_detection_enabled",
            "description": "Security incidents must be detected automatically",
        },
        {
            "id": "HIPAA-164.312-c-2",
            "requirement": "Integrity Monitoring: Baseline tamper detection",
            "check": "integrity_monitoring",
            "description": "Critical configuration files should be monitored for tampering",
        },
    ],
    "soc2": [
        {
            "id": "SOC2-CC6.1",
            "requirement": "Logical Access: Restrict access to authorized users",
            "check": "trust_tiers_defined",
            "description": "Agent trust tiers must be defined",
        },
        {
            "id": "SOC2-CC6.2",
            "requirement": "Access Credentials: Manage system credentials",
            "check": "secret_scanning_enabled",
            "description": "Secrets must be scanned and protected",
        },
        {
            "id": "SOC2-CC6.3",
            "requirement": "Access Removal: Remove access when no longer needed",
            "check": "rate_limits_defined",
            "description": "Rate limits must control access volume",
        },
        {
            "id": "SOC2-CC7.2",
            "requirement": "Monitoring: Detect anomalies",
            "check": "anomaly_detection_enabled",
            "description": "Anomalous agent behavior must be detected",
        },
        {
            "id": "SOC2-CC7.3",
            "requirement": "Incident Response: Evaluate and respond",
            "check": "alerts_configured",
            "description": "Alerts must be configured for incidents",
        },
        {
            "id": "SOC2-CC7.4",
            "requirement": "Incident Response: Contain and remediate",
            "check": "force_sync_available",
            "description": "Must be able to force policy updates",
        },
        {
            "id": "SOC2-CC8.1",
            "requirement": "Change Management: Authorize and track changes",
            "check": "policy_versioning_available",
            "description": "Policy changes must be versioned",
        },
        {
            "id": "SOC2-CC7.5",
            "requirement": "Integrity Monitoring: Detect unauthorized changes",
            "check": "integrity_monitoring",
            "description": "Configuration integrity baseline should be monitored",
        },
    ],
    "eu_ai_act": [
        {
            "id": "EU-AI-ACT-9",
            "requirement": "Risk Management System",
            "check": "risk_profiles_available",
            "description": "Continuous risk assessment of AI system",
        },
        {
            "id": "EU-AI-ACT-12",
            "requirement": "Record-keeping: Automatic logging",
            "check": "audit_logging_enabled",
            "description": "High-risk AI systems must log all decisions",
        },
        {
            "id": "EU-AI-ACT-13",
            "requirement": "Transparency: Information to users",
            "check": "decision_explanations_available",
            "description": "Users must understand AI decisions",
        },
        {
            "id": "EU-AI-ACT-14",
            "requirement": "Human Oversight",
            "check": "budget_limits_defined",
            "description": "Human must be able to override AI actions",
        },
        {
            "id": "EU-AI-ACT-15",
            "requirement": "Accuracy, Robustness, Cybersecurity",
            "check": "adversarial_testing_exists",
            "description": "System must be tested against adversarial inputs",
        },
    ],
    "nist_ai_rmf": [
        {
            "id": "NIST-MAP-1.1",
            "requirement": "Identify intended purpose and context",
            "check": "agents_have_unique_ids",
            "description": "AI agents must have defined scope",
        },
        {
            "id": "NIST-MEASURE-2.6",
            "requirement": "Monitor AI system performance",
            "check": "metrics_available",
            "description": "Performance metrics must be collected",
        },
        {
            "id": "NIST-MANAGE-2.2",
            "requirement": "Manage AI risk with controls",
            "check": "denied_operations_defined",
            "description": "Dangerous operations must be restricted",
        },
        {
            "id": "NIST-GOVERN-1.2",
            "requirement": "AI risk management roles assigned",
            "check": "alerts_configured",
            "description": "Alert recipients must be assigned",
        },
        {
            "id": "NIST-MANAGE-2.4",
            "requirement": "Integrity monitoring of safety-critical artifacts",
            "check": "integrity_monitoring",
            "description": "Security baselines should detect policy/config tampering",
        },
    ],
    "owasp_asi": [
        {"id": "ASI-01", "requirement": "Agent Authorization & Control", "check": "asi_01_authorization_control"},
        {"id": "ASI-02", "requirement": "Tool & Function Misuse", "check": "asi_02_tool_misuse"},
        {"id": "ASI-03", "requirement": "Privilege & Access Escalation", "check": "asi_03_privilege_escalation"},
        {"id": "ASI-04", "requirement": "Knowledge & Memory Poisoning", "check": "asi_04_memory_poisoning"},
        {"id": "ASI-05", "requirement": "Supply Chain & Dependency Vulnerabilities", "check": "asi_05_supply_chain"},
        {"id": "ASI-06", "requirement": "Output Integrity & Handling", "check": "asi_06_output_integrity"},
        {"id": "ASI-07", "requirement": "Prompt & Instruction Manipulation", "check": "asi_07_prompt_manipulation"},
        {"id": "ASI-08", "requirement": "Goal & Alignment Hijacking", "check": "asi_08_goal_alignment"},
        {"id": "ASI-09", "requirement": "Logging, Auditing & Monitoring", "check": "asi_09_logging_monitoring"},
        {"id": "ASI-10", "requirement": "Multi-Agent Exploitation", "check": "asi_10_multi_agent"},
    ],
    "mitre_atlas": [
        {"id": "AML-T0051", "requirement": "LLM Prompt Injection", "check": "atlas_t0051_prompt_injection"},
        {"id": "AML-T0054", "requirement": "LLM Jailbreak", "check": "atlas_t0054_jailbreak"},
        {"id": "AML-T0052", "requirement": "Verify ML Artifacts", "check": "atlas_t0052_verify_artifacts"},
        {"id": "AML-T0040", "requirement": "ML Supply Chain Compromise", "check": "atlas_t0040_supply_chain"},
        {"id": "AML-T0048", "requirement": "Exfiltration via ML API", "check": "atlas_t0048_exfiltration"},
        {"id": "AML-T0047", "requirement": "Evade ML Model", "check": "atlas_t0047_evasion"},
    ],
    "cosai": [
        {"id": "COSAI-GOV-01", "requirement": "AI Security Governance", "check": "cosai_gov_01"},
        {"id": "COSAI-RISK-01", "requirement": "AI Risk Assessment", "check": "cosai_risk_01"},
        {"id": "COSAI-SUPPLY-01", "requirement": "AI Supply Chain Security", "check": "cosai_supply_01"},
        {"id": "COSAI-RUNTIME-01", "requirement": "AI Runtime Protection", "check": "cosai_runtime_01"},
        {"id": "COSAI-MONITOR-01", "requirement": "AI Monitoring & Detection", "check": "cosai_monitor_01"},
    ],
    "csa_maestro": [
        {"id": "MAESTRO-L1", "requirement": "Foundation Model Security", "check": "maestro_l1"},
        {"id": "MAESTRO-L2", "requirement": "Data Operations Security", "check": "maestro_l2"},
        {"id": "MAESTRO-L3", "requirement": "Agent Framework Security", "check": "maestro_l3"},
        {"id": "MAESTRO-L4", "requirement": "Tool & Integration Security", "check": "maestro_l4"},
        {"id": "MAESTRO-L5", "requirement": "Agent Orchestration Security", "check": "maestro_l5"},
        {"id": "MAESTRO-L6", "requirement": "Deployment Security", "check": "maestro_l6"},
        {"id": "MAESTRO-L7", "requirement": "Ecosystem Security", "check": "maestro_l7"},
    ],
    "nist_ai_100_2": [
        {"id": "NIST-AML-EVASION", "requirement": "Evasion Attacks", "check": "nist_aml_evasion"},
        {"id": "NIST-AML-POISONING", "requirement": "Poisoning Attacks", "check": "nist_aml_poisoning"},
        {"id": "NIST-AML-PRIVACY", "requirement": "Privacy Attacks", "check": "nist_aml_privacy"},
        {"id": "NIST-AML-MISUSE", "requirement": "Misuse/Abuse", "check": "nist_aml_misuse"},
    ],
}


class FrameworkCrossReference:
    """Map Orchesis capabilities to external framework checks."""

    CROSS_MAP: dict[str, list[str]] = {
        "tool_access_control": [
            "owasp_asi:ASI-02",
            "mitre_atlas:AML-T0051",
            "csa_maestro:MAESTRO-L4",
            "cosai:COSAI-RUNTIME-01",
        ],
        "pii_detection": [
            "owasp_asi:ASI-06",
            "mitre_atlas:AML-T0048",
            "csa_maestro:MAESTRO-L2",
            "nist_ai_100_2:NIST-AML-PRIVACY",
        ],
        "secret_scanning": [
            "owasp_asi:ASI-06",
            "mitre_atlas:AML-T0048",
            "csa_maestro:MAESTRO-L2",
            "cosai:COSAI-SUPPLY-01",
        ],
        "skill_scanning": [
            "owasp_asi:ASI-05",
            "mitre_atlas:AML-T0052",
            "csa_maestro:MAESTRO-L7",
            "cosai:COSAI-SUPPLY-01",
        ],
        "forensics_engine": [
            "owasp_asi:ASI-09",
            "mitre_atlas:AML-T0047",
            "csa_maestro:MAESTRO-L3",
            "cosai:COSAI-MONITOR-01",
        ],
        "budget_limits": [
            "owasp_asi:ASI-08",
            "mitre_atlas:AML-T0054",
            "csa_maestro:MAESTRO-L1",
            "nist_ai_100_2:NIST-AML-MISUSE",
        ],
        "rate_limits": [
            "owasp_asi:ASI-08",
            "mitre_atlas:AML-T0054",
            "nist_ai_100_2:NIST-AML-MISUSE",
        ],
        "session_sandbox": [
            "owasp_asi:ASI-03",
            "owasp_asi:ASI-07",
            "csa_maestro:MAESTRO-L4",
            "nist_ai_100_2:NIST-AML-MISUSE",
        ],
    }

    def get_coverage(self, feature: str) -> list[str]:
        return list(self.CROSS_MAP.get(feature, []))

    def get_feature_for_check(self, framework_check: str) -> list[str]:
        return [feature for feature, refs in self.CROSS_MAP.items() if framework_check in refs]

    def generate_coverage_matrix(self) -> dict[str, Any]:
        all_checks = {
            ref for refs in self.CROSS_MAP.values() for ref in refs
        }
        return {
            "features": {feature: list(refs) for feature, refs in self.CROSS_MAP.items()},
            "covered_checks": len(all_checks),
            "total_checks": sum(len(items) for items in FRAMEWORK_CHECKS.values()),
            "coverage_ratio": (len(all_checks) / sum(len(items) for items in FRAMEWORK_CHECKS.values()))
            if FRAMEWORK_CHECKS
            else 0.0,
        }


class ComplianceEngine:
    """Generate compliance reports from policy and runtime state."""

    def __init__(
        self,
        policy_path: str = "policy.yaml",
        decisions_path: str = ".orchesis/decisions.jsonl",
        incidents_path: str = ".orchesis/incidents.jsonl",
        frameworks: list[Framework] | None = None,
        max_findings: int = 10_000,
        enabled: bool = True,
    ):
        self._policy_path = policy_path
        self._decisions_path = decisions_path
        self._incidents_path = incidents_path
        self._frameworks = frameworks or [Framework.OWASP_LLM_TOP_10, Framework.NIST_AI_RMF]
        self._findings: list[ComplianceFinding] = []
        self._max_findings = max(1, int(max_findings))
        self._enabled = bool(enabled)

    @staticmethod
    def _known_items_for(framework: Framework) -> list[FrameworkItem]:
        if framework == Framework.OWASP_LLM_TOP_10:
            return OWASP_LLM_TOP_10
        if framework == Framework.NIST_AI_RMF:
            return NIST_AI_RMF_FUNCTIONS
        return []

    @staticmethod
    def _mappings_for(framework: Framework) -> list[ComplianceMapping]:
        if framework == Framework.OWASP_LLM_TOP_10:
            return ORCHESIS_OWASP_MAPPINGS
        if framework == Framework.NIST_AI_RMF:
            return ORCHESIS_NIST_MAPPINGS
        return []

    @staticmethod
    def _framework_from_alias(value: str | None) -> Framework | None:
        if not isinstance(value, str):
            return None
        normalized = value.strip().lower()
        aliases = {
            "owasp_llm_top10": Framework.OWASP_LLM_TOP_10,
            "owasp_llm_top10_2025": Framework.OWASP_LLM_TOP_10,
            "owasp": Framework.OWASP_LLM_TOP_10,
            "nist_ai_rmf": Framework.NIST_AI_RMF,
            "nist_ai_rmf_1_0": Framework.NIST_AI_RMF,
            "nist": Framework.NIST_AI_RMF,
            "nist_ai_agent": Framework.NIST_AI_AGENT,
            "nist_ai_agent_2026": Framework.NIST_AI_AGENT,
        }
        return aliases.get(normalized)

    def map_finding(
        self,
        source_module: str,
        source_detail: str,
        description: str,
        severity: Severity,
        evidence: dict[str, Any] | None = None,
    ) -> ComplianceFinding:
        """Map runtime finding to configured frameworks."""
        mappings: list[tuple[str, str]] = []
        source_module_norm = str(source_module or "").strip().lower()
        source_detail_norm = str(source_detail or "").strip().lower()
        for framework in self._frameworks:
            for item in self._mappings_for(framework):
                module_match = source_module_norm == item.orchesis_module.lower()
                detail_match = source_detail_norm == item.orchesis_feature.lower()
                if module_match or detail_match:
                    key = (item.framework_item.framework.value, item.framework_item.item_id)
                    if key not in mappings:
                        mappings.append(key)
        finding = ComplianceFinding(
            finding_id=f"cmp_{len(self._findings) + 1:06d}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            source_module=source_module_norm,
            source_detail=source_detail_norm,
            description=str(description),
            severity=severity,
            framework_mappings=mappings,
            evidence=evidence if isinstance(evidence, dict) else {},
            recommendation="Review policy controls and apply mitigation workflow.",
        )
        self._findings.append(finding)
        if len(self._findings) > self._max_findings:
            overflow = len(self._findings) - self._max_findings
            if overflow > 0:
                self._findings = self._findings[overflow:]
        return finding

    def get_coverage_report(self, framework: Framework | None = None) -> dict[str, Any]:
        """Return per-framework coverage report."""
        target = framework or (self._frameworks[0] if self._frameworks else Framework.OWASP_LLM_TOP_10)
        items = self._known_items_for(target)
        mappings = self._mappings_for(target)
        by_item: dict[str, list[ComplianceMapping]] = {}
        for mapping in mappings:
            by_item.setdefault(mapping.framework_item.item_id, []).append(mapping)
        rows: list[dict[str, Any]] = []
        covered = 0
        for item in items:
            item_mappings = by_item.get(item.item_id, [])
            if not item_mappings:
                status = "not_covered"
                coverage = "none"
            else:
                coverage_values = {m.coverage for m in item_mappings}
                if "full" in coverage_values:
                    status = "covered"
                    coverage = "full"
                    covered += 1
                elif "partial" in coverage_values:
                    status = "partial"
                    coverage = "partial"
                    covered += 1
                elif "detect_only" in coverage_values:
                    status = "detect_only"
                    coverage = "detect_only"
                    covered += 1
                else:
                    status = "not_covered"
                    coverage = "none"
            findings_count = 0
            for finding in self._findings:
                if (target.value, item.item_id) in finding.framework_mappings:
                    findings_count += 1
            rows.append(
                {
                    "id": item.item_id,
                    "name": item.name,
                    "status": status,
                    "coverage": coverage,
                    "modules": sorted({m.orchesis_feature for m in item_mappings}),
                    "findings_count": findings_count,
                }
            )
        total_items = len(items)
        percent = (covered / total_items * 100.0) if total_items > 0 else 0.0
        return {
            "framework": target.value,
            "total_items": total_items,
            "covered_items": covered,
            "coverage_percent": round(percent, 2),
            "items": rows,
        }

    def get_findings(
        self,
        framework: Framework | None = None,
        item_id: str | None = None,
        severity: Severity | None = None,
        limit: int = 100,
    ) -> list[ComplianceFinding]:
        """Return filtered compliance findings."""
        max_items = max(1, int(limit))
        filtered: list[ComplianceFinding] = []
        for finding in reversed(self._findings):
            if severity is not None and finding.severity != severity:
                continue
            if framework is not None and not any(framework.value == fw for fw, _ in finding.framework_mappings):
                continue
            if isinstance(item_id, str) and item_id and not any(item_id == it for _, it in finding.framework_mappings):
                continue
            filtered.append(finding)
            if len(filtered) >= max_items:
                break
        return filtered

    def get_summary(self) -> dict[str, Any]:
        """Aggregate compliance summary across configured frameworks."""
        frameworks_payload: dict[str, dict[str, Any]] = {}
        for framework in self._frameworks:
            report = self.get_coverage_report(framework)
            frameworks_payload[framework.value] = {
                "covered": int(report.get("covered_items", 0)),
                "total": int(report.get("total_items", 0)),
                "percent": float(report.get("coverage_percent", 0.0)),
            }
        by_severity: dict[str, int] = {item.value: 0 for item in Severity}
        for finding in self._findings:
            by_severity[finding.severity.value] = by_severity.get(finding.severity.value, 0) + 1
        return {
            "frameworks": frameworks_payload,
            "total_findings": len(self._findings),
            "findings_by_severity": by_severity,
        }

    def export_report(self, format: str = "json") -> dict[str, Any] | str:
        """Export compliance report in JSON or Markdown."""
        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": self.get_summary(),
            "coverage": {framework.value: self.get_coverage_report(framework) for framework in self._frameworks},
            "findings": [
                {
                    **asdict(finding),
                    "severity": finding.severity.value,
                }
                for finding in self.get_findings(limit=self._max_findings)
            ],
        }
        if str(format).lower() == "markdown":
            lines = [
                "# Orchesis Compliance Report",
                "",
                f"- Generated: {payload['generated_at']}",
                f"- Total Findings: {payload['summary']['total_findings']}",
                "",
                "## Framework Coverage",
            ]
            for fw, item in payload["summary"]["frameworks"].items():
                lines.append(f"- {fw}: {item['covered']}/{item['total']} ({item['percent']}%)")
            lines.append("")
            lines.append("## Recent Findings")
            if not payload["findings"]:
                lines.append("- No findings recorded.")
            else:
                for finding in payload["findings"][:20]:
                    lines.append(
                        f"- [{finding['severity']}] {finding['source_module']}/{finding['source_detail']}: {finding['description']}"
                    )
            return "\n".join(lines) + "\n"
        return payload

    def get_stats(self) -> dict[str, Any]:
        """Summary stats for runtime endpoint integration."""
        summary = self.get_summary()
        return {
            "enabled": self._enabled,
            "frameworks": [framework.value for framework in self._frameworks],
            "max_findings": self._max_findings,
            "total_findings": summary.get("total_findings", 0),
            "coverage": summary.get("frameworks", {}),
            "findings_by_severity": summary.get("findings_by_severity", {}),
        }

    def check(self, framework: str) -> ComplianceReport:
        if framework not in FRAMEWORK_CHECKS:
            raise ValueError(f"Unsupported framework: {framework}")

        policy = self._load_policy()
        checks: list[ComplianceCheck] = []
        for item in FRAMEWORK_CHECKS[framework]:
            fn_name = f"_check_{item['check']}"
            checker = getattr(self, fn_name)
            result = checker(policy)
            checks.append(
                ComplianceCheck(
                    id=item["id"],
                    framework=framework,
                    requirement=item["requirement"],
                    status=result.status,
                    evidence=result.evidence,
                    recommendation=result.recommendation,
                )
            )

        pass_count = sum(1 for check in checks if check.status == "pass")
        fail_count = sum(1 for check in checks if check.status == "fail")
        partial_count = sum(1 for check in checks if check.status == "partial")
        score = self._score(checks)
        summary = (
            f"Score: {score*100:.1f}% ({pass_count}/{len(checks)} pass, "
            f"{partial_count} partial, {fail_count} fail)"
        )
        return ComplianceReport(
            framework=framework,
            generated_at=datetime.now(timezone.utc).isoformat(),
            policy_version=self._policy_hash(policy),
            checks=checks,
            score=score,
            pass_count=pass_count,
            fail_count=fail_count,
            partial_count=partial_count,
            summary=summary,
        )

    def check_all(self) -> dict[str, ComplianceReport]:
        return {framework: self.check(framework) for framework in FRAMEWORK_CHECKS}

    def export_json(self, report: ComplianceReport) -> str:
        return json.dumps(asdict(report), ensure_ascii=False, indent=2)

    def export_markdown(self, report: ComplianceReport) -> str:
        lines = [
            f"# Compliance Report: {report.framework.upper()}",
            f"Generated: {report.generated_at}",
            f"Policy Version: {report.policy_version}",
            "",
            "## Summary",
            report.summary,
            "",
            "## Checks",
            "",
            "| ID | Requirement | Status | Evidence |",
            "|----|-------------|--------|----------|",
        ]
        for check in report.checks:
            lines.append(
                f"| {check.id} | {check.requirement} | {check.status.upper()} | {check.evidence} |"
            )
        recommendations = [check.recommendation for check in report.checks if check.status != "pass"]
        if recommendations:
            lines.extend(["", "## Recommendations"])
            for index, text in enumerate(dict.fromkeys(recommendations), start=1):
                lines.append(f"{index}. {text}")
        return "\n".join(lines) + "\n"

    # Individual checks
    def _check_agents_have_unique_ids(self, policy: dict[str, Any]) -> ComplianceCheck:
        agents: list[str] = []
        for rule in self._rules(policy):
            if self._rule_type(rule) != "context_rules":
                continue
            entries = rule.get("rules")
            if isinstance(entries, list):
                for item in entries:
                    if isinstance(item, dict):
                        agent = item.get("agent")
                        if isinstance(agent, str) and agent and agent != "*":
                            agents.append(agent)
        if not agents:
            return self._result("agents_have_unique_ids", "partial", "No explicit agent IDs", "Define explicit agent identifiers in context_rules")
        if len(set(agents)) != len(agents):
            return self._result("agents_have_unique_ids", "fail", "Duplicate agent IDs detected", "Ensure all agent IDs are unique")
        return self._result("agents_have_unique_ids", "pass", f"{len(agents)} unique agents configured", "")

    def _check_audit_logging_enabled(self, policy: dict[str, Any]) -> ComplianceCheck:
        _ = policy
        decisions = Path(self._decisions_path)
        if decisions.exists():
            return self._result("audit_logging_enabled", "pass", "decisions log exists", "")
        return self._result("audit_logging_enabled", "partial", "decisions log not found", "Enable verify/audit logging in runtime")

    def _check_trust_tiers_defined(self, policy: dict[str, Any]) -> ComplianceCheck:
        tool_access = policy.get("tool_access")
        if isinstance(tool_access, dict) and str(tool_access.get("mode", "")).lower() == "allowlist":
            return self._result("trust_tiers_defined", "pass", "allowlist tool_access mode enabled", "")
        tiers = policy.get("trust_tiers")
        if isinstance(tiers, list) and tiers:
            return self._result("trust_tiers_defined", "pass", f"{len(tiers)} trust tiers defined", "")
        return self._result("trust_tiers_defined", "partial", "No trust tiers defined", "Add trust_tiers section to policy")

    def _check_rate_limits_defined(self, policy: dict[str, Any]) -> ComplianceCheck:
        if any(self._rule_type(rule) == "rate_limit" for rule in self._rules(policy)):
            return self._result("rate_limits_defined", "pass", "rate_limit rule present", "")
        return self._result("rate_limits_defined", "fail", "No rate_limit rule", "Define rate_limit in policy rules")

    def _check_budget_limits_defined(self, policy: dict[str, Any]) -> ComplianceCheck:
        tool_access = policy.get("tool_access")
        if isinstance(tool_access, dict):
            return self._result("budget_limits_defined", "pass", "tool_access controls configured", "")
        if any(self._rule_type(rule) == "budget_limit" for rule in self._rules(policy)):
            return self._result("budget_limits_defined", "pass", "budget_limit rule present", "")
        return self._result("budget_limits_defined", "partial", "No budget_limit rule", "Define budget_limit for human oversight")

    def _check_denied_operations_defined(self, policy: dict[str, Any]) -> ComplianceCheck:
        for rule in self._rules(policy):
            if self._rule_type(rule) != "sql_restriction":
                continue
            denied = rule.get("denied_operations")
            if isinstance(denied, list) and denied:
                return self._result("denied_operations_defined", "pass", "denied SQL operations configured", "")
        return self._result("denied_operations_defined", "fail", "No denied SQL operations", "Add sql_restriction.denied_operations")

    def _check_write_restrictions_exist(self, policy: dict[str, Any]) -> ComplianceCheck:
        tool_access = policy.get("tool_access")
        if isinstance(tool_access, dict):
            return self._result("write_restrictions_exist", "pass", "tool_access controls configured", "")
        for rule in self._rules(policy):
            if self._rule_type(rule) != "file_access":
                continue
            denied = rule.get("denied_paths")
            if isinstance(denied, list) and denied:
                return self._result("write_restrictions_exist", "pass", "Denied paths configured", "")
        return self._result("write_restrictions_exist", "partial", "No denied paths configured", "Add file_access denied_paths")

    def _check_pii_detection_enabled(self, policy: dict[str, Any]) -> ComplianceCheck:
        if self._plugin_enabled(policy, "pii_detector"):
            return self._result("pii_detection_enabled", "pass", "pii_detector plugin enabled", "")
        return self._result("pii_detection_enabled", "partial", "PII detector plugin not enabled", "Enable pii_detector plugin in policy.yaml")

    def _check_secret_scanning_enabled(self, policy: dict[str, Any]) -> ComplianceCheck:
        if self._plugin_enabled(policy, "secret_scanner"):
            return self._result("secret_scanning_enabled", "pass", "secret_scanner enabled", "")
        return self._result("secret_scanning_enabled", "partial", "secret_scanner not enabled", "Enable secret_scanner plugin")

    def _check_incident_detection_enabled(self, policy: dict[str, Any]) -> ComplianceCheck:
        if Path(self._incidents_path).exists():
            return self._result("incident_detection_enabled", "pass", "incidents log detected", "")
        if policy.get("incident_detection") is True:
            return self._result("incident_detection_enabled", "pass", "incident_detection flag enabled", "")
        return self._result("incident_detection_enabled", "partial", "No incident signal configured", "Enable incident detection and incident log")

    def _check_risk_profiles_available(self, policy: dict[str, Any]) -> ComplianceCheck:
        if policy.get("risk_profiles") is True:
            return self._result("risk_profiles_available", "pass", "risk_profiles enabled", "")
        if Path(self._incidents_path).exists():
            return self._result("risk_profiles_available", "partial", "incidents available but risk profile flag absent", "Enable risk_profiles in policy")
        return self._result("risk_profiles_available", "partial", "No risk profile configuration", "Enable risk_profiles")

    def _check_alerts_configured(self, policy: dict[str, Any]) -> ComplianceCheck:
        alerts = policy.get("alerts")
        if isinstance(alerts, dict):
            recipients = alerts.get("recipients")
            if isinstance(recipients, list) and recipients:
                return self._result("alerts_configured", "pass", f"{len(recipients)} alert recipients", "")
        return self._result("alerts_configured", "partial", "No alert recipients configured", "Configure alerts.recipients")

    def _check_force_sync_available(self, policy: dict[str, Any]) -> ComplianceCheck:
        sync_cfg = policy.get("sync")
        if isinstance(sync_cfg, dict) and sync_cfg.get("force_sync") is True:
            return self._result("force_sync_available", "pass", "force_sync enabled", "")
        return self._result("force_sync_available", "partial", "force_sync not configured", "Enable sync.force_sync for emergency overrides")

    def _check_agent_authentication_configured(self, policy: dict[str, Any]) -> ComplianceCheck:
        auth = policy.get("authentication")
        if isinstance(auth, dict) and auth.get("required") is True:
            return self._result("agent_authentication_configured", "pass", "authentication.required=true", "")
        identity = policy.get("identity")
        if isinstance(identity, dict) and identity.get("enabled") is True:
            return self._result("agent_authentication_configured", "pass", "identity enabled", "")
        return self._result("agent_authentication_configured", "partial", "No explicit authentication config", "Configure authentication/identity controls")

    def _check_anomaly_detection_enabled(self, policy: dict[str, Any]) -> ComplianceCheck:
        if policy.get("anomaly_detection") is True:
            return self._result("anomaly_detection_enabled", "pass", "anomaly_detection enabled", "")
        return self._result("anomaly_detection_enabled", "partial", "anomaly_detection not configured", "Enable anomaly_detection")

    def _check_policy_versioning_available(self, policy: dict[str, Any]) -> ComplianceCheck:
        integrity = self._integrity_monitoring_status(policy)
        if isinstance(policy.get("policy_version"), str):
            return self._result(
                "policy_versioning_available",
                "pass",
                f"policy_version field present; integrity={integrity}",
                "",
            )
        if isinstance(policy.get("version"), str):
            return self._result(
                "policy_versioning_available",
                "pass",
                f"version field present; integrity={integrity}",
                "",
            )
        return self._result(
            "policy_versioning_available",
            "partial",
            f"No explicit policy version field; integrity={integrity}",
            "Add policy_version metadata",
        )

    def _check_integrity_monitoring(self, policy: dict[str, Any]) -> ComplianceCheck:
        _ = policy
        baseline_path = self._integrity_baseline_path()
        if not baseline_path.exists():
            return self._result(
                "integrity_monitoring",
                "fail",
                "Integrity baseline not found",
                "Run 'orchesis integrity init' and schedule checks",
            )
        updated_at: datetime | None = None
        try:
            payload = json.loads(baseline_path.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                raw_updated = payload.get("updated_at")
                if isinstance(raw_updated, str) and raw_updated.strip():
                    updated_at = datetime.fromisoformat(raw_updated.replace("Z", "+00:00"))
                    if updated_at.tzinfo is None:
                        updated_at = updated_at.replace(tzinfo=timezone.utc)
        except Exception:
            updated_at = None
        if updated_at is None:
            updated_at = datetime.fromtimestamp(baseline_path.stat().st_mtime, tz=timezone.utc)
        age = datetime.now(timezone.utc) - updated_at
        if age.days <= 7:
            return self._result("integrity_monitoring", "pass", f"Baseline fresh ({age.days}d old)", "")
        return self._result(
            "integrity_monitoring",
            "partial",
            f"Baseline stale ({age.days}d old)",
            "Update integrity baseline at least weekly",
        )

    def _check_decision_explanations_available(self, policy: dict[str, Any]) -> ComplianceCheck:
        if policy.get("decision_explanations") is True:
            return self._result("decision_explanations_available", "pass", "decision_explanations enabled", "")
        # Orchesis core always returns reasons, so this is partially satisfied by design.
        return self._result("decision_explanations_available", "partial", "Reason strings available by default", "Enable decision_explanations metadata")

    def _check_adversarial_testing_exists(self, policy: dict[str, Any]) -> ComplianceCheck:
        _ = policy
        threat_model = Path("docs/THREAT_MODEL.md")
        if threat_model.exists():
            return self._result("adversarial_testing_exists", "pass", "THREAT_MODEL.md found", "")
        return self._result("adversarial_testing_exists", "partial", "No THREAT_MODEL.md found", "Add adversarial testing evidence")

    def _check_metrics_available(self, policy: dict[str, Any]) -> ComplianceCheck:
        integrity = self._integrity_monitoring_status(policy)
        if policy.get("metrics") is True or Path(".orchesis/metrics.json").exists():
            return self._result("metrics_available", "pass", f"Metrics configuration available; integrity={integrity}", "")
        return self._result(
            "metrics_available",
            "partial",
            f"Metrics not configured; integrity={integrity}",
            "Enable metrics collection",
        )

    # OWASP ASI
    def _check_asi_01_authorization_control(self, policy: dict[str, Any]) -> ComplianceCheck:
        has_default_tier = isinstance(policy.get("default_trust_tier"), str)
        has_tool_access = isinstance(policy.get("tool_access"), dict)
        restrictive = str(policy.get("default_trust_tier", "")).lower() in {"intern", "assistant"}
        if has_default_tier and has_tool_access and restrictive:
            return self._result("asi_01_authorization_control", "pass", "trust tiers + tool_access + restrictive default tier", "")
        if has_default_tier and has_tool_access:
            return self._result("asi_01_authorization_control", "partial", "Authorization controls exist but default tier is broad", "Set default_trust_tier to intern/assistant")
        return self._result("asi_01_authorization_control", "fail", "Missing trust tier/tool_access controls", "Define default_trust_tier and tool_access")

    def _check_asi_02_tool_misuse(self, policy: dict[str, Any]) -> ComplianceCheck:
        tool_access = policy.get("tool_access")
        if not isinstance(tool_access, dict):
            return self._result("asi_02_tool_misuse", "fail", "tool_access not configured", "Configure tool_access allowlist")
        mode = str(tool_access.get("mode", "")).lower()
        denied = {item for item in tool_access.get("denied", []) if isinstance(item, str)}
        dangerous = {"shell", "exec", "eval", "subprocess"}
        dangerous_denied = bool(dangerous.intersection(denied))
        has_sandbox_exec = any(
            isinstance(cfg, dict)
            and isinstance(cfg.get("sandbox"), dict)
            and isinstance(cfg.get("sandbox", {}).get("execution"), dict)
            for cfg in (policy.get("session_policies", {}) or {}).values()
        ) if isinstance(policy.get("session_policies"), dict) else False
        if mode == "allowlist" and (dangerous_denied or has_sandbox_exec):
            return self._result("asi_02_tool_misuse", "pass", "allowlist with dangerous tool controls", "")
        if mode in {"allowlist", "denylist"}:
            return self._result("asi_02_tool_misuse", "partial", f"{mode} configured with limited misuse controls", "Deny dangerous tools and configure sandbox.execution")
        return self._result("asi_02_tool_misuse", "fail", "tool_access mode missing", "Use tool_access mode allowlist")

    def _check_asi_03_privilege_escalation(self, policy: dict[str, Any]) -> ComplianceCheck:
        session_policies = policy.get("session_policies")
        has_sessions = isinstance(session_policies, dict) and bool(session_policies)
        has_channel = isinstance(policy.get("channel_policies"), dict) and bool(policy.get("channel_policies"))
        if has_sessions and has_channel:
            return self._result("asi_03_privilege_escalation", "pass", "session_policies + channel_policies configured", "")
        if has_sessions:
            return self._result("asi_03_privilege_escalation", "partial", "session_policies configured but channel_policies missing", "Add channel_policies")
        return self._result("asi_03_privilege_escalation", "fail", "session_policies missing", "Define session_policies with restrictive trust tiers")

    def _check_asi_04_memory_poisoning(self, policy: dict[str, Any]) -> ComplianceCheck:
        scan_cfg = policy.get("scanner")
        has_hidden_scan = isinstance(scan_cfg, dict) and bool(scan_cfg.get("detect_hidden_instructions"))
        has_ioc = isinstance(policy.get("ioc"), dict) and bool(policy.get("ioc", {}).get("enabled"))
        response_scanning = isinstance(policy.get("proxy"), dict) and bool(policy.get("proxy", {}).get("scan_responses"))
        if has_hidden_scan and has_ioc and response_scanning:
            return self._result("asi_04_memory_poisoning", "pass", "hidden instruction + ioc + response scan enabled", "")
        if has_ioc or response_scanning:
            return self._result("asi_04_memory_poisoning", "partial", "partial poisoning defenses configured", "Enable scanner hidden-instruction checks and ioc scanning")
        return self._result("asi_04_memory_poisoning", "fail", "No poisoning controls configured", "Enable scanner/ioc/proxy response scanning")

    def _check_asi_05_supply_chain(self, policy: dict[str, Any]) -> ComplianceCheck:
        scanner_cfg = policy.get("scanner")
        has_skill_scan = isinstance(scanner_cfg, dict) and bool(scanner_cfg.get("scan_skills_before_install"))
        has_remote_scan = isinstance(scanner_cfg, dict) and bool(scanner_cfg.get("remote_scan"))
        has_ioc_supply = isinstance(policy.get("ioc"), dict) and bool(policy.get("ioc", {}).get("supply_chain_patterns"))
        if has_skill_scan and has_remote_scan and has_ioc_supply:
            return self._result("asi_05_supply_chain", "pass", "local+remote skill scanning and supply-chain IoC configured", "")
        if has_skill_scan or has_remote_scan or has_ioc_supply:
            return self._result("asi_05_supply_chain", "partial", "Partial supply-chain controls configured", "Enable skill pre-install scan, remote scan, and supply-chain IoC patterns")
        return self._result("asi_05_supply_chain", "fail", "No supply-chain controls configured", "Configure scanner and IoC supply-chain checks")

    def _check_asi_06_output_integrity(self, policy: dict[str, Any]) -> ComplianceCheck:
        proxy = policy.get("proxy")
        pii = isinstance(proxy, dict) and isinstance(proxy.get("pii_scanning"), dict) and bool(proxy.get("pii_scanning", {}).get("enabled"))
        sec = isinstance(proxy, dict) and isinstance(proxy.get("secret_scanning"), dict) and bool(proxy.get("secret_scanning", {}).get("enabled"))
        red = isinstance(proxy, dict) and isinstance(proxy.get("response_redaction"), dict) and bool(proxy.get("response_redaction", {}).get("enabled"))
        if pii and sec and red:
            return self._result("asi_06_output_integrity", "pass", "PII + secret scan and response redaction configured", "")
        if pii or sec or red:
            return self._result("asi_06_output_integrity", "partial", "Only subset of output controls configured", "Enable proxy pii_scanning, secret_scanning and response_redaction")
        return self._result("asi_06_output_integrity", "fail", "No output integrity controls configured", "Configure proxy output scanning/redaction")

    def _check_asi_07_prompt_manipulation(self, policy: dict[str, Any]) -> ComplianceCheck:
        has_ioc_injection = isinstance(policy.get("ioc"), dict) and bool(policy.get("ioc", {}).get("prompt_injection_patterns"))
        scanner_cfg = policy.get("scanner")
        has_unicode = isinstance(scanner_cfg, dict) and bool(scanner_cfg.get("detect_unicode_tricks"))
        has_behavioral_sandbox = any(
            isinstance(cfg, dict)
            and isinstance(cfg.get("sandbox"), dict)
            and (cfg.get("sandbox", {}).get("execution") or cfg.get("sandbox", {}).get("data"))
            for cfg in (policy.get("session_policies", {}) or {}).values()
        ) if isinstance(policy.get("session_policies"), dict) else False
        if has_ioc_injection and has_unicode and has_behavioral_sandbox:
            return self._result("asi_07_prompt_manipulation", "pass", "injection+unicode+sandbox controls configured", "")
        if has_ioc_injection or has_unicode or has_behavioral_sandbox:
            return self._result("asi_07_prompt_manipulation", "partial", "Partial prompt-manipulation controls configured", "Enable IoC injection patterns, unicode checks, sandbox behavior controls")
        return self._result("asi_07_prompt_manipulation", "fail", "No prompt-manipulation controls configured", "Configure scanner/ioc/sandbox controls")

    def _check_asi_08_goal_alignment(self, policy: dict[str, Any]) -> ComplianceCheck:
        has_budget = any(self._rule_type(rule) == "budget_limit" for rule in self._rules(policy))
        has_rate = any(self._rule_type(rule) == "rate_limit" for rule in self._rules(policy))
        has_token = isinstance(policy.get("token_limits"), dict)
        if has_budget and has_rate and has_token:
            return self._result("asi_08_goal_alignment", "pass", "budget+rate+token limits configured", "")
        if has_budget and has_rate:
            return self._result("asi_08_goal_alignment", "partial", "budget/rate configured but token limits missing", "Add token_limits")
        return self._result("asi_08_goal_alignment", "fail", "Missing budget/rate controls", "Configure budget_limit and rate_limit")

    def _check_asi_09_logging_monitoring(self, policy: dict[str, Any]) -> ComplianceCheck:
        has_logging = isinstance(policy.get("logging"), dict)
        has_redaction = isinstance(policy.get("logging"), dict) and isinstance(policy.get("logging", {}).get("redaction"), dict) and bool(policy.get("logging", {}).get("redaction", {}).get("enabled"))
        has_alerts = isinstance(policy.get("alerts"), dict) and bool(policy.get("alerts"))
        if has_logging and has_redaction and has_alerts:
            return self._result("asi_09_logging_monitoring", "pass", "logging+redaction+alerts configured", "")
        if has_logging or has_alerts:
            return self._result("asi_09_logging_monitoring", "partial", "partial monitoring controls configured", "Enable logging.redaction and alerts integrations")
        return self._result("asi_09_logging_monitoring", "fail", "No monitoring controls configured", "Configure logging and alerts")

    def _check_asi_10_multi_agent(self, policy: dict[str, Any]) -> ComplianceCheck:
        agents = policy.get("agents")
        has_agent_tiers = isinstance(agents, list) and any(isinstance(item, dict) and isinstance(item.get("trust_tier"), str) for item in agents)
        has_sync = isinstance(policy.get("sync"), dict)
        has_channels = isinstance(policy.get("channel_policies"), dict) and bool(policy.get("channel_policies"))
        if has_agent_tiers and has_sync and has_channels:
            return self._result("asi_10_multi_agent", "pass", "agent tiers + sync + channels configured", "")
        if has_agent_tiers:
            return self._result("asi_10_multi_agent", "partial", "Agent tiers configured, distributed controls partial", "Configure sync and channel_policies")
        return self._result("asi_10_multi_agent", "fail", "No per-agent trust tier controls", "Define agents with trust_tier")

    # MITRE ATLAS
    def _check_atlas_t0051_prompt_injection(self, policy: dict[str, Any]) -> ComplianceCheck:
        has_ioc = isinstance(policy.get("ioc"), dict) and bool(policy.get("ioc", {}).get("prompt_injection_patterns"))
        has_skill_scan = isinstance(policy.get("scanner"), dict) and bool(policy.get("scanner", {}).get("detect_hidden_instructions"))
        has_allowlist = isinstance(policy.get("tool_access"), dict) and str(policy.get("tool_access", {}).get("mode", "")).lower() == "allowlist"
        if has_ioc and has_skill_scan and has_allowlist:
            return self._result("atlas_t0051_prompt_injection", "pass", "ioc + skill scanner + allowlist configured", "")
        if has_ioc or has_skill_scan or has_allowlist:
            return self._result("atlas_t0051_prompt_injection", "partial", "Partial prompt injection controls configured", "Enable IoC prompt injection patterns, hidden instruction scanner, and allowlist")
        return self._result("atlas_t0051_prompt_injection", "fail", "No prompt injection controls configured", "Configure IoC/scanner/tool_access")

    def _check_atlas_t0054_jailbreak(self, policy: dict[str, Any]) -> ComplianceCheck:
        has_budget = any(self._rule_type(rule) == "budget_limit" for rule in self._rules(policy))
        has_rate = any(self._rule_type(rule) == "rate_limit" for rule in self._rules(policy))
        has_forensics = isinstance(policy.get("incident_detection"), bool) and bool(policy.get("incident_detection"))
        if has_budget and has_rate and has_forensics:
            return self._result("atlas_t0054_jailbreak", "pass", "budget/rate/forensics controls configured", "")
        if has_budget or has_rate:
            return self._result("atlas_t0054_jailbreak", "partial", "Only rate/budget controls configured", "Enable incident_detection/forensics")
        return self._result("atlas_t0054_jailbreak", "fail", "No jailbreak controls configured", "Configure budget_limit and rate_limit")

    def _check_atlas_t0052_verify_artifacts(self, policy: dict[str, Any]) -> ComplianceCheck:
        scanner_cfg = policy.get("scanner")
        has_skill_scan = isinstance(scanner_cfg, dict) and bool(scanner_cfg.get("scan_skills_before_install"))
        has_remote = isinstance(scanner_cfg, dict) and bool(scanner_cfg.get("remote_scan"))
        has_ioc_supply = isinstance(policy.get("ioc"), dict) and bool(policy.get("ioc", {}).get("supply_chain_patterns"))
        if has_skill_scan and has_remote and has_ioc_supply:
            return self._result("atlas_t0052_verify_artifacts", "pass", "artifact verification checks configured", "")
        if has_skill_scan or has_remote or has_ioc_supply:
            return self._result("atlas_t0052_verify_artifacts", "partial", "Partial artifact verification controls configured", "Enable scanner.remote_scan and supply-chain IoC patterns")
        return self._result("atlas_t0052_verify_artifacts", "fail", "No artifact verification controls configured", "Configure pre-install and remote scanning")

    def _check_atlas_t0040_supply_chain(self, policy: dict[str, Any]) -> ComplianceCheck:
        has_secret = isinstance(policy.get("proxy"), dict) and isinstance(policy.get("proxy", {}).get("secret_scanning"), dict) and bool(policy.get("proxy", {}).get("secret_scanning", {}).get("enabled"))
        has_ioc = isinstance(policy.get("ioc"), dict) and bool(policy.get("ioc", {}).get("enabled"))
        has_perm = isinstance(policy.get("network_scanner"), dict) and bool(policy.get("network_scanner", {}).get("check_permissions"))
        if has_secret and has_ioc and has_perm:
            return self._result("atlas_t0040_supply_chain", "pass", "secret/ioc/permission controls configured", "")
        if has_secret or has_ioc:
            return self._result("atlas_t0040_supply_chain", "partial", "Partial supply-chain controls configured", "Enable network scanner permission checks")
        return self._result("atlas_t0040_supply_chain", "fail", "No supply-chain compromise controls configured", "Enable secret scanning and IoC controls")

    def _check_atlas_t0048_exfiltration(self, policy: dict[str, Any]) -> ComplianceCheck:
        proxy = policy.get("proxy")
        has_secret = isinstance(proxy, dict) and isinstance(proxy.get("secret_scanning"), dict) and bool(proxy.get("secret_scanning", {}).get("enabled"))
        has_pii = isinstance(proxy, dict) and isinstance(proxy.get("pii_scanning"), dict) and bool(proxy.get("pii_scanning", {}).get("enabled"))
        denied_domains = any(
            isinstance(cfg, dict)
            and isinstance(cfg.get("sandbox"), dict)
            and isinstance(cfg.get("sandbox", {}).get("network"), dict)
            and isinstance(cfg.get("sandbox", {}).get("network", {}).get("denied_domains"), list)
            and bool(cfg.get("sandbox", {}).get("network", {}).get("denied_domains"))
            for cfg in (policy.get("session_policies", {}) or {}).values()
        ) if isinstance(policy.get("session_policies"), dict) else False
        if has_secret and has_pii and denied_domains:
            return self._result("atlas_t0048_exfiltration", "pass", "secret+pii scanning and denied domains configured", "")
        if has_secret or has_pii or denied_domains:
            return self._result("atlas_t0048_exfiltration", "partial", "Partial exfiltration controls configured", "Enable secret/PII scanning and denied_domains")
        return self._result("atlas_t0048_exfiltration", "fail", "No exfiltration controls configured", "Configure scanning and network denied_domains")

    def _check_atlas_t0047_evasion(self, policy: dict[str, Any]) -> ComplianceCheck:
        has_forensics = bool(policy.get("incident_detection")) or bool(policy.get("anomaly_detection"))
        has_multi_rule = len(self._rules(policy)) >= 2
        if has_forensics and has_multi_rule:
            return self._result("atlas_t0047_evasion", "pass", "forensics/anomaly + multi-rule policy configured", "")
        if has_multi_rule:
            return self._result("atlas_t0047_evasion", "partial", "Multi-rule policy present but anomaly/forensics limited", "Enable incident_detection/anomaly_detection")
        return self._result("atlas_t0047_evasion", "fail", "Single-rule/no-detection evasion posture", "Add multiple rules and anomaly detection")

    # CoSAI
    def _check_cosai_gov_01(self, policy: dict[str, Any]) -> ComplianceCheck:
        has_policy = isinstance(policy, dict) and bool(policy)
        has_version = isinstance(policy.get("version"), str) or isinstance(policy.get("policy_version"), str)
        has_compliance = bool(policy.get("compliance")) or Path("docs/SECURITY.md").exists()
        if has_policy and has_version and has_compliance:
            return self._result("cosai_gov_01", "pass", "policy-as-code + versioning + compliance artifacts", "")
        if has_policy and has_version:
            return self._result("cosai_gov_01", "partial", "policy/versioning configured but compliance metadata minimal", "Add compliance reporting metadata")
        return self._result("cosai_gov_01", "fail", "Missing governance metadata", "Define policy versioning and compliance metadata")

    def _check_cosai_risk_01(self, policy: dict[str, Any]) -> ComplianceCheck:
        has_risk = bool(policy.get("risk_profiles"))
        has_gap = bool(policy.get("compliance"))
        has_network = bool(policy.get("network_scanner"))
        if has_risk and has_gap and has_network:
            return self._result("cosai_risk_01", "pass", "risk/gap/network checks configured", "")
        if has_risk or has_gap:
            return self._result("cosai_risk_01", "partial", "Partial risk assessment controls configured", "Enable network_scanner and compliance gap config")
        return self._result("cosai_risk_01", "fail", "No explicit AI risk assessment controls configured", "Enable risk_profiles and compliance gap analysis")

    def _check_cosai_supply_01(self, policy: dict[str, Any]) -> ComplianceCheck:
        scanner_cfg = policy.get("scanner")
        has_skill = isinstance(scanner_cfg, dict) and bool(scanner_cfg.get("scan_skills_before_install"))
        has_ioc = isinstance(policy.get("ioc"), dict) and bool(policy.get("ioc", {}).get("enabled"))
        has_remote = isinstance(scanner_cfg, dict) and bool(scanner_cfg.get("remote_scan"))
        if has_skill and has_ioc and has_remote:
            return self._result("cosai_supply_01", "pass", "supply-chain scanner and IoC controls configured", "")
        if has_skill or has_ioc:
            return self._result("cosai_supply_01", "partial", "Partial supply-chain controls configured", "Enable scanner.remote_scan and ioc.enabled")
        return self._result("cosai_supply_01", "fail", "No AI supply-chain security controls configured", "Configure scanner and ioc controls")

    def _check_cosai_runtime_01(self, policy: dict[str, Any]) -> ComplianceCheck:
        has_runtime = bool(policy.get("rules"))
        has_tool = isinstance(policy.get("tool_access"), dict)
        has_limits = (
            any(self._rule_type(rule) == "budget_limit" for rule in self._rules(policy))
            and any(self._rule_type(rule) == "rate_limit" for rule in self._rules(policy))
            and isinstance(policy.get("token_limits"), dict)
        )
        if has_runtime and has_tool and has_limits:
            return self._result("cosai_runtime_01", "pass", "runtime/tool access/limits configured", "")
        if has_runtime and has_tool:
            return self._result("cosai_runtime_01", "partial", "runtime enforcement configured with partial limits", "Add token_limits and complete rate/budget controls")
        return self._result("cosai_runtime_01", "fail", "Runtime protection controls incomplete", "Configure rules and tool_access")

    def _check_cosai_monitor_01(self, policy: dict[str, Any]) -> ComplianceCheck:
        has_logging = isinstance(policy.get("logging"), dict)
        has_incident = bool(policy.get("incident_detection"))
        has_alerts = isinstance(policy.get("alerts"), dict) and bool(policy.get("alerts"))
        if has_logging and has_incident and has_alerts:
            return self._result("cosai_monitor_01", "pass", "monitoring/detection/alerts configured", "")
        if has_logging or has_incident:
            return self._result("cosai_monitor_01", "partial", "Partial monitoring controls configured", "Enable alerts integrations")
        return self._result("cosai_monitor_01", "fail", "No monitoring controls configured", "Enable logging + incident_detection + alerts")

    # CSA MAESTRO
    def _check_maestro_l1(self, policy: dict[str, Any]) -> ComplianceCheck:
        has_token = isinstance(policy.get("token_limits"), dict)
        has_budget = any(self._rule_type(rule) == "budget_limit" for rule in self._rules(policy))
        if has_token and has_budget:
            return self._result("maestro_l1", "pass", "token + budget controls configured", "")
        if has_token or has_budget:
            return self._result("maestro_l1", "partial", "Only one of token/budget controls configured", "Configure token_limits and budget_limit")
        return self._result("maestro_l1", "fail", "No foundation model resource controls", "Add token_limits and budget_limit")

    def _check_maestro_l2(self, policy: dict[str, Any]) -> ComplianceCheck:
        proxy = policy.get("proxy")
        has_pii = isinstance(proxy, dict) and isinstance(proxy.get("pii_scanning"), dict) and bool(proxy.get("pii_scanning", {}).get("enabled"))
        has_secret = isinstance(proxy, dict) and isinstance(proxy.get("secret_scanning"), dict) and bool(proxy.get("secret_scanning", {}).get("enabled"))
        has_redaction = isinstance(policy.get("logging"), dict) and isinstance(policy.get("logging", {}).get("redaction"), dict) and bool(policy.get("logging", {}).get("redaction", {}).get("enabled"))
        if has_pii and has_secret and has_redaction:
            return self._result("maestro_l2", "pass", "PII+secret scans and audit redaction configured", "")
        if has_pii or has_secret or has_redaction:
            return self._result("maestro_l2", "partial", "Partial data operations controls configured", "Enable proxy scanning + logging.redaction")
        return self._result("maestro_l2", "fail", "No data operations controls configured", "Enable PII/secret scanning and redaction")

    def _check_maestro_l3(self, policy: dict[str, Any]) -> ComplianceCheck:
        has_policy_engine = bool(policy.get("rules"))
        has_agent_tiers = isinstance(policy.get("agents"), list) and bool(policy.get("agents"))
        has_plugins = isinstance(policy.get("plugins"), list)
        if has_policy_engine and has_agent_tiers and has_plugins:
            return self._result("maestro_l3", "pass", "policy engine + agent tiers + plugin model configured", "")
        if has_policy_engine and has_agent_tiers:
            return self._result("maestro_l3", "partial", "core agent framework controls configured", "Add plugin configuration metadata")
        return self._result("maestro_l3", "fail", "Agent framework controls incomplete", "Configure rules and per-agent tiers")

    def _check_maestro_l4(self, policy: dict[str, Any]) -> ComplianceCheck:
        has_tool_access = isinstance(policy.get("tool_access"), dict)
        has_mcp_scan = isinstance(policy.get("scanner"), dict) and bool(policy.get("scanner", {}).get("scan_mcp"))
        has_sandbox = isinstance(policy.get("session_policies"), dict) and any(
            isinstance(item, dict) and isinstance(item.get("sandbox"), dict)
            for item in policy.get("session_policies", {}).values()
        )
        if has_tool_access and has_mcp_scan and has_sandbox:
            return self._result("maestro_l4", "pass", "tool access + MCP scan + sandbox configured", "")
        if has_tool_access and has_sandbox:
            return self._result("maestro_l4", "partial", "tool access and sandbox configured", "Enable scanner.scan_mcp")
        return self._result("maestro_l4", "fail", "Tool/integration security controls incomplete", "Configure tool_access, MCP scan, and sandbox")

    def _check_maestro_l5(self, policy: dict[str, Any]) -> ComplianceCheck:
        has_agent_tiers = isinstance(policy.get("agents"), list) and bool(policy.get("agents"))
        has_sync = isinstance(policy.get("sync"), dict)
        has_channel = isinstance(policy.get("channel_policies"), dict) and bool(policy.get("channel_policies"))
        if has_agent_tiers and has_sync and has_channel:
            return self._result("maestro_l5", "pass", "orchestration controls configured", "")
        if has_agent_tiers and has_channel:
            return self._result("maestro_l5", "partial", "channel + multi-agent configured but sync missing", "Configure sync for distributed orchestration")
        return self._result("maestro_l5", "fail", "Orchestration controls incomplete", "Configure agents, sync, and channel_policies")

    def _check_maestro_l6(self, policy: dict[str, Any]) -> ComplianceCheck:
        net = policy.get("network_scanner")
        has_exposure = isinstance(net, dict) and bool(net.get("enabled"))
        has_perms = isinstance(net, dict) and bool(net.get("check_permissions"))
        has_gate = isinstance(policy.get("ci_gate"), dict) or bool(policy.get("gate"))
        if has_exposure and has_perms and has_gate:
            return self._result("maestro_l6", "pass", "deployment scanner + permissions + gate configured", "")
        if has_exposure or has_perms:
            return self._result("maestro_l6", "partial", "partial deployment controls configured", "Enable CI/CD security gate metadata")
        return self._result("maestro_l6", "fail", "Deployment controls missing", "Enable network scanner and gate metadata")

    def _check_maestro_l7(self, policy: dict[str, Any]) -> ComplianceCheck:
        has_marketplace = isinstance(policy.get("marketplace"), dict) and bool(policy.get("marketplace"))
        has_remote = isinstance(policy.get("scanner"), dict) and bool(policy.get("scanner", {}).get("remote_scan"))
        has_ioc = isinstance(policy.get("ioc"), dict) and bool(policy.get("ioc", {}).get("enabled"))
        if has_marketplace and has_remote and has_ioc:
            return self._result("maestro_l7", "pass", "ecosystem marketplace + remote scanner + ioc configured", "")
        if has_remote or has_ioc:
            return self._result("maestro_l7", "partial", "partial ecosystem controls configured", "Configure marketplace metadata and IoC database")
        return self._result("maestro_l7", "fail", "Ecosystem controls missing", "Enable marketplace, remote scanner, and ioc")

    # NIST AI 100-2
    def _check_nist_aml_evasion(self, policy: dict[str, Any]) -> ComplianceCheck:
        has_forensics = bool(policy.get("incident_detection")) or bool(policy.get("anomaly_detection"))
        has_multi_rule = len(self._rules(policy)) >= 2
        if has_forensics and has_multi_rule:
            return self._result("nist_aml_evasion", "pass", "forensics/anomaly + multi-rule policy present", "")
        if has_multi_rule:
            return self._result("nist_aml_evasion", "partial", "multi-rule policy present but anomaly detection limited", "Enable incident_detection/anomaly_detection")
        return self._result("nist_aml_evasion", "fail", "evasion controls not configured", "Add forensics and anomaly detection controls")

    def _check_nist_aml_poisoning(self, policy: dict[str, Any]) -> ComplianceCheck:
        has_skill = isinstance(policy.get("scanner"), dict) and bool(policy.get("scanner", {}).get("scan_skills_before_install"))
        has_ioc_supply = isinstance(policy.get("ioc"), dict) and bool(policy.get("ioc", {}).get("supply_chain_patterns"))
        has_integrity = bool(policy.get("integrity_checks"))
        if has_skill and has_ioc_supply and has_integrity:
            return self._result("nist_aml_poisoning", "pass", "skill scan + supply chain IoC + integrity checks configured", "")
        if has_skill and has_ioc_supply:
            return self._result("nist_aml_poisoning", "partial", "poisoning controls configured without integrity_checks metadata", "Enable integrity_checks metadata")
        return self._result("nist_aml_poisoning", "fail", "poisoning controls missing", "Configure scanner and supply-chain IoC")

    def _check_nist_aml_privacy(self, policy: dict[str, Any]) -> ComplianceCheck:
        proxy = policy.get("proxy")
        has_pii = isinstance(proxy, dict) and isinstance(proxy.get("pii_scanning"), dict) and bool(proxy.get("pii_scanning", {}).get("enabled"))
        has_secret = isinstance(proxy, dict) and isinstance(proxy.get("secret_scanning"), dict) and bool(proxy.get("secret_scanning", {}).get("enabled"))
        has_redaction = isinstance(policy.get("logging"), dict) and isinstance(policy.get("logging", {}).get("redaction"), dict) and bool(policy.get("logging", {}).get("redaction", {}).get("enabled"))
        if has_pii and has_secret and has_redaction:
            return self._result("nist_aml_privacy", "pass", "privacy controls fully configured", "")
        if has_pii or has_secret or has_redaction:
            return self._result("nist_aml_privacy", "partial", "partial privacy controls configured", "Enable PII/secret scanning and redaction")
        return self._result("nist_aml_privacy", "fail", "privacy controls not configured", "Configure proxy scanning and redaction")

    def _check_nist_aml_misuse(self, policy: dict[str, Any]) -> ComplianceCheck:
        has_tool = isinstance(policy.get("tool_access"), dict)
        has_budget = any(self._rule_type(rule) == "budget_limit" for rule in self._rules(policy))
        has_rate = any(self._rule_type(rule) == "rate_limit" for rule in self._rules(policy))
        has_scope = isinstance(policy.get("session_policies"), dict) or isinstance(policy.get("channel_policies"), dict)
        if has_tool and has_budget and has_rate and has_scope:
            return self._result("nist_aml_misuse", "pass", "misuse controls fully configured", "")
        if has_tool and (has_budget or has_rate):
            return self._result("nist_aml_misuse", "partial", "core misuse controls configured", "Add session/channel scoping policies")
        return self._result("nist_aml_misuse", "fail", "misuse controls missing", "Configure tool_access, budget/rate, and scope policies")

    def _load_policy(self) -> dict[str, Any]:
        path = Path(self._policy_path)
        if not path.exists():
            return {}
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        return loaded if isinstance(loaded, dict) else {}

    def _policy_hash(self, policy: dict[str, Any]) -> str:
        payload = yaml.dump(policy, sort_keys=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _integrity_monitoring_status(self, policy: dict[str, Any]) -> str:
        if bool(policy.get("integrity_checks")):
            return "enabled"
        if self._integrity_baseline_path().exists():
            return "baseline_present"
        return "disabled"

    def _integrity_baseline_path(self) -> Path:
        policy_parent = Path(self._policy_path).resolve().parent
        return policy_parent / ".orchesis" / "integrity.json"

    def _rules(self, policy: dict[str, Any]) -> list[dict[str, Any]]:
        rules = policy.get("rules")
        if not isinstance(rules, list):
            return []
        return [rule for rule in rules if isinstance(rule, dict)]

    def _rule_type(self, rule: dict[str, Any]) -> str:
        value = rule.get("type")
        if isinstance(value, str) and value:
            return value
        name = rule.get("name")
        return name if isinstance(name, str) else ""

    def _plugin_enabled(self, policy: dict[str, Any], name: str) -> bool:
        plugins = policy.get("plugins")
        if not isinstance(plugins, list):
            return False
        for plugin in plugins:
            if not isinstance(plugin, dict):
                continue
            plugin_name = plugin.get("name")
            if isinstance(plugin_name, str) and plugin_name == name:
                return True
        return False

    def _score(self, checks: list[ComplianceCheck]) -> float:
        if not checks:
            return 0.0
        points = 0.0
        for check in checks:
            if check.status == "pass":
                points += 1.0
            elif check.status == "partial":
                points += 0.5
        return points / len(checks)

    def _result(self, check_name: str, status: str, evidence: str, recommendation: str) -> ComplianceCheck:
        return ComplianceCheck(
            id=check_name,
            framework="internal",
            requirement=check_name,
            status=status,
            evidence=evidence,
            recommendation=recommendation,
        )
