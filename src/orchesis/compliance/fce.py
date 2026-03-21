"""
Fleet Compliance Engine v1 - EU AI Act compliance checks.

Checks fleet configuration and runtime state against
EU AI Act Articles 9, 12, 72 requirements.

Usage:
    engine = FleetComplianceEngine(policy, fleet_state)
    report = engine.evaluate()
    print(report.summary())
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import time
from typing import Any, Optional

from orchesis.utils.log import get_logger

logger = get_logger(__name__)


class ComplianceStatus(str, Enum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


@dataclass
class ComplianceRule:
    rule_id: str
    name: str
    article: str
    description: str
    severity: str = "HIGH"


@dataclass
class ComplianceViolation:
    rule_id: str
    rule_name: str
    article: str
    description: str
    severity: str
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""


@dataclass
class ComplianceReport:
    status: ComplianceStatus = ComplianceStatus.UNKNOWN
    violations: list[ComplianceViolation] = field(default_factory=list)
    checked_rules: int = 0
    passed_rules: int = 0
    timestamp: float = field(default_factory=time.time)
    fleet_size: int = 0

    def summary(self) -> str:
        lines = [
            f"Fleet Compliance Report - {self.status.value.upper()}",
            f"Rules checked: {self.checked_rules}, Passed: {self.passed_rules}, Violations: {len(self.violations)}",
            f"Fleet size: {self.fleet_size}",
        ]
        for violation in self.violations:
            lines.append(f"  [{violation.severity}] {violation.article}: {violation.rule_name}")
            lines.append(f"    {violation.description}")
            if violation.remediation:
                lines.append(f"    Fix: {violation.remediation}")
        return "\n".join(lines)


RULE_ART9_RISK_MANAGEMENT = ComplianceRule(
    rule_id="EU-ART9-001",
    name="Risk Management System",
    article="Article 9",
    description=(
        "High-risk AI systems shall have a risk management system "
        "established, implemented, documented and maintained."
    ),
    severity="HIGH",
)

RULE_ART12_RECORD_KEEPING = ComplianceRule(
    rule_id="EU-ART12-001",
    name="Automatic Logging",
    article="Article 12",
    description=(
        "High-risk AI systems shall have logging capabilities "
        "that enable monitoring of operation and traceability."
    ),
    severity="HIGH",
)

RULE_ART72_MONITORING = ComplianceRule(
    rule_id="EU-ART72-001",
    name="Post-Market Monitoring",
    article="Article 72",
    description=(
        "Providers shall establish and document a post-market "
        "monitoring system proportionate to the AI technology."
    ),
    severity="HIGH",
)

RULE_ART9_TRANSPARENCY = ComplianceRule(
    rule_id="EU-ART9-002",
    name="Risk Assessment Documentation",
    article="Article 9",
    description=(
        "Risk management shall include identification and analysis "
        "of known and foreseeable risks."
    ),
    severity="MEDIUM",
)

ALL_RULES = [
    RULE_ART9_RISK_MANAGEMENT,
    RULE_ART12_RECORD_KEEPING,
    RULE_ART72_MONITORING,
    RULE_ART9_TRANSPARENCY,
]


class FleetComplianceEngine:
    """
    Evaluate fleet compliance against EU AI Act.

    Args:
        policy: loaded policy mapping
        fleet_state: current fleet state
    """

    def __init__(self, policy: dict[str, Any] | None = None, fleet_state: dict[str, Any] | None = None):
        self.policy = policy or {}
        self.fleet_state = fleet_state or {}
        self.rules = list(ALL_RULES)

    def _check_art9_risk_management(self) -> Optional[ComplianceViolation]:
        has_scanning = bool(self.fleet_state.get("security_scanning_enabled", False))
        has_incidents = bool(self.fleet_state.get("incident_db_enabled", False))
        if has_scanning and has_incidents:
            return None
        missing: list[str] = []
        if not has_scanning:
            missing.append("security scanning")
        if not has_incidents:
            missing.append("incident database")
        return ComplianceViolation(
            rule_id="EU-ART9-001",
            rule_name="Risk Management System",
            article="Article 9",
            description=f"Missing components: {', '.join(missing)}",
            severity="HIGH",
            evidence={"scanning": has_scanning, "incidents": has_incidents},
            remediation="Enable Injection Shield and CASURA incident database.",
        )

    def _check_art12_record_keeping(self) -> Optional[ComplianceViolation]:
        logging_on = bool(self.fleet_state.get("logging_enabled", False))
        if logging_on:
            return None
        return ComplianceViolation(
            rule_id="EU-ART12-001",
            rule_name="Automatic Logging",
            article="Article 12",
            description="Fleet logging is not enabled. Cannot ensure traceability.",
            severity="HIGH",
            evidence={"logging_enabled": False},
            remediation="Set logging: { enabled: true } in orchesis.yaml policy.",
        )

    def _check_art72_monitoring(self) -> Optional[ComplianceViolation]:
        monitoring = bool(self.fleet_state.get("monitoring_enabled", False))
        agents = self.fleet_state.get("agents", [])
        safe_agents = agents if isinstance(agents, list) else []
        if monitoring and len(safe_agents) > 0:
            return None
        issues: list[str] = []
        if not monitoring:
            issues.append("monitoring not enabled")
        if not safe_agents:
            issues.append("no agents registered")
        return ComplianceViolation(
            rule_id="EU-ART72-001",
            rule_name="Post-Market Monitoring",
            article="Article 72",
            description=f"Monitoring gaps: {', '.join(issues)}",
            severity="HIGH",
            evidence={"monitoring": monitoring, "agent_count": len(safe_agents)},
            remediation="Enable monitoring and register agents with orchesis.",
        )

    def _check_art9_transparency(self) -> Optional[ComplianceViolation]:
        path = self.fleet_state.get("risk_assessment_path")
        if isinstance(path, str) and path.strip():
            return None
        if path:
            return None
        return ComplianceViolation(
            rule_id="EU-ART9-002",
            rule_name="Risk Assessment Documentation",
            article="Article 9",
            description="No risk assessment document path configured.",
            severity="MEDIUM",
            evidence={"risk_assessment_path": None},
            remediation="Create risk assessment doc and set risk_assessment_path in config.",
        )

    def evaluate(self) -> ComplianceReport:
        logger.info(
            "Running fleet compliance evaluation",
            extra={"component": "fce", "rule_count": len(self.rules)},
        )
        checkers = [
            self._check_art9_risk_management,
            self._check_art12_record_keeping,
            self._check_art72_monitoring,
            self._check_art9_transparency,
        ]
        violations: list[ComplianceViolation] = []
        for checker in checkers:
            try:
                result = checker()
                if result is not None:
                    violations.append(result)
            except Exception as error:  # noqa: BLE001
                logger.warning(
                    "Compliance check failed",
                    exc_info=True,
                    extra={"component": "fce", "error": str(error)},
                )
        passed = len(checkers) - len(violations)
        agents = self.fleet_state.get("agents", [])
        safe_agents = agents if isinstance(agents, list) else []
        if not violations:
            status = ComplianceStatus.COMPLIANT
        elif passed > 0:
            status = ComplianceStatus.PARTIAL
        else:
            status = ComplianceStatus.NON_COMPLIANT
        report = ComplianceReport(
            status=status,
            violations=violations,
            checked_rules=len(checkers),
            passed_rules=passed,
            fleet_size=len(safe_agents),
        )
        logger.info(
            "Compliance evaluation complete",
            extra={"component": "fce", "status": status.value, "violations": len(violations)},
        )
        return report

