"""Compliance report generation from policy and runtime artifacts."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


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
    ],
}


class ComplianceEngine:
    """Generate compliance reports from policy and runtime state."""

    def __init__(
        self,
        policy_path: str = "policy.yaml",
        decisions_path: str = ".orchesis/decisions.jsonl",
        incidents_path: str = ".orchesis/incidents.jsonl",
    ):
        self._policy_path = policy_path
        self._decisions_path = decisions_path
        self._incidents_path = incidents_path

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
        if isinstance(policy.get("policy_version"), str):
            return self._result("policy_versioning_available", "pass", "policy_version field present", "")
        if isinstance(policy.get("version"), str):
            return self._result("policy_versioning_available", "pass", "version field present", "")
        return self._result("policy_versioning_available", "partial", "No explicit policy version field", "Add policy_version metadata")

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
        if policy.get("metrics") is True or Path(".orchesis/metrics.json").exists():
            return self._result("metrics_available", "pass", "Metrics configuration available", "")
        return self._result("metrics_available", "partial", "Metrics not configured", "Enable metrics collection")

    def _load_policy(self) -> dict[str, Any]:
        path = Path(self._policy_path)
        if not path.exists():
            return {}
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        return loaded if isinstance(loaded, dict) else {}

    def _policy_hash(self, policy: dict[str, Any]) -> str:
        payload = yaml.dump(policy, sort_keys=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

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
