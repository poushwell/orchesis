"""Automated compliance coverage report generator."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


class ComplianceReportGenerator:
    """Generates compliance coverage reports."""

    FRAMEWORKS = {
        "mast": {"total": 14, "name": "MAST Mobile AI Security"},
        "owasp": {"total": 10, "name": "OWASP Agentic AI Top 10"},
        "eu_ai_act": {"total": 8, "name": "EU AI Act Articles 9/12/72"},
        "nist": {"total": 6, "name": "NIST AI RMF"},
    }

    _SIGNALS = {
        "mast": {
            "MAST-01": ["prompt_injection", "policy", "rule"],
            "MAST-02": ["authentication", "signature", "credential"],
            "MAST-03": ["redaction", "pii", "secret"],
            "MAST-04": ["rate_limit", "burst", "throttle"],
            "MAST-05": ["budget", "cost", "spend"],
            "MAST-06": ["audit", "log", "forensics"],
            "MAST-07": ["incident", "alert", "threat"],
            "MAST-08": ["model", "routing", "cascade"],
            "MAST-09": ["session", "risk"],
            "MAST-10": ["integrity", "signing", "tamper"],
            "MAST-11": ["approval", "human", "review"],
            "MAST-12": ["sandbox", "isolation", "tool_policy"],
            "MAST-13": ["compliance", "framework", "control"],
            "MAST-14": ["reliability", "latency", "error"],
        },
        "owasp": {
            "OWASP-A01": ["prompt_injection", "ignore all previous"],
            "OWASP-A02": ["tool", "function", "call"],
            "OWASP-A03": ["data", "leak", "pii"],
            "OWASP-A04": ["auth", "credential", "signature"],
            "OWASP-A05": ["rate_limit", "dos", "throttle"],
            "OWASP-A06": ["logging", "audit", "trace"],
            "OWASP-A07": ["supply_chain", "plugin", "dependency"],
            "OWASP-A08": ["model", "drift", "anomaly"],
            "OWASP-A09": ["misconfiguration", "policy", "yaml"],
            "OWASP-A10": ["incident", "response", "forensics"],
        },
        "eu_ai_act": {
            "EU-09": ["risk", "assessment", "session_risk"],
            "EU-10": ["data_governance", "dataset", "quality"],
            "EU-11": ["technical_documentation", "policy_version", "traceability"],
            "EU-12": ["logging", "audit", "event_id"],
            "EU-13": ["transparency", "explain", "reason"],
            "EU-14": ["human_oversight", "approval", "review"],
            "EU-15": ["robustness", "reliability", "resilience"],
            "EU-72": ["incident", "report", "notification"],
        },
        "nist": {
            "NIST-GOV": ["govern", "policy", "control"],
            "NIST-MAP": ["map", "inventory", "assets"],
            "NIST-MEA": ["measure", "metrics", "monitor"],
            "NIST-MAN": ["manage", "response", "mitigation"],
            "NIST-OPS": ["ops", "runbook", "process"],
            "NIST-IMP": ["improve", "feedback", "calibration"],
        },
    }

    def _event_to_text(self, event: Any) -> str:
        if isinstance(event, dict):
            payload = event
        else:
            payload = event.__dict__ if hasattr(event, "__dict__") else {}
        parts: list[str] = []
        for key in ("decision", "tool", "policy_version", "decision_reason"):
            value = payload.get(key)
            if isinstance(value, str):
                parts.append(value)
        reasons = payload.get("reasons")
        if isinstance(reasons, list):
            parts.extend(str(item) for item in reasons)
        rules_checked = payload.get("rules_checked")
        if isinstance(rules_checked, list):
            parts.extend(str(item) for item in rules_checked)
        rules_triggered = payload.get("rules_triggered")
        if isinstance(rules_triggered, list):
            parts.extend(str(item) for item in rules_triggered)
        state = payload.get("state_snapshot")
        if isinstance(state, dict):
            parts.extend(str(v) for v in state.values() if isinstance(v, str | int | float))
        return " ".join(parts).lower()

    def _framework_report(self, framework: str, corpus: str) -> dict[str, Any]:
        controls = self._SIGNALS[framework]
        covered = 0
        gaps: list[str] = []
        for control_id, keywords in controls.items():
            if any(keyword.lower() in corpus for keyword in keywords):
                covered += 1
            else:
                gaps.append(control_id)
        total = int(self.FRAMEWORKS[framework]["total"])
        percent = round((covered / float(total)) * 100.0, 2) if total > 0 else 0.0
        return {"covered": covered, "total": total, "percent": percent, "gaps": gaps}

    def get_recommendations(self, gaps: list[str]) -> list[str]:
        """Map gaps to actionable recommendations."""
        actions: list[str] = []
        for gap in gaps:
            if gap.startswith("OWASP-A01") or gap.startswith("MAST-01"):
                actions.append("Add stronger prompt-injection pattern detection and policy deny rules.")
            elif gap.startswith("EU-12") or gap.startswith("NIST-MEA"):
                actions.append("Increase audit logging coverage and preserve decision trace metadata.")
            elif gap.startswith("EU-14") or gap.startswith("MAST-11"):
                actions.append("Enable approval gates for high-risk tool calls.")
            elif gap.startswith("MAST-05"):
                actions.append("Define and enforce tighter per-agent budget controls.")
            elif gap.startswith("NIST-IMP"):
                actions.append("Add post-incident feedback loops to tune detection thresholds.")
            else:
                actions.append(f"Implement control coverage for {gap}.")
        deduped = list(dict.fromkeys(actions))
        return deduped[:8]

    def generate(self, agent_id: str, decisions_log: list) -> dict:
        """Generate full compliance report."""
        corpus = " ".join(self._event_to_text(event) for event in decisions_log)
        frameworks = {
            name: self._framework_report(name, corpus)
            for name in ("mast", "owasp", "eu_ai_act", "nist")
        }
        overall_score = round(
            sum(float(item["percent"]) for item in frameworks.values()) / float(len(frameworks)),
            2,
        )
        critical_gaps: list[str] = []
        for framework_name in ("owasp", "eu_ai_act", "mast"):
            gaps = frameworks[framework_name]["gaps"]
            if isinstance(gaps, list):
                critical_gaps.extend(gaps[:2])
        critical_gaps = list(dict.fromkeys(critical_gaps))[:8]
        recommendations = self.get_recommendations(critical_gaps)
        return {
            "report_id": str(uuid4()),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "agent_id": str(agent_id),
            "frameworks": frameworks,
            "overall_score": overall_score,
            "critical_gaps": critical_gaps,
            "recommendations": recommendations,
        }

    def export_text(self, report: dict) -> str:
        """Human-readable text report."""
        lines = [
            "Orchesis Compliance Coverage Report",
            "==================================",
            f"Report ID: {report.get('report_id', '-')}",
            f"Generated: {report.get('generated_at', '-')}",
            f"Agent ID: {report.get('agent_id', '-')}",
            "",
            "Framework Coverage:",
        ]
        frameworks = report.get("frameworks", {})
        for key in ("mast", "owasp", "eu_ai_act", "nist"):
            item = frameworks.get(key, {})
            total = int(item.get("total", 0) or 0)
            covered = int(item.get("covered", 0) or 0)
            percent = float(item.get("percent", 0.0) or 0.0)
            name = self.FRAMEWORKS.get(key, {}).get("name", key)
            lines.append(f"- {name}: {covered}/{total} ({percent:.1f}%)")
            gaps = item.get("gaps", [])
            if isinstance(gaps, list) and gaps:
                lines.append(f"  gaps: {', '.join(str(x) for x in gaps[:6])}")
        lines.extend(
            [
                "",
                f"Overall Score: {float(report.get('overall_score', 0.0)):.1f}%",
                f"Critical Gaps: {', '.join(report.get('critical_gaps', [])[:8]) or 'none'}",
                "",
                "Recommendations:",
            ]
        )
        for rec in report.get("recommendations", []):
            lines.append(f"- {rec}")
        return "\n".join(lines)
