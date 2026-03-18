"""Real-time compliance checker utilities."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import uuid
from typing import Any


class RealTimeComplianceChecker:
    """Checks requests against compliance frameworks in real-time."""

    CHECKS = {
        "eu_ai_act_logging": {
            "framework": "EU AI Act Article 12",
            "description": "All decisions must be logged",
            "check": lambda policy: bool(policy.get("recording", {}).get("enabled")),
            "critical": True,
        },
        "eu_ai_act_monitoring": {
            "framework": "EU AI Act Article 9",
            "description": "Continuous monitoring required",
            "check": lambda policy: bool(policy.get("threat_intel", {}).get("enabled")),
            "critical": True,
        },
        "owasp_rate_limiting": {
            "framework": "OWASP Agentic A4",
            "description": "Rate limiting must be configured",
            "critical": False,
        },
        "owasp_input_validation": {
            "framework": "OWASP Agentic A1",
            "description": "Input validation must be active",
            "critical": False,
        },
        "nist_audit_trail": {
            "framework": "NIST AI RMF",
            "description": "Audit trail must be maintained",
            "critical": True,
        },
    }

    @staticmethod
    def _has_rate_limit(policy: dict[str, Any]) -> bool:
        rules = policy.get("rules")
        if isinstance(rules, list):
            for rule in rules:
                if isinstance(rule, dict) and str(rule.get("name", "")).strip().lower() == "rate_limit":
                    return True
        api_cfg = policy.get("api")
        if isinstance(api_cfg, dict):
            nested = api_cfg.get("rate_limit")
            if isinstance(nested, dict) and bool(nested.get("enabled", True)):
                return True
        api_rl = policy.get("api_rate_limit")
        if isinstance(api_rl, dict) and bool(api_rl.get("enabled", True)):
            return True
        return False

    @staticmethod
    def _has_input_validation(policy: dict[str, Any]) -> bool:
        rules = policy.get("rules")
        if isinstance(rules, list):
            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                name = str(rule.get("name", "")).strip().lower()
                if name in {"regex_match", "input_validation", "prompt_validation"}:
                    return True
        if isinstance(policy.get("adaptive_detection"), dict):
            return bool(policy.get("adaptive_detection", {}).get("enabled"))
        return False

    @staticmethod
    def _has_audit_trail(policy: dict[str, Any]) -> bool:
        recording = policy.get("recording")
        if isinstance(recording, dict) and bool(recording.get("enabled")):
            return True
        logging_cfg = policy.get("logging")
        if isinstance(logging_cfg, dict) and bool(logging_cfg.get("enabled")):
            return True
        return False

    def check_policy(self, policy: dict) -> dict:
        candidate = policy if isinstance(policy, dict) else {}
        checks: list[dict[str, Any]] = []
        critical_failures: list[str] = []
        warnings: list[str] = []

        for check_id, meta in self.CHECKS.items():
            if check_id == "owasp_rate_limiting":
                passed = self._has_rate_limit(candidate)
            elif check_id == "owasp_input_validation":
                passed = self._has_input_validation(candidate)
            elif check_id == "nist_audit_trail":
                passed = self._has_audit_trail(candidate)
            else:
                fn = meta.get("check")
                passed = bool(fn(candidate)) if callable(fn) else False
            item = {
                "check_id": check_id,
                "framework": str(meta.get("framework", "")),
                "description": str(meta.get("description", "")),
                "passed": bool(passed),
                "critical": bool(meta.get("critical", False)),
            }
            checks.append(item)
            if not passed:
                if item["critical"]:
                    critical_failures.append(check_id)
                else:
                    warnings.append(check_id)

        total = len(checks)
        passed_count = sum(1 for row in checks if row["passed"])
        score = round((float(passed_count) / float(total) * 100.0) if total > 0 else 0.0, 2)
        compliant = len(critical_failures) == 0 and passed_count == total
        certificate = self.generate_certificate(candidate) if compliant else None
        return {
            "compliant": compliant,
            "score": score,
            "checks": checks,
            "critical_failures": critical_failures,
            "warnings": warnings,
            "certificate": certificate,
        }

    def check_request(self, request: dict, policy: dict) -> dict:
        """Real-time compliance check on single request."""
        req = request if isinstance(request, dict) else {}
        policy_result = self.check_policy(policy if isinstance(policy, dict) else {})
        request_id = str(req.get("request_id", "")) or f"req-{uuid.uuid4().hex[:10]}"
        return {
            "request_id": request_id,
            "compliant": bool(policy_result.get("compliant", False)),
            "score": float(policy_result.get("score", 0.0)),
            "critical_failures": list(policy_result.get("critical_failures", [])),
            "warnings": list(policy_result.get("warnings", [])),
            "decision": "allow" if policy_result.get("compliant") else "warn",
        }

    def generate_certificate(self, policy: dict) -> dict:
        """Generate compliance certificate if all checks pass."""
        issued_at = datetime.now(timezone.utc)
        return {
            "certificate_id": f"cmp-{uuid.uuid4().hex[:12]}",
            "issued_at": issued_at.isoformat(),
            "valid_until": (issued_at + timedelta(days=365)).isoformat(),
            "frameworks": sorted(
                {
                    str(meta.get("framework", ""))
                    for meta in self.CHECKS.values()
                    if str(meta.get("framework", ""))
                }
            ),
            "score": 100.0,
        }

