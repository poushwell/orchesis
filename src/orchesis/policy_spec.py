"""Formal Policy-as-Code specification helpers."""

from __future__ import annotations

from typing import Any


class PolicySpec:
    """Formal Policy-as-Code specification for orchesis.yaml.

    Maps to: EU AI Act, OWASP Agentic Top 10, NIST AI RMF.
    Draft -> community feedback -> OWASP submission.
    """

    SPEC_VERSION = "1.0.0"

    SCHEMA = {
        "version": {"type": "string", "required": False},
        "proxy": {"type": "dict", "required": True},
        "security": {"type": "dict", "required": False},
        "budgets": {"type": "dict", "required": False},
        "semantic_cache": {"type": "dict", "required": False},
        "recording": {"type": "dict", "required": False},
        "loop_detection": {"type": "dict", "required": False},
    }

    EU_AI_ACT_MAPPING = {
        "recording.enabled": "Article 12 - Record keeping",
        "threat_intel.enabled": "Article 72 - Post-market monitoring",
        "budgets.daily": "Article 9 - Risk management",
    }

    OWASP_MAPPING = {
        "loop_detection.enabled": "OWASP-A8 - Unbounded consumption",
        "security.rate_limiting": "OWASP-A4 - Rate limiting",
        "semantic_cache.enabled": "OWASP-A3 - Data poisoning mitigation",
    }

    @staticmethod
    def _type_matches(value: Any, expected: str) -> bool:
        if expected == "dict":
            return isinstance(value, dict)
        if expected == "string":
            return isinstance(value, str)
        return True

    @staticmethod
    def _resolve_path(data: dict[str, Any], dotted_path: str) -> Any:
        current: Any = data
        for part in dotted_path.split("."):
            if not isinstance(current, dict):
                return None
            current = current.get(part)
        return current

    def validate(self, policy: dict) -> dict:
        """Full spec validation."""
        payload = policy if isinstance(policy, dict) else {}
        violations: list[dict[str, Any]] = []
        warnings: list[dict[str, Any]] = []
        for key, spec in self.SCHEMA.items():
            required = bool(spec.get("required", False))
            expected_type = str(spec.get("type", "dict"))
            present = key in payload
            value = payload.get(key)
            if required and not present:
                violations.append(
                    {"path": key, "code": "missing_required", "message": f"Missing required key '{key}'"}
                )
                continue
            if present and not self._type_matches(value, expected_type):
                violations.append(
                    {
                        "path": key,
                        "code": "invalid_type",
                        "message": f"Key '{key}' should be of type {expected_type}",
                    }
                )
        # Advisory warnings
        if not isinstance(payload.get("recording"), dict):
            warnings.append({"path": "recording", "code": "recommended", "message": "Enable recording for auditability"})
        if not isinstance(payload.get("semantic_cache"), dict):
            warnings.append({"path": "semantic_cache", "code": "recommended", "message": "Enable semantic cache controls"})

        compliance_map = {
            "eu_ai_act": self.export_eu_ai_act_alignment(),
            "owasp": self.export_owasp_alignment(),
        }
        return {
            "valid": len(violations) == 0,
            "spec_version": self.SPEC_VERSION,
            "violations": violations,
            "warnings": warnings,
            "compliance_map": compliance_map,
        }

    def generate_spec_doc(self) -> str:
        """Generate human-readable spec documentation."""
        lines: list[str] = []
        lines.append(f"# Orchesis Policy Spec v{self.SPEC_VERSION}")
        lines.append("")
        lines.append("## Schema")
        for key, spec in self.SCHEMA.items():
            req = "required" if bool(spec.get("required", False)) else "optional"
            lines.append(f"- `{key}`: `{spec.get('type', 'dict')}` ({req})")
        lines.append("")
        lines.append("## EU AI Act Mapping")
        for key, article in self.EU_AI_ACT_MAPPING.items():
            lines.append(f"- `{key}` -> {article}")
        lines.append("")
        lines.append("## OWASP Agentic Top 10 Mapping")
        for key, article in self.OWASP_MAPPING.items():
            lines.append(f"- `{key}` -> {article}")
        return "\n".join(lines) + "\n"

    def export_owasp_alignment(self) -> dict:
        """Export OWASP Agentic Top 10 alignment report."""
        return {
            "framework": "OWASP Agentic Top 10",
            "spec_version": self.SPEC_VERSION,
            "controls": dict(self.OWASP_MAPPING),
            "count": len(self.OWASP_MAPPING),
        }

    def export_eu_ai_act_alignment(self) -> dict:
        """Export EU AI Act Article mapping."""
        return {
            "framework": "EU AI Act",
            "spec_version": self.SPEC_VERSION,
            "articles": dict(self.EU_AI_ACT_MAPPING),
            "count": len(self.EU_AI_ACT_MAPPING),
        }

    def get_spec_version(self) -> str:
        return self.SPEC_VERSION
