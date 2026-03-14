"""Smart error responses that guide agents to correct behavior."""

from __future__ import annotations

from dataclasses import dataclass, replace


@dataclass
class SmartError:
    blocked: bool
    reason: str
    suggestion: str
    severity: str
    detector: str
    code: str


class ErrorResponseBuilder:
    """Build descriptive error responses that help agents self-correct."""

    TEMPLATES = {
        "prompt_injection": SmartError(
            blocked=True,
            reason="Detected prompt injection attempt in message content",
            suggestion=(
                "Remove instruction-override patterns from user input. "
                "If this is legitimate, add domain to security.whitelist in config."
            ),
            severity="critical",
            detector="threat_intel",
            code="ORCH-SEC-001",
        ),
        "budget_exceeded": SmartError(
            blocked=True,
            reason="Daily budget limit of ${limit} exceeded. Current spend: ${current}",
            suggestion=(
                "Wait for budget reset (midnight UTC) or increase budget.daily_limit_usd in config. "
                "Consider using a cheaper model for this request."
            ),
            severity="high",
            detector="budget",
            code="ORCH-COST-001",
        ),
        "loop_detected": SmartError(
            blocked=False,
            reason="Detected request loop: {pattern} repeated {count} times",
            suggestion=(
                "Context has been reset to break the loop. Agent will retry with fresh context. "
                "If loops persist, check agent logic for recursive patterns."
            ),
            severity="medium",
            detector="loop_detection",
            code="ORCH-REL-001",
        ),
        "tool_blocked": SmartError(
            blocked=True,
            reason="Tool '{tool}' is blocked by policy for agent '{agent}'",
            suggestion=(
                "This tool is not in the allowed list. Allowed tools: {allowed}. "
                "To change, update tool_policies in config."
            ),
            severity="high",
            detector="tool_policy",
            code="ORCH-POL-001",
        ),
        "domain_blocked": SmartError(
            blocked=True,
            reason="Domain '{domain}' is in blocked_domains list",
            suggestion=(
                "Remove '{domain}' from tool_policies.blocked_domains if this is intentional. "
                "Current blocked: {blocked_list}"
            ),
            severity="high",
            detector="tool_policy",
            code="ORCH-POL-002",
        ),
        "credential_leak": SmartError(
            blocked=True,
            reason="Detected credential/secret in {direction}: {pattern_name}",
            suggestion=(
                "Remove the credential from the message. Use environment variables instead of "
                "hardcoding secrets. Pattern matched: {pattern}"
            ),
            severity="critical",
            detector="secrets_filter",
            code="ORCH-SEC-002",
        ),
        "rate_limited": SmartError(
            blocked=True,
            reason="Agent '{agent}' exceeded rate limit: {current}/{max} requests per {window}",
            suggestion=(
                "Wait {retry_after} seconds before retrying. If limit is too low, adjust "
                "agent_rate_limits in config."
            ),
            severity="medium",
            detector="agent_rate_limit",
            code="ORCH-POL-003",
        ),
        "approval_required": SmartError(
            blocked=True,
            reason="Action requires human approval: {tool} by {agent}",
            suggestion=(
                "Approval ID: {approval_id}. Retry this request with header "
                "X-Orchesis-Approval-Id: {approval_id} after approval. "
                "Check /api/v1/approvals for status."
            ),
            severity="medium",
            detector="approval_queue",
            code="ORCH-POL-004",
        ),
    }

    @classmethod
    def build(cls, error_type: str, **kwargs) -> SmartError:
        base = cls.TEMPLATES.get(error_type)
        if base is None:
            return SmartError(
                blocked=True,
                reason=str(kwargs.get("reason", "Request blocked by policy")),
                suggestion=str(kwargs.get("suggestion", "Review policy and retry with compliant input.")),
                severity=str(kwargs.get("severity", "medium")),
                detector=str(kwargs.get("detector", "policy")),
                code=str(kwargs.get("code", "ORCH-UNKNOWN-001")),
            )
        reason = base.reason
        suggestion = base.suggestion
        for key, value in kwargs.items():
            reason = reason.replace(f"{{{key}}}", str(value)).replace(f"${{{key}}}", str(value))
            suggestion = suggestion.replace(f"{{{key}}}", str(value)).replace(f"${{{key}}}", str(value))
        result = replace(base)
        result.reason = reason
        result.suggestion = suggestion
        return result

    @classmethod
    def to_http_response(cls, error: SmartError) -> dict:
        return {
            "error": True,
            "code": error.code,
            "reason": error.reason,
            "suggestion": error.suggestion,
            "severity": error.severity,
            "detector": error.detector,
            "blocked": error.blocked,
        }

    @classmethod
    def to_hook_output(cls, error: SmartError) -> str:
        state = "BLOCKED" if error.blocked else "WARN"
        return f"[{state}] {error.code}: {error.reason}\n→ {error.suggestion}"

    @classmethod
    def to_header(cls, error: SmartError) -> str:
        return f"{error.code}|{error.detector}|{error.severity}"

