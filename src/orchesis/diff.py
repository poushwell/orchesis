"""Session diff utilities for Time Machine replay outputs."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from typing import Any

from orchesis.recorder import SessionRecord
from orchesis.replayer import ReplayReport


@dataclass
class CostComparison:
    original_total: float
    replay_total: float
    delta: float
    savings_pct: float


@dataclass
class ErrorComparison:
    original_errors: int
    replay_errors: int
    new_errors: list[str]
    fixed_errors: list[str]


@dataclass
class PolicyImpact:
    blocked_count: int
    blocked_requests: list[dict[str, Any]]
    estimated_cost_prevented: float
    severity_breakdown: dict[str, int]


@dataclass
class RequestDiff:
    request_id: str
    cost_delta: float
    latency_delta_ms: float
    status_changed: bool
    policy_blocked: bool


@dataclass
class SessionDiff:
    session_id: str
    total_requests: int
    cost_comparison: CostComparison
    error_comparison: ErrorComparison
    policy_impact: PolicyImpact
    per_request: list[RequestDiff]


class SessionDiffer:
    def diff(self, original: list[SessionRecord], replay: ReplayReport) -> SessionDiff:
        by_id = {item.request_id: item for item in original}
        per_request: list[RequestDiff] = []
        new_errors: list[str] = []
        fixed_errors: list[str] = []
        blocked_requests: list[dict[str, Any]] = []
        estimated_cost_prevented = 0.0
        severity_breakdown: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for item in replay.results:
            orig = by_id.get(item.request_id)
            original_had_error = bool(orig and (orig.error or orig.status_code >= 400))
            replay_has_error = bool(item.replay_error or item.replay_status >= 400)
            if replay_has_error and not original_had_error:
                new_errors.append(item.request_id)
            if original_had_error and not replay_has_error:
                fixed_errors.append(item.request_id)
            if item.policy_blocked:
                reason = item.policy_block_reason or ""
                reason_lower = reason.lower()
                if any(kw in reason_lower for kw in ("critical", "rce", "injection", "execute")):
                    sev = "critical"
                elif any(kw in reason_lower for kw in ("secret", "credential", "key", "token", "password")):
                    sev = "high"
                elif any(kw in reason_lower for kw in ("budget", "limit", "cost", "rate")):
                    sev = "medium"
                else:
                    sev = "low"
                severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1
                blocked_requests.append(
                    {
                        "request_id": item.request_id,
                        "reason": item.policy_block_reason,
                        "severity": sev,
                    }
                )
                estimated_cost_prevented += max(0.0, float(item.replay_cost))
            per_request.append(
                RequestDiff(
                    request_id=item.request_id,
                    cost_delta=round(item.replay_cost - item.original_cost, 8),
                    latency_delta_ms=round(item.replay_latency_ms - item.original_latency_ms, 6),
                    status_changed=item.original_status != item.replay_status,
                    policy_blocked=item.policy_blocked,
                )
            )

        original_total = replay.summary.original_cost
        replay_total = replay.summary.replay_cost
        delta = replay_total - original_total
        savings_pct = ((original_total - replay_total) / original_total * 100.0) if original_total > 0 else 0.0

        return SessionDiff(
            session_id=replay.session_id,
            total_requests=len(replay.results),
            cost_comparison=CostComparison(
                original_total=round(original_total, 8),
                replay_total=round(replay_total, 8),
                delta=round(delta, 8),
                savings_pct=round(savings_pct, 4),
            ),
            error_comparison=ErrorComparison(
                original_errors=replay.summary.original_errors,
                replay_errors=replay.summary.replay_errors,
                new_errors=new_errors,
                fixed_errors=fixed_errors,
            ),
            policy_impact=PolicyImpact(
                blocked_count=len(blocked_requests),
                blocked_requests=blocked_requests,
                estimated_cost_prevented=round(estimated_cost_prevented, 8),
                severity_breakdown=severity_breakdown,
            ),
            per_request=per_request,
        )

    def to_json(self, diff: SessionDiff) -> str:
        return json.dumps(asdict(diff), ensure_ascii=False, indent=2)

    def to_summary_text(self, diff: SessionDiff) -> str:
        return (
            f"Session: {diff.session_id}\n"
            f"Requests: {diff.total_requests}\n"
            f"Cost: {diff.cost_comparison.original_total:.6f} -> {diff.cost_comparison.replay_total:.6f} "
            f"(delta {diff.cost_comparison.delta:.6f}, savings {diff.cost_comparison.savings_pct:.2f}%)\n"
            f"Errors: {diff.error_comparison.original_errors} -> {diff.error_comparison.replay_errors}\n"
            f"Policy blocks: {diff.policy_impact.blocked_count}\n"
        )
