"""Deterministic decision replay engine."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from orchesis.engine import evaluate
from orchesis.models import Decision
from orchesis.state import GLOBAL_AGENT_ID, RateLimitTracker
from orchesis.telemetry import DecisionEvent

PARAMS_DEPENDENT_RULES = {"file_access", "sql_restriction", "regex_match"}


@dataclass(frozen=True)
class ReplayResult:
    original_event: DecisionEvent
    replayed_decision: Decision
    match: bool
    drift_reasons: list[str]


@dataclass(frozen=True)
class ReplayReport:
    total: int
    matches: int
    drifts: int
    drift_details: list[ReplayResult]

    @property
    def deterministic(self) -> bool:
        return self.drifts == 0


class ReplayEngine:
    """Replays decisions from telemetry events to verify determinism."""

    def __init__(self, policy_registry: dict[str, dict[str, Any]] | None = None):
        self.policy_registry = policy_registry or {}

    def replay_event(
        self,
        event: DecisionEvent,
        policy: dict[str, Any],
        *,
        strict: bool = False,
    ) -> ReplayResult:
        effective_policy = self.policy_registry.get(event.policy_version, policy)
        state = RateLimitTracker(persist_path=None)
        self._hydrate_state(state, event)

        reconstructed_request: dict[str, Any] = {
            "tool": event.tool,
            "cost": event.cost,
            "context": {"agent": event.agent_id},
            # params are intentionally unavailable in telemetry for privacy.
            "params": {},
        }
        replayed = evaluate(reconstructed_request, effective_policy, state=state)

        drift_reasons: list[str] = []
        original_reasons = set(event.reasons)
        replay_reasons = set(replayed.reasons)
        missing = sorted(original_reasons - replay_reasons)
        extra = sorted(replay_reasons - original_reasons)
        non_param_missing = [item for item in missing if not _is_params_dependent_reason(item)]
        non_param_extra = [item for item in extra if not _is_params_dependent_reason(item)]

        limitation_note = self._params_limitation_note(effective_policy)
        decision_match = (event.decision == "ALLOW") == replayed.allowed
        if not decision_match:
            if strict or limitation_note is None:
                drift_reasons.append(
                    f"decision_mismatch: original={event.decision} replayed="
                    f"{'ALLOW' if replayed.allowed else 'DENY'}"
                )
            else:
                union_reasons = sorted(original_reasons.union(replay_reasons))
                has_non_param_reason = any(
                    not _is_params_dependent_reason(reason) for reason in union_reasons
                )
                if has_non_param_reason:
                    drift_reasons.append(
                        f"decision_mismatch: original={event.decision} replayed="
                        f"{'ALLOW' if replayed.allowed else 'DENY'}"
                    )

        if non_param_missing:
            drift_reasons.append(f"reasons_missing_in_replay: {non_param_missing}")
        elif missing and strict:
            drift_reasons.append(f"reasons_missing_in_replay: {missing}")

        if non_param_extra:
            drift_reasons.append(f"extra_reasons_in_replay: {non_param_extra}")
        elif extra and strict:
            drift_reasons.append(f"extra_reasons_in_replay: {extra}")

        if limitation_note is not None:
            drift_reasons.append(limitation_note)

        match = len(drift_reasons) == 0
        if not strict and limitation_note is not None and len(drift_reasons) == 1:
            match = True

        return ReplayResult(
            original_event=event,
            replayed_decision=replayed,
            match=match,
            drift_reasons=drift_reasons,
        )

    def replay_log(
        self,
        events: list[DecisionEvent],
        policy: dict[str, Any],
        *,
        strict: bool = False,
    ) -> ReplayReport:
        results = [self.replay_event(event, policy, strict=strict) for event in events]
        drift_details = [item for item in results if not item.match]
        return ReplayReport(
            total=len(results),
            matches=len(results) - len(drift_details),
            drifts=len(drift_details),
            drift_details=drift_details,
        )

    def replay_file(
        self,
        jsonl_path: str,
        policy: dict[str, Any],
        *,
        strict: bool = False,
    ) -> ReplayReport:
        events = read_events_from_jsonl(Path(jsonl_path))
        return self.replay_log(events, policy, strict=strict)

    def _hydrate_state(self, state: RateLimitTracker, event: DecisionEvent) -> None:
        snapshot = event.state_snapshot or {}
        tool_counts = snapshot.get("tool_counts")
        if isinstance(tool_counts, dict):
            adjusted: dict[str, int] = {}
            for tool, count in tool_counts.items():
                if not isinstance(tool, str) or not isinstance(count, int):
                    continue
                # state_snapshot is captured after evaluation; roll back one event for replay input.
                if tool == event.tool and count > 0:
                    adjusted[tool] = count - 1
                else:
                    adjusted[tool] = count
            state.load_agent_snapshot(event.agent_id, adjusted)

    def _params_limitation_note(self, policy: dict[str, Any]) -> str | None:
        rules = policy.get("rules")
        if not isinstance(rules, list):
            return None
        used: set[str] = set()
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            rule_type = rule.get("type")
            if not isinstance(rule_type, str):
                rule_name = rule.get("name")
                rule_type = rule_name if isinstance(rule_name, str) else ""
            if rule_type in PARAMS_DEPENDENT_RULES:
                used.add(rule_type)
        if not used:
            return None
        return f"params_unavailable: skipped fidelity for {sorted(used)}"


def _is_params_dependent_reason(reason: str) -> bool:
    if ":" not in reason:
        return False
    rule_name = reason.split(":", 1)[0].strip()
    return rule_name in PARAMS_DEPENDENT_RULES


def read_events_from_jsonl(path: str | Path) -> list[DecisionEvent]:
    source = Path(path)
    if not source.exists():
        return []

    events: list[DecisionEvent] = []
    for index, line in enumerate(source.read_text(encoding="utf-8").splitlines()):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        event = _to_decision_event(payload, index=index)
        if event is not None:
            events.append(event)
    return events


def _to_decision_event(payload: dict[str, Any], *, index: int) -> DecisionEvent | None:
    # Native structured telemetry event.
    if "event_id" in payload:
        try:
            return DecisionEvent(**payload)
        except TypeError:
            return None

    # Backward-compatible legacy decisions.jsonl support.
    decision = payload.get("decision")
    if not isinstance(decision, str):
        return None

    tool = payload.get("tool")
    timestamp = payload.get("timestamp")
    if not isinstance(tool, str) or not isinstance(timestamp, str):
        return None

    reasons_raw = payload.get("reasons")
    reasons = (
        [item for item in reasons_raw if isinstance(item, str)]
        if isinstance(reasons_raw, list)
        else []
    )
    rules_checked_raw = payload.get("rules_checked")
    rules_checked = (
        [item for item in rules_checked_raw if isinstance(item, str)]
        if isinstance(rules_checked_raw, list)
        else []
    )
    cost_raw = payload.get("cost")
    if isinstance(cost_raw, int | float):
        cost = float(cost_raw)
    else:
        try:
            cost = float(cost_raw) if isinstance(cost_raw, str) else 0.0
        except ValueError:
            cost = 0.0

    context = payload.get("context")
    agent_id = GLOBAL_AGENT_ID
    if (
        isinstance(context, dict)
        and isinstance(context.get("agent"), str)
        and context.get("agent")
    ):
        agent_id = str(context["agent"])

    raw_id = f"{timestamp}:{tool}:{index}"
    event_id = str(uuid.uuid5(uuid.NAMESPACE_URL, raw_id))
    params_hash = hashlib.sha256(json.dumps({}, sort_keys=True).encode("utf-8")).hexdigest()
    return DecisionEvent(
        event_id=event_id,
        timestamp=timestamp,
        agent_id=agent_id,
        tool=tool,
        params_hash=params_hash,
        cost=cost,
        decision=decision,
        reasons=reasons,
        rules_checked=rules_checked,
        rules_triggered=[],
        evaluation_order=[],
        evaluation_duration_us=0,
        policy_version="legacy",
        state_snapshot={"tool_counts": {}},
        signature=payload.get("signature") if isinstance(payload.get("signature"), str) else None,
    )
