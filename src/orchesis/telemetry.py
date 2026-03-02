"""Structured telemetry event types and emitters."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Protocol

from orchesis.redaction import AuditRedactor


@dataclass(frozen=True)
class DecisionEvent:
    # Identity
    event_id: str
    timestamp: str
    agent_id: str

    # Request
    tool: str
    params_hash: str
    cost: float

    # Decision
    decision: str
    reasons: list[str]

    # Trace
    rules_checked: list[str]
    rules_triggered: list[str]
    evaluation_order: list[str]
    evaluation_duration_us: int

    # Context
    policy_version: str
    state_snapshot: dict[str, Any]
    decision_reason: str | None = None
    signature: str | None = None


class EventEmitter(Protocol):
    def emit(self, event: DecisionEvent) -> None: ...


class JsonlEmitter:
    """Writes DecisionEvents to JSONL file."""

    def __init__(self, path: str | Path, redactor: AuditRedactor | None = None):
        self.path = Path(path)
        self._redactor = redactor

    def emit(self, event: DecisionEvent) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = asdict(event)
        if self._redactor is not None:
            payload = self._redactor.redact_event(payload)
        with self.path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(payload, ensure_ascii=False) + "\n")


class InMemoryEmitter:
    """Stores DecisionEvents in memory for tests."""

    def __init__(self) -> None:
        self._events: list[DecisionEvent] = []

    def emit(self, event: DecisionEvent) -> None:
        self._events.append(event)

    def get_events(self) -> list[DecisionEvent]:
        return list(self._events)
