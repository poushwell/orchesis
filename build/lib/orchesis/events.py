"""Event bus for real-time decision streaming."""

from __future__ import annotations

import threading
from typing import Callable

from orchesis.telemetry import DecisionEvent, EventEmitter


class EventBus:
    """Central pub/sub for decision events."""

    def __init__(self):
        self._lock = threading.Lock()
        self._next_id = 1
        self._subscribers: dict[int, EventEmitter] = {}
        self._filters: dict[int, Callable[[DecisionEvent], bool]] = {}

    def subscribe(
        self,
        emitter: EventEmitter,
        filter_fn: Callable[[DecisionEvent], bool] | None = None,
    ) -> int:
        """Subscribe to event stream and return subscriber id."""
        with self._lock:
            subscriber_id = self._next_id
            self._next_id += 1
            self._subscribers[subscriber_id] = emitter
            if filter_fn is not None:
                self._filters[subscriber_id] = filter_fn
            return subscriber_id

    def unsubscribe(self, subscriber_id: int) -> None:
        """Remove subscriber if present."""
        with self._lock:
            self._subscribers.pop(subscriber_id, None)
            self._filters.pop(subscriber_id, None)

    def publish(self, event: DecisionEvent) -> None:
        """Publish event to subscribers; never raises."""
        with self._lock:
            items = list(self._subscribers.items())
            filters = dict(self._filters)

        for subscriber_id, emitter in items:
            try:
                filter_fn = filters.get(subscriber_id)
                if filter_fn is not None and not filter_fn(event):
                    continue
                emitter.emit(event)
            except Exception:
                continue

    def emit(self, event: DecisionEvent) -> None:
        """EventEmitter-compatible method."""
        self.publish(event)

    @property
    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscribers)
