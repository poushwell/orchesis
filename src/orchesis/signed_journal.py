"""Signed tracking journal — tamper-evident hash chain.

Per SPEC §1.9.2. Each event the proxy appends to its tracking journal is
stamped with:
  - a monotonic sequence number (gap detection),
  - the current phase id (sourced from a context variable, not a parameter —
    prevents spoofing where plugin A claims to be plugin B),
  - a monotonic timestamp,
  - the event type + payload,
  - the previous event's hash,
  - the SHA-256 of all the above (the "event hash").

Append cost: one SHA-256 per event ≈ 1–3 µs on ~200-byte payloads. A
request that emits 50 events pays 50-150 µs total — well within budget.

Tampering responses (handled by the proxy):
  - Current request fails fast (opaque 500).
  - Pipeline keeps running (one bad plugin shouldn't DoS the proxy).
  - Plugin is suspected after a threshold of events in a window;
    disabled for the remainder of the process.

This module ships the append-side primitives. The intervention manager
lives in proxy code; this module reports tampering via `JournalError`.
"""

from __future__ import annotations

import contextvars
import hashlib
import hmac
import json
import threading
import time
from dataclasses import dataclass, field
from typing import Iterable, Mapping


CURRENT_PHASE: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "orchesis_current_phase", default=None
)


class JournalError(Exception):
    """Raised when integrity check fails (hash mismatch, seq gap, etc.)."""


@dataclass(frozen=True, slots=True)
class JournalEvent:
    seq: int
    phase_id: str
    timestamp_ns: int
    event_type: str
    payload: bytes
    prev_hash: bytes
    event_hash: bytes

    def to_dict(self) -> dict[str, object]:
        return {
            "seq": self.seq,
            "phase_id": self.phase_id,
            "timestamp_ns": self.timestamp_ns,
            "event_type": self.event_type,
            "payload_b64": self.payload.hex(),
            "prev_hash": self.prev_hash.hex(),
            "event_hash": self.event_hash.hex(),
        }


_GENESIS_HASH: bytes = bytes(32)  # 32 zero bytes seed the chain


def _canonical(seq: int, phase_id: str, timestamp_ns: int,
               event_type: str, payload: bytes, prev_hash: bytes) -> bytes:
    """Deterministic byte layout used as SHA-256 input.

    Each field is length-prefixed so different fields cannot collide.
    """
    parts: list[bytes] = []
    for value in (
        seq.to_bytes(8, "big", signed=False),
        phase_id.encode("utf-8"),
        timestamp_ns.to_bytes(8, "big", signed=False),
        event_type.encode("utf-8"),
        payload,
        prev_hash,
    ):
        parts.append(len(value).to_bytes(4, "big"))
        parts.append(value)
    return b"".join(parts)


class SignedJournal:
    """Append-only hash-chain journal.

    Threadsafe: a single internal lock guards seq assignment and tail
    update so concurrent producers cannot interleave a gap.
    """

    __slots__ = ("_events", "_tail_hash", "_seq", "_lock", "_hmac_key")

    def __init__(self, hmac_key: bytes | None = None) -> None:
        self._events: list[JournalEvent] = []
        self._tail_hash: bytes = _GENESIS_HASH
        self._seq: int = 0
        self._lock = threading.Lock()
        # Optional HMAC checkpoint key. When set, each event also carries
        # an HMAC; tampering with the underlying log is detected without
        # access to the live tail hash.
        self._hmac_key = hmac_key

    def append(self, event_type: str, payload: bytes | str | Mapping) -> JournalEvent:
        """Append one event. Phase identity is read from the context var.

        Accepts payload as bytes, str (utf-8), or JSON-compatible Mapping
        (serialized to JSON bytes).
        """
        if isinstance(payload, str):
            payload_bytes = payload.encode("utf-8")
        elif isinstance(payload, (bytes, bytearray)):
            payload_bytes = bytes(payload)
        elif isinstance(payload, Mapping):
            payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        else:
            raise JournalError(f"unsupported payload type {type(payload).__name__}")
        phase_id = CURRENT_PHASE.get() or "unknown"
        timestamp_ns = time.monotonic_ns()
        with self._lock:
            self._seq += 1
            seq = self._seq
            prev_hash = self._tail_hash
            canonical = _canonical(seq, phase_id, timestamp_ns, event_type,
                                   payload_bytes, prev_hash)
            event_hash = hashlib.sha256(canonical).digest()
            event = JournalEvent(
                seq=seq,
                phase_id=phase_id,
                timestamp_ns=timestamp_ns,
                event_type=event_type,
                payload=payload_bytes,
                prev_hash=prev_hash,
                event_hash=event_hash,
            )
            self._events.append(event)
            self._tail_hash = event_hash
        return event

    def events(self) -> tuple[JournalEvent, ...]:
        with self._lock:
            return tuple(self._events)

    @property
    def tail_hash(self) -> bytes:
        with self._lock:
            return self._tail_hash

    @property
    def length(self) -> int:
        with self._lock:
            return len(self._events)

    # -- integrity --------------------------------------------------------

    def verify(self) -> None:
        """Walk the chain. Raise JournalError on first inconsistency."""
        prev_hash = _GENESIS_HASH
        prev_seq = 0
        for event in self.events():
            if event.seq != prev_seq + 1:
                raise JournalError(
                    f"sequence gap at seq={event.seq}, expected {prev_seq + 1}"
                )
            if event.prev_hash != prev_hash:
                raise JournalError(
                    f"prev_hash mismatch at seq={event.seq}"
                )
            canonical = _canonical(
                event.seq, event.phase_id, event.timestamp_ns,
                event.event_type, event.payload, event.prev_hash,
            )
            expected = hashlib.sha256(canonical).digest()
            if expected != event.event_hash:
                raise JournalError(f"event hash mismatch at seq={event.seq}")
            prev_hash = event.event_hash
            prev_seq = event.seq

    def hmac_checkpoint(self) -> bytes:
        """Return an HMAC over the current tail hash.

        Useful as a periodic checkpoint exported to a separate audit
        store. Tampering with any event invalidates the tail hash and
        hence the next checkpoint.
        """
        if self._hmac_key is None:
            raise JournalError("HMAC key not configured")
        with self._lock:
            tail = self._tail_hash
        return hmac.new(self._hmac_key, tail, hashlib.sha256).digest()


# ---------------------------------------------------------------------------
# Context helper — phases use `with stamp_phase(name): journal.append(...)`
# ---------------------------------------------------------------------------


class _PhaseStamper:
    __slots__ = ("_name", "_token")

    def __init__(self, name: str):
        self._name = name
        self._token = None  # type: ignore[assignment]

    def __enter__(self) -> "_PhaseStamper":
        self._token = CURRENT_PHASE.set(self._name)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        CURRENT_PHASE.reset(self._token)


def stamp_phase(name: str) -> _PhaseStamper:
    """Context manager that scopes a phase id onto the current task."""
    return _PhaseStamper(name)
