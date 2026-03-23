"""Append-only evidence ledger with SHA-256 hash chaining."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path
from typing import Any


class EvidenceLedger:
    """Store audit evidence entries as a tamper-evident hash chain.

    Records are buffered in memory and flushed to disk in batches to avoid
    synchronous file I/O on the request hot path.
    """

    def __init__(
        self,
        path: str | Path = ".orchesis/evidence_ledger.jsonl",
        *,
        max_buffer_size: int = 100,
        flush_interval: float = 5.0,
    ) -> None:
        self._path = Path(path)
        self._max_buffer_size = max(1, int(max_buffer_size))
        self._flush_interval = float(flush_interval)
        self._last_hash = self._load_last_hash()
        self._buffer: list[dict[str, Any]] = []
        self._buffer_lock = threading.Lock()
        self._flush_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._flush_thread: threading.Thread | None = None
        self._closed = False
        if self._flush_interval > 0:
            self._flush_thread = threading.Thread(
                target=self._flush_loop,
                name="orchesis-evidence-ledger",
                daemon=True,
            )
            self._flush_thread.start()

    def _flush_loop(self) -> None:
        while not self._stop_event.wait(timeout=self._flush_interval):
            self._flush()

    @staticmethod
    def _hash_payload(event: dict[str, Any], timestamp: float, prev_hash: str) -> str:
        material = {
            "event": event,
            "timestamp": float(timestamp),
            "prev_hash": str(prev_hash),
        }
        encoded = json.dumps(material, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _load_last_hash(self) -> str:
        if not self._path.exists():
            return ""
        last_valid_hash = ""
        try:
            with self._path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except Exception:
                        continue
                    if isinstance(row, dict):
                        hash_value = row.get("hash")
                        if isinstance(hash_value, str):
                            last_valid_hash = hash_value
        except Exception:
            return ""
        return last_valid_hash

    def _flush(self) -> None:
        with self._flush_lock:
            with self._buffer_lock:
                if not self._buffer:
                    return
                batch = list(self._buffer)
                self._buffer.clear()
            self._path.parent.mkdir(parents=True, exist_ok=True)
            prev_hash = self._last_hash
            lines: list[str] = []
            for event in batch:
                timestamp = float(time.time())
                hash_value = self._hash_payload(event, timestamp, prev_hash)
                entry = {
                    "event": event,
                    "timestamp": timestamp,
                    "prev_hash": prev_hash,
                    "hash": hash_value,
                }
                lines.append(json.dumps(entry, ensure_ascii=False) + "\n")
                prev_hash = hash_value
            with self._path.open("a", encoding="utf-8") as handle:
                handle.writelines(lines)
            self._last_hash = prev_hash

    def flush(self) -> None:
        """Write all buffered entries to disk without stopping the background thread."""
        if self._closed:
            return
        self._flush()

    def record(self, event: dict[str, Any]) -> str:
        """Append one event to the buffer; flush when full. Returns \"\" when buffered."""
        if self._closed:
            return ""
        if not isinstance(event, dict):
            raise TypeError("event must be a dict")
        should_flush = False
        with self._buffer_lock:
            self._buffer.append(dict(event))
            should_flush = len(self._buffer) >= self._max_buffer_size
        if should_flush:
            self._flush()
        return ""

    def close(self) -> None:
        """Stop background flush and write any buffered entries."""
        if self._closed:
            return
        self._closed = True
        self._stop_event.set()
        if self._flush_thread is not None and self._flush_thread.is_alive():
            self._flush_thread.join(timeout=30.0)
        self._flush()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def verify_chain(self) -> bool:
        """Verify hash chain integrity for all ledger entries."""
        self._flush()
        if not self._path.exists():
            return True

        expected_prev = ""
        try:
            with self._path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    row = json.loads(line)
                    if not isinstance(row, dict):
                        return False

                    event = row.get("event")
                    timestamp = row.get("timestamp")
                    prev_hash = row.get("prev_hash")
                    hash_value = row.get("hash")

                    if not isinstance(event, dict):
                        return False
                    if not isinstance(timestamp, int | float):
                        return False
                    if not isinstance(prev_hash, str) or not isinstance(hash_value, str):
                        return False
                    if prev_hash != expected_prev:
                        return False

                    computed = self._hash_payload(event, float(timestamp), prev_hash)
                    if computed != hash_value:
                        return False

                    expected_prev = hash_value
        except Exception:
            return False
        return True
