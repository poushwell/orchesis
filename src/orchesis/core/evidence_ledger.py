"""Append-only evidence ledger with SHA-256 hash chaining."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any


class EvidenceLedger:
    """Store audit evidence entries as a tamper-evident hash chain."""

    def __init__(self, path: str | Path = ".orchesis/evidence_ledger.jsonl") -> None:
        self._path = Path(path)
        self._last_hash = self._load_last_hash()

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

    def record(self, event: dict[str, Any]) -> str:
        """Append one event to the ledger and return its hash."""
        if not isinstance(event, dict):
            raise TypeError("event must be a dict")
        timestamp = float(time.time())
        prev_hash = self._last_hash
        hash_value = self._hash_payload(event, timestamp, prev_hash)
        entry = {
            "event": event,
            "timestamp": timestamp,
            "prev_hash": prev_hash,
            "hash": hash_value,
        }
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        self._last_hash = hash_value
        return hash_value

    def verify_chain(self) -> bool:
        """Verify hash chain integrity for all ledger entries."""
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
