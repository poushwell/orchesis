"""Policy version storage with rollback support."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from orchesis.config import load_agent_registry, load_policy
from orchesis.identity import AgentRegistry


@dataclass(frozen=True)
class PolicyVersion:
    """Immutable policy version record."""

    version_id: str
    policy: dict[str, Any]
    loaded_at: str
    source_path: str
    registry: AgentRegistry


class PolicyStore:
    """Manages policy versions with rollback capability."""

    def __init__(
        self,
        max_versions: int = 10,
        history_path: str | Path = ".orchesis/policy_versions.jsonl",
    ):
        self._versions: list[PolicyVersion] = []
        self._current: PolicyVersion | None = None
        self._max_versions = max_versions
        self._history_path = Path(history_path)
        self._load_history()

    def load(self, path: str) -> PolicyVersion:
        """Load policy from file and store as a new version."""
        source = Path(path)
        content = source.read_bytes()
        policy = load_policy(source)
        loaded_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        version = PolicyVersion(
            version_id=hashlib.sha256(content).hexdigest(),
            policy=policy,
            loaded_at=loaded_at,
            source_path=str(source),
            registry=load_agent_registry(policy),
        )
        if (
            self._current is not None
            and self._current.version_id == version.version_id
            and self._current.source_path == version.source_path
        ):
            return self._current
        self._versions.insert(0, version)
        if len(self._versions) > self._max_versions:
            self._versions = self._versions[: self._max_versions]
        self._current = self._versions[0] if self._versions else None
        self._persist_version(version)
        return version

    @property
    def current(self) -> PolicyVersion | None:
        """Current active policy version."""
        return self._current

    def rollback(self) -> PolicyVersion | None:
        """Rollback to previous version and return new current."""
        if self._current is None or len(self._versions) < 2:
            return None
        current_index = next(
            (
                idx
                for idx, version in enumerate(self._versions)
                if version.version_id == self._current.version_id
            ),
            -1,
        )
        if current_index < 0 or current_index >= len(self._versions) - 1:
            return None
        self._current = self._versions[current_index + 1]
        self._persist_rollback(self._current.version_id)
        return self._current

    def get_version(self, version_id: str) -> PolicyVersion | None:
        """Look up a specific version by hash."""
        for version in self._versions:
            if version.version_id == version_id:
                return version
        return None

    def history(self) -> list[PolicyVersion]:
        """Return all stored versions, newest first."""
        return list(self._versions)

    def _load_history(self) -> None:
        """Load version history from JSONL."""
        if not self._history_path.exists():
            return

        try:
            lines = self._history_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return

        loaded_records: list[dict[str, Any]] = []
        active_version_id: str | None = None
        for line in lines:
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict):
                continue
            version_id = payload.get("version_id")
            loaded_at = payload.get("loaded_at")
            source_path = payload.get("source_path")
            active = payload.get("active")
            if (
                not isinstance(version_id, str)
                or not isinstance(loaded_at, str)
                or not isinstance(source_path, str)
                or not isinstance(active, bool)
            ):
                continue
            loaded_records.append(payload)
            if active:
                active_version_id = version_id

        # Keep first occurrence per version_id from newest to oldest order.
        seen: set[str] = set()
        versions: list[PolicyVersion] = []
        for record in reversed(loaded_records):
            version_id = str(record["version_id"])
            if version_id in seen:
                continue
            seen.add(version_id)
            source = Path(str(record["source_path"]))
            try:
                policy = load_policy(source)
            except (ValueError, OSError):
                continue
            versions.append(
                PolicyVersion(
                    version_id=version_id,
                    policy=policy,
                    loaded_at=str(record["loaded_at"]),
                    source_path=str(source),
                    registry=load_agent_registry(policy),
                )
            )

        self._versions = versions[: self._max_versions]
        if active_version_id is not None:
            self._current = next(
                (version for version in self._versions if version.version_id == active_version_id),
                None,
            )
        if self._current is None and self._versions:
            self._current = self._versions[0]

    def _persist_version(self, version: PolicyVersion) -> None:
        """Append version metadata to history file."""
        self._history_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version_id": version.version_id,
            "loaded_at": version.loaded_at,
            "source_path": version.source_path,
            "active": True,
        }
        with self._history_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")

    def _persist_rollback(self, version_id: str) -> None:
        """Persist rollback by marking selected version active."""
        selected = self.get_version(version_id)
        if selected is None:
            return
        self._history_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version_id": selected.version_id,
            "loaded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "source_path": selected.source_path,
            "active": True,
        }
        with self._history_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
