"""Policy version storage with rollback support."""

from __future__ import annotations

import hashlib
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

    def __init__(self, max_versions: int = 10):
        self._versions: list[PolicyVersion] = []
        self._current: PolicyVersion | None = None
        self._max_versions = max_versions

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
        self._versions.insert(0, version)
        if len(self._versions) > self._max_versions:
            self._versions = self._versions[: self._max_versions]
        self._current = self._versions[0] if self._versions else None
        return version

    @property
    def current(self) -> PolicyVersion | None:
        """Current active policy version."""
        return self._current

    def rollback(self) -> PolicyVersion | None:
        """Rollback to previous version and return new current."""
        if len(self._versions) < 2:
            return None
        self._versions.pop(0)
        self._current = self._versions[0]
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
