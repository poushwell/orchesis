"""Policy migration utilities for orchesis.yaml."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class PolicyMigrator:
    """Migrates orchesis.yaml between versions."""

    MIGRATIONS = {
        "0.1.x -> 0.2.x": {
            "description": "Add semantic_cache, recording, loop_detection defaults",
            "added_keys": ["semantic_cache", "recording", "loop_detection"],
            "renamed_keys": {},
            "removed_keys": [],
        },
        "0.2.x -> 0.3.x": {
            "description": "Add context_budget, community, alert_rules sections",
            "added_keys": ["context_budget", "community", "alert_rules"],
            "renamed_keys": {},
            "removed_keys": [],
        },
    }

    @staticmethod
    def _defaults_02() -> dict[str, Any]:
        return {
            "semantic_cache": {"enabled": True, "similarity_threshold": 0.85},
            "recording": {"enabled": True},
            "loop_detection": {"enabled": True, "warn_threshold": 3, "block_threshold": 5},
        }

    @staticmethod
    def _defaults_03() -> dict[str, Any]:
        return {
            "context_budget": {"enabled": False},
            "community": {"enabled": False},
            "alert_rules": [],
        }

    def detect_version(self, policy: dict) -> str:
        """Detect policy version from structure."""
        if not isinstance(policy, dict):
            return "0.1.x"
        if any(key in policy for key in ("context_budget", "community", "alert_rules")):
            return "0.3.x"
        if any(key in policy for key in ("semantic_cache", "recording", "loop_detection")):
            return "0.2.x"
        return "0.1.x"

    @staticmethod
    def _apply_defaults(target: dict[str, Any], defaults: dict[str, Any], changes: list[str]) -> None:
        for key, value in defaults.items():
            if key in target:
                continue
            target[key] = deepcopy(value)
            if isinstance(value, dict) and "enabled" in value:
                changes.append(f"+ {key}.enabled: {str(bool(value['enabled'])).lower()}")
            else:
                changes.append(f"+ {key}")

    def migrate(self, policy: dict, target_version: str) -> dict:
        """Migrate policy to target version."""
        current = self.detect_version(policy)
        target = str(target_version or "").strip() or "0.2.x"
        if target not in {"0.2.x", "0.3.x"}:
            raise ValueError(f"Unsupported target version: {target}")

        out = deepcopy(policy) if isinstance(policy, dict) else {}
        changes: list[str] = []
        warnings: list[str] = []

        if current == "0.3.x" and target == "0.2.x":
            warnings.append("Downgrade is not supported automatically; no keys removed.")
            return {"policy": out, "changes": changes, "warnings": warnings}

        if current == "0.1.x":
            self._apply_defaults(out, self._defaults_02(), changes)
            current = "0.2.x"
        if target == "0.3.x" and current in {"0.1.x", "0.2.x"}:
            self._apply_defaults(out, self._defaults_03(), changes)

        return {"policy": out, "changes": changes, "warnings": warnings}

    def dry_run(self, policy: dict, target_version: str) -> dict:
        """Show what would change without applying."""
        return self.migrate(deepcopy(policy) if isinstance(policy, dict) else {}, target_version)

    def backup(self, policy_path: str) -> str:
        """Create backup before migration. Returns backup path."""
        source = Path(policy_path)
        if not source.exists():
            raise FileNotFoundError(f"Config not found: {policy_path}")
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
        candidate = source.with_name(f"{source.name}.bak.{stamp}")
        if candidate.exists():
            candidate = source.with_name(f"{source.name}.bak.{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}")
        candidate.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
        return str(candidate)
