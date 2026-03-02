"""Policy marketplace foundation for reusable policy packs."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from orchesis.config import validate_policy


@dataclass
class PolicyPack:
    """Installable policy package metadata and payload."""

    name: str
    version: str
    description: str
    author: str
    tags: list[str]
    rules: list[dict[str, Any]]
    agents: list[dict[str, Any]]
    plugins_required: list[str]


class PolicyMarketplace:
    """Registry of installable policy packs."""

    def __init__(self, packs_dir: str = "~/.orchesis/packs") -> None:
        self._user_packs_dir = Path(packs_dir).expanduser()
        self._builtin_dir = Path(__file__).resolve().parent / "packs"
        self._user_packs_dir.mkdir(parents=True, exist_ok=True)

    def _load_pack_file(self, path: Path) -> PolicyPack | None:
        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return None
        if not isinstance(payload, dict):
            return None
        try:
            return PolicyPack(
                name=str(payload.get("name", "")),
                version=str(payload.get("version", "1.0")),
                description=str(payload.get("description", "")),
                author=str(payload.get("author", "Orchesis Project")),
                tags=[str(item) for item in payload.get("tags", []) if isinstance(item, str)],
                rules=[item for item in payload.get("rules", []) if isinstance(item, dict)],
                agents=[item for item in payload.get("agents", []) if isinstance(item, dict)],
                plugins_required=[
                    str(item) for item in payload.get("plugins_required", []) if isinstance(item, str)
                ],
            )
        except Exception:  # noqa: BLE001
            return None

    def list_available(self) -> list[PolicyPack]:
        """List built-in policy packs."""
        packs: list[PolicyPack] = []
        for path in sorted(self._builtin_dir.glob("*.yaml")):
            loaded = self._load_pack_file(path)
            if loaded is not None:
                packs.append(loaded)
        return packs

    def get(self, name: str) -> PolicyPack | None:
        """Get a policy pack by name."""
        for pack in self.list_available():
            if pack.name == name:
                return pack
        return None

    def install(
        self,
        name: str,
        target_path: str = "policy.yaml",
        merge: bool = False,
    ) -> str:
        """Install a policy pack to target path."""
        pack = self.get(name)
        if pack is None:
            raise ValueError(f"Unknown policy pack: {name}")
        target = Path(target_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        if merge and target.exists():
            existing = yaml.safe_load(target.read_text(encoding="utf-8"))
            policy = existing if isinstance(existing, dict) else {}
            rules = policy.get("rules")
            if not isinstance(rules, list):
                rules = []
            rules.extend(pack.rules)
            policy["rules"] = rules
            agents = policy.get("agents")
            if not isinstance(agents, list):
                agents = []
            agents.extend(pack.agents)
            policy["agents"] = agents
        else:
            policy = {
                "version": pack.version,
                "rules": pack.rules,
                "agents": pack.agents,
            }
        target.write_text(yaml.safe_dump(policy, sort_keys=False, allow_unicode=True), encoding="utf-8")
        return str(target)

    def validate_pack(self, pack: PolicyPack) -> list[str]:
        """Validate policy pack payload and return errors."""
        errors: list[str] = []
        if not pack.name:
            errors.append("name is required")
        if not pack.version:
            errors.append("version is required")
        if not isinstance(pack.rules, list) or not pack.rules:
            errors.append("rules must be a non-empty list")
        policy = {"rules": pack.rules}
        if pack.agents:
            policy["agents"] = pack.agents
        errors.extend(validate_policy(policy))
        return errors

    def quality_snapshot(self) -> dict[str, Any]:
        """Return lightweight marketplace quality metadata."""
        packs = self.list_available()
        return {
            "total_packs": len(packs),
            "names": [item.name for item in packs],
            "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
