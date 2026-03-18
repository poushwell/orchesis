"""Tenant policy isolation manager."""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class TenantManager:
    """Manages per-tenant policy isolation."""

    def __init__(self, storage_path: str = ".orchesis/tenants"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self._tenants: dict[str, dict[str, Any]] = {}
        self._load()

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    def _tenant_path(self, tenant_id: str) -> Path:
        safe = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in str(tenant_id))
        return self.storage_path / f"{safe}.json"

    def _load(self) -> None:
        self._tenants = {}
        for file_path in sorted(self.storage_path.glob("*.json")):
            try:
                payload = json.loads(file_path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if not isinstance(payload, dict):
                continue
            tenant_id = str(payload.get("tenant_id", "")).strip()
            policy = payload.get("policy")
            if not tenant_id or not isinstance(policy, dict):
                continue
            self._tenants[tenant_id] = {
                "tenant_id": tenant_id,
                "policy": deepcopy(policy),
                "created_at": str(payload.get("created_at") or self._now_iso()),
                "updated_at": str(payload.get("updated_at") or self._now_iso()),
            }

    def _save_one(self, tenant_id: str) -> None:
        record = self._tenants[tenant_id]
        self._tenant_path(tenant_id).write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")

    def _get_record(self, tenant_id: str) -> dict[str, Any] | None:
        key = str(tenant_id).strip()
        if not key:
            return None
        row = self._tenants.get(key)
        if row is None:
            return None
        return deepcopy(row)

    @staticmethod
    def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
        out: dict[str, Any] = deepcopy(base)
        for key, value in override.items():
            if (
                key in out
                and isinstance(out[key], dict)
                and isinstance(value, dict)
            ):
                out[key] = TenantManager._deep_merge(out[key], value)
            else:
                out[key] = deepcopy(value)
        return out

    def create_tenant(self, tenant_id: str, policy: dict) -> dict:
        """Create new tenant with isolated policy."""
        key = str(tenant_id).strip()
        if not key:
            raise ValueError("tenant_id is required")
        if not isinstance(policy, dict):
            raise ValueError("policy must be object")
        if key in self._tenants:
            raise ValueError("tenant already exists")
        now = self._now_iso()
        self._tenants[key] = {
            "tenant_id": key,
            "policy": deepcopy(policy),
            "created_at": now,
            "updated_at": now,
        }
        self._save_one(key)
        return self._get_record(key) or {}

    def get_policy(self, tenant_id: str) -> dict | None:
        """Get tenant-specific policy."""
        row = self._get_record(tenant_id)
        if row is None:
            return None
        policy = row.get("policy")
        return deepcopy(policy) if isinstance(policy, dict) else None

    def update_policy(self, tenant_id: str, policy: dict) -> dict:
        """Update tenant policy."""
        key = str(tenant_id).strip()
        if key not in self._tenants:
            raise KeyError("tenant not found")
        if not isinstance(policy, dict):
            raise ValueError("policy must be object")
        self._tenants[key]["policy"] = deepcopy(policy)
        self._tenants[key]["updated_at"] = self._now_iso()
        self._save_one(key)
        return self._get_record(key) or {}

    def delete_tenant(self, tenant_id: str) -> bool:
        """Remove tenant."""
        key = str(tenant_id).strip()
        if key not in self._tenants:
            return False
        self._tenants.pop(key, None)
        try:
            self._tenant_path(key).unlink(missing_ok=True)
        except Exception:
            pass
        return True

    def list_tenants(self) -> list[dict]:
        """List all tenants with metadata."""
        rows: list[dict[str, Any]] = []
        for key in sorted(self._tenants.keys()):
            row = self._get_record(key)
            if row is None:
                continue
            rows.append(
                {
                    "tenant_id": row["tenant_id"],
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"],
                }
            )
        return rows

    def resolve_policy(self, tenant_id: str | None, base_policy: dict) -> dict:
        """Merge tenant policy with base policy. Tenant overrides base."""
        base = deepcopy(base_policy) if isinstance(base_policy, dict) else {}
        if not isinstance(tenant_id, str) or not tenant_id.strip():
            return base
        tenant_policy = self.get_policy(tenant_id)
        if not isinstance(tenant_policy, dict):
            return base
        return self._deep_merge(base, tenant_policy)
