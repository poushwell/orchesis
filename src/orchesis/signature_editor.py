"""Custom threat signature editor."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


class SignatureEditor:
    """Create and manage custom threat signatures."""

    SIGNATURE_SCHEMA = {
        "id": str,
        "name": str,
        "category": str,
        "severity": str,
        "pattern": str,
        "description": str,
        "enabled": bool,
        "created_at": str,
        "tags": list,
    }

    _CATEGORIES = {"prompt_injection", "credential", "infrastructure", "custom"}
    _SEVERITIES = {"low", "medium", "high", "critical"}

    def __init__(self, storage_path: str = ".orchesis/signatures.json"):
        self.storage_path = Path(storage_path)
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        self._items: list[dict[str, Any]] = []
        self._load()

    def _load(self) -> None:
        if not self.storage_path.exists():
            self._items = []
            return
        try:
            payload = json.loads(self.storage_path.read_text(encoding="utf-8"))
        except Exception:
            self._items = []
            return
        if isinstance(payload, list):
            self._items = [dict(item) for item in payload if isinstance(item, dict)]
        else:
            self._items = []

    def _save(self) -> None:
        self.storage_path.write_text(json.dumps(self._items, ensure_ascii=False, indent=2), encoding="utf-8")

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    def _get(self, sig_id: str) -> dict[str, Any] | None:
        target = str(sig_id)
        for item in self._items:
            if str(item.get("id", "")) == target:
                return item
        return None

    def _normalize(self, signature: dict[str, Any], *, for_update: bool = False) -> dict[str, Any]:
        if not isinstance(signature, dict):
            raise ValueError("signature must be an object")

        out: dict[str, Any] = {}
        if not for_update:
            sig_id = str(signature.get("id", "")).strip()
            if not sig_id:
                raise ValueError("id is required")
            out["id"] = sig_id

        if "name" in signature or not for_update:
            name = str(signature.get("name", "")).strip()
            if not name and not for_update:
                raise ValueError("name is required")
            if name:
                out["name"] = name

        if "category" in signature or not for_update:
            category = str(signature.get("category", "custom")).strip().lower()
            if category not in self._CATEGORIES:
                raise ValueError("invalid category")
            out["category"] = category

        if "severity" in signature or not for_update:
            severity = str(signature.get("severity", "medium")).strip().lower()
            if severity not in self._SEVERITIES:
                raise ValueError("invalid severity")
            out["severity"] = severity

        if "pattern" in signature or not for_update:
            pattern = str(signature.get("pattern", "")).strip()
            if not pattern and not for_update:
                raise ValueError("pattern is required")
            if pattern:
                try:
                    re.compile(pattern)
                except re.error as exc:
                    raise ValueError(f"invalid pattern: {exc}") from exc
                out["pattern"] = pattern

        if "description" in signature or not for_update:
            out["description"] = str(signature.get("description", "")).strip()

        if "enabled" in signature or not for_update:
            out["enabled"] = bool(signature.get("enabled", True))

        if "created_at" in signature:
            out["created_at"] = str(signature.get("created_at", "")).strip() or self._now_iso()
        elif not for_update:
            out["created_at"] = self._now_iso()

        if "tags" in signature or not for_update:
            tags = signature.get("tags", [])
            if not isinstance(tags, list):
                raise ValueError("tags must be list")
            out["tags"] = [str(item).strip() for item in tags if str(item).strip()]

        return out

    def create(self, signature: dict) -> dict:
        """Validate and create new signature."""
        row = self._normalize(signature, for_update=False)
        if self._get(str(row.get("id", ""))) is not None:
            raise ValueError("signature id already exists")
        self._items.append(row)
        self._save()
        return dict(row)

    def update(self, sig_id: str, updates: dict) -> dict:
        """Update existing signature."""
        item = self._get(sig_id)
        if item is None:
            raise KeyError("signature not found")
        patch = self._normalize(updates, for_update=True)
        patch.pop("id", None)
        item.update(patch)
        self._save()
        return dict(item)

    def delete(self, sig_id: str) -> bool:
        """Delete signature."""
        target = str(sig_id)
        before = len(self._items)
        self._items = [item for item in self._items if str(item.get("id", "")) != target]
        changed = len(self._items) < before
        if changed:
            self._save()
        return changed

    def list_all(self, category: str | None = None) -> list[dict]:
        """List signatures with optional category filter."""
        rows = [dict(item) for item in self._items]
        if isinstance(category, str) and category.strip():
            key = category.strip().lower()
            rows = [item for item in rows if str(item.get("category", "")).lower() == key]
        rows.sort(key=lambda item: str(item.get("id", "")))
        return rows

    def test_pattern(self, pattern: str, test_text: str) -> dict:
        """Test regex pattern against sample text safely."""
        pat = str(pattern or "")
        text = str(test_text or "")
        if len(pat) > 1000 or len(text) > 20_000:
            return {"matched": False, "matches": [], "safe": False}

        # Basic heuristic for catastrophic patterns.
        risky = bool(re.search(r"\([^)]*[+*][^)]*\)[+*]", pat))
        if risky:
            return {"matched": False, "matches": [], "safe": False}
        try:
            compiled = re.compile(pat)
        except re.error:
            return {"matched": False, "matches": [], "safe": False}

        matches = [m.group(0) for m in compiled.finditer(text)]
        return {"matched": bool(matches), "matches": matches[:50], "safe": True}

    def export_yaml(self, path: str) -> None:
        """Export signatures as YAML."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(yaml.safe_dump(self._items, sort_keys=False, allow_unicode=True), encoding="utf-8")

    def import_yaml(self, path: str) -> int:
        """Import signatures from YAML."""
        source = Path(path)
        payload = yaml.safe_load(source.read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            return 0
        imported = 0
        for item in payload:
            if not isinstance(item, dict):
                continue
            try:
                normalized = self._normalize(item, for_update=False)
            except ValueError:
                continue
            existing = self._get(str(normalized.get("id", "")))
            if existing is None:
                self._items.append(normalized)
            else:
                existing.update(normalized)
            imported += 1
        if imported:
            self._save()
        return imported
