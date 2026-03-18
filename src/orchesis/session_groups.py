"""Session group management utilities."""

from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class SessionGroupManager:
    """Groups related sessions into named workflows."""

    def __init__(self, storage_path: str = ".orchesis/session_groups.json"):
        self._groups: dict[str, dict] = {}
        self._storage = str(storage_path)
        self._lock = threading.Lock()
        self._load()

    def _load(self) -> None:
        path = Path(self._storage)
        if not path.exists():
            return
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return
        if isinstance(payload, dict):
            groups = payload.get("groups", {})
            if isinstance(groups, dict):
                self._groups = {
                    str(group_id): dict(item)
                    for group_id, item in groups.items()
                    if isinstance(item, dict)
                }

    def _save(self) -> None:
        path = Path(self._storage)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"groups": self._groups}
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    @staticmethod
    def _event_field(event: Any, key: str, default: Any = None) -> Any:
        if isinstance(event, dict):
            return event.get(key, default)
        return getattr(event, key, default)

    @staticmethod
    def _event_session_id(event: Any) -> str:
        if isinstance(event, dict):
            snapshot = event.get("state_snapshot", {})
            if isinstance(snapshot, dict):
                sid = snapshot.get("session_id")
                if isinstance(sid, str) and sid.strip():
                    return sid.strip()
            sid = event.get("session_id")
            return sid.strip() if isinstance(sid, str) and sid.strip() else ""
        snapshot = getattr(event, "state_snapshot", {})
        if isinstance(snapshot, dict):
            sid = snapshot.get("session_id")
            if isinstance(sid, str) and sid.strip():
                return sid.strip()
        sid = getattr(event, "session_id", "")
        return sid.strip() if isinstance(sid, str) and sid.strip() else ""

    def create_group(self, name: str, description: str = "") -> dict:
        group_id = uuid.uuid4().hex[:8]
        row = {
            "group_id": group_id,
            "name": str(name),
            "description": str(description or ""),
            "sessions": [],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "total_cost": 0.0,
            "total_requests": 0,
        }
        with self._lock:
            self._groups[group_id] = row
            self._save()
            return dict(row)

    def add_session(self, group_id: str, session_id: str) -> bool:
        gid = str(group_id)
        sid = str(session_id).strip()
        if not sid:
            return False
        with self._lock:
            group = self._groups.get(gid)
            if not isinstance(group, dict):
                return False
            sessions = list(group.get("sessions", [])) if isinstance(group.get("sessions"), list) else []
            if sid in sessions:
                return True
            sessions.append(sid)
            group["sessions"] = sessions
            self._save()
            return True

    def remove_session(self, group_id: str, session_id: str) -> bool:
        gid = str(group_id)
        sid = str(session_id).strip()
        with self._lock:
            group = self._groups.get(gid)
            if not isinstance(group, dict):
                return False
            sessions = list(group.get("sessions", [])) if isinstance(group.get("sessions"), list) else []
            if sid not in sessions:
                return False
            group["sessions"] = [item for item in sessions if item != sid]
            self._save()
            return True

    def get_group_stats(self, group_id: str, decisions_log: list) -> dict:
        gid = str(group_id)
        with self._lock:
            group = dict(self._groups.get(gid, {}))
        if not group:
            return {}
        sessions = set(str(item) for item in group.get("sessions", []) if isinstance(item, str) and item.strip())
        total_cost = 0.0
        total_requests = 0
        threats = 0
        for event in decisions_log if isinstance(decisions_log, list) else []:
            sid = self._event_session_id(event)
            if sid not in sessions:
                continue
            total_requests += 1
            try:
                total_cost += float(self._event_field(event, "cost", 0.0) or 0.0)
            except (TypeError, ValueError):
                pass
            decision = str(self._event_field(event, "decision", "") or "").upper()
            reasons = self._event_field(event, "reasons", [])
            reason_text = " ".join(str(item).lower() for item in reasons) if isinstance(reasons, list) else ""
            if decision == "DENY" or "threat" in reason_text or "injection" in reason_text:
                threats += 1
        group["total_cost"] = round(total_cost, 8)
        group["total_requests"] = int(total_requests)
        group["threats"] = int(threats)
        return group

    def list_groups(self) -> list[dict]:
        with self._lock:
            rows = [dict(item) for item in self._groups.values() if isinstance(item, dict)]
        rows.sort(key=lambda item: str(item.get("created_at", "")), reverse=True)
        return rows

    def delete_group(self, group_id: str) -> bool:
        gid = str(group_id)
        with self._lock:
            if gid not in self._groups:
                return False
            del self._groups[gid]
            self._save()
            return True
