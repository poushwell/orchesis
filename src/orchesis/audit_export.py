"""Audit trail export utilities."""

from __future__ import annotations

import csv
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


class AuditTrailExporter:
    """Export full audit trail in multiple formats."""

    def __init__(self, decisions_log_path: str):
        self.log_path = decisions_log_path

    def export_json(self, output_path: str, filters: dict | None = None) -> int:
        """Export as JSON. Returns record count."""
        records = self._records_for_filters(filters)
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")
        return len(records)

    def export_csv(self, output_path: str, filters: dict | None = None) -> int:
        """Export as CSV. Returns record count."""
        records = self._records_for_filters(filters)
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        fieldnames = [
            "timestamp",
            "agent_id",
            "session_id",
            "tool",
            "decision",
            "cost",
            "reasons",
            "policy_version",
            "event_id",
        ]
        with target.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for record in records:
                writer.writerow(
                    {
                        "timestamp": record.get("timestamp", ""),
                        "agent_id": record.get("agent_id", ""),
                        "session_id": self._session_id(record),
                        "tool": record.get("tool", ""),
                        "decision": record.get("decision", ""),
                        "cost": record.get("cost", 0.0),
                        "reasons": "; ".join(
                            item for item in record.get("reasons", []) if isinstance(item, str)
                        ),
                        "policy_version": record.get("policy_version", ""),
                        "event_id": record.get("event_id", ""),
                    }
                )
        return len(records)

    def export_jsonl(self, output_path: str, filters: dict | None = None) -> int:
        """Export as JSONL (newline-delimited). Returns record count."""
        records = self._records_for_filters(filters)
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("w", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        return len(records)

    def filter_by(
        self,
        agent_id: str | None = None,
        session_id: str | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        decision: str | None = None,  # "ALLOW" | "DENY"
    ) -> list[dict]:
        """Filter decisions log."""
        records = self._read_records()
        from_dt = self._parse_bound(date_from, end=False) if isinstance(date_from, str) and date_from.strip() else None
        to_dt = self._parse_bound(date_to, end=True) if isinstance(date_to, str) and date_to.strip() else None
        decision_norm = decision.strip().upper() if isinstance(decision, str) and decision.strip() else None

        filtered: list[dict] = []
        for record in records:
            if agent_id and str(record.get("agent_id", "")) != str(agent_id):
                continue
            if session_id and self._session_id(record) != str(session_id):
                continue
            if decision_norm and str(record.get("decision", "")).upper() != decision_norm:
                continue
            ts = self._parse_timestamp(record.get("timestamp"))
            if from_dt is not None:
                if ts is None or ts < from_dt:
                    continue
            if to_dt is not None:
                if ts is None or ts >= to_dt:
                    continue
            filtered.append(record)
        return filtered

    def get_summary(self, records: list[dict]) -> dict:
        """Summary stats for filtered records."""
        total = len(records)
        allow_count = sum(1 for item in records if str(item.get("decision", "")).upper() == "ALLOW")
        deny_count = sum(1 for item in records if str(item.get("decision", "")).upper() == "DENY")
        agents = {
            str(item.get("agent_id", ""))
            for item in records
            if isinstance(item.get("agent_id"), str) and str(item.get("agent_id")).strip()
        }
        sessions = {self._session_id(item) for item in records if self._session_id(item)}
        total_cost = 0.0
        for item in records:
            try:
                total_cost += float(item.get("cost", 0.0))
            except (TypeError, ValueError):
                continue
        return {
            "total_records": total,
            "allow_count": allow_count,
            "deny_count": deny_count,
            "unique_agents": len(agents),
            "unique_sessions": len(sessions),
            "total_cost_usd": round(total_cost, 6),
        }

    def _records_for_filters(self, filters: dict | None) -> list[dict]:
        if not isinstance(filters, dict):
            return self.filter_by()
        return self.filter_by(
            agent_id=filters.get("agent_id"),
            session_id=filters.get("session_id"),
            date_from=filters.get("date_from"),
            date_to=filters.get("date_to"),
            decision=filters.get("decision"),
        )

    def _read_records(self) -> list[dict]:
        path = Path(self.log_path)
        if not path.exists():
            return []
        rows: list[dict] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            row = line.strip()
            if not row:
                continue
            try:
                payload = json.loads(row)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                rows.append(payload)
        return rows

    @staticmethod
    def _session_id(record: dict[str, Any]) -> str:
        if isinstance(record.get("session_id"), str) and record.get("session_id"):
            return str(record.get("session_id"))
        snapshot = record.get("state_snapshot")
        if isinstance(snapshot, dict):
            session_id = snapshot.get("session_id")
            if isinstance(session_id, str) and session_id:
                return session_id
        return ""

    @staticmethod
    def _parse_timestamp(value: Any) -> datetime | None:
        if not isinstance(value, str) or not value.strip():
            return None
        try:
            dt = datetime.fromisoformat(value)
        except ValueError:
            return None
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    @staticmethod
    def _parse_bound(raw: str, *, end: bool) -> datetime | None:
        value = raw.strip()
        if not value:
            return None
        if len(value) == 10:
            try:
                date_only = datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except ValueError:
                return None
            return date_only + timedelta(days=1) if end else date_only
        parsed = AuditTrailExporter._parse_timestamp(value)
        if parsed is None:
            return None
        return parsed + timedelta(microseconds=1) if end else parsed
