"""Public findings publisher with anonymization."""

from __future__ import annotations

import json
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from orchesis import __version__


class FindingsPublisher:
    """Publishes anonymized security findings."""

    def __init__(self, config: dict | None = None):
        cfg = config or {}
        self.publish_url = str(cfg.get("publish_url", "https://orchesis.io/api/publish"))

    def build_report(self, decisions_log: list, period_days: int = 7) -> dict:
        """Build anonymized public report."""
        now = datetime.now(timezone.utc)
        threshold = now - timedelta(days=max(1, int(period_days)))
        filtered = [item for item in decisions_log if self._within_period(item, threshold)]
        total = len(filtered)
        denied = sum(
            1
            for item in filtered
            if str(self._get(item, "decision", "")).upper() == "DENY"
        )
        blocked_percent = round((denied / total * 100.0) if total else 0.0, 2)

        durations_us: list[float] = []
        for item in filtered:
            raw = self._get(item, "evaluation_duration_us", None)
            try:
                if raw is not None:
                    durations_us.append(float(raw))
            except (TypeError, ValueError):
                continue
        avg_response_ms = round(((sum(durations_us) / len(durations_us)) / 1000.0) if durations_us else 0.0, 3)

        category_counter: Counter[str] = Counter()
        finding_counter: Counter[str] = Counter()
        for item in filtered:
            if str(self._get(item, "decision", "")).upper() != "DENY":
                continue
            reasons = self._to_str_list(self._get(item, "reasons", []))
            if not reasons:
                category_counter["policy"] += 1
                finding_counter["policy"] += 1
                continue
            for reason in reasons:
                category = self._reason_category(reason)
                category_counter[category] += 1
                finding_counter[category] += 1

        top_categories = [
            {"category": category, "count": count}
            for category, count in category_counter.most_common(5)
        ]
        findings = [
            {"category": category, "count": count, "sample": self._anonymize_text(category)}
            for category, count in finding_counter.most_common(10)
        ]

        return {
            "report_id": str(uuid4()),
            "period_days": int(max(1, int(period_days))),
            "generated_at": now.isoformat(),
            "stats": {
                "total_requests": total,
                "blocked_percent": blocked_percent,
                "top_threat_categories": top_categories,
                "avg_response_ms": avg_response_ms,
            },
            "findings": findings,
            "environment": {
                "orchesis_version": __version__,
                "pipeline_phases": 17,
            },
        }

    def publish(self, report: dict) -> str:
        """Publish report. Returns public URL."""
        report_id = str(report.get("report_id", uuid4()))
        base = self.publish_url.rstrip("/")
        if base.endswith("/api/publish"):
            base = base[: -len("/api/publish")]
        return f"{base}/reports/{report_id}"

    def export_local(self, report: dict, path: str) -> None:
        """Save report locally without publishing."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    @staticmethod
    def _get(item: Any, key: str, default: Any = None) -> Any:
        if isinstance(item, dict):
            return item.get(key, default)
        return getattr(item, key, default)

    @staticmethod
    def _to_str_list(value: Any) -> list[str]:
        if not isinstance(value, list):
            return []
        return [str(v) for v in value if isinstance(v, str) and v.strip()]

    @staticmethod
    def _parse_ts(value: Any) -> datetime | None:
        if not isinstance(value, str) or not value.strip():
            return None
        try:
            dt = datetime.fromisoformat(value)
        except ValueError:
            return None
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    def _within_period(self, item: Any, threshold: datetime) -> bool:
        ts = self._parse_ts(self._get(item, "timestamp", None))
        if ts is None:
            return False
        return ts >= threshold

    @staticmethod
    def _reason_category(reason: str) -> str:
        head = reason.split(":", 1)[0].strip().lower()
        if not head:
            return "policy"
        return FindingsPublisher._anonymize_text(head)

    @staticmethod
    def _anonymize_text(text: str) -> str:
        out = text
        out = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "[redacted_email]", out)
        out = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "[redacted_ssn]", out)
        out = re.sub(r"\bsk-[A-Za-z0-9_-]+\b", "[redacted_key]", out)
        out = re.sub(r"\bAKIA[0-9A-Z]{16}\b", "[redacted_key]", out)
        return out
