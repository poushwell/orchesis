"""CASURA Incident Database core primitives."""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class CASURAIncidentDB:
    """CASURA - AI Agent Incident Intelligence Platform.

    Open database with AISS v2.0 severity scoring.
    CVSS-inspired, cross-mapped to OWASP Agentic, MAST, MITRE ATLAS,
    EU AI Act, NIST, MIT Risk Repository.
    """

    AISS_VERSION = "2.0"

    SEVERITY_LEVELS = {
        "CRITICAL": (9.0, 10.0),
        "HIGH": (7.0, 8.9),
        "MEDIUM": (4.0, 6.9),
        "LOW": (0.1, 3.9),
        "INFORMATIONAL": (0.0, 0.0),
    }

    FRAMEWORK_MAPPINGS = {
        "owasp_agentic": "OWASP Agentic AI Top 10",
        "mast": "MAST Mobile AI Security",
        "mitre_atlas": "MITRE ATLAS",
        "eu_ai_act": "EU AI Act Articles",
        "nist": "NIST AI RMF",
        "mit_risk": "MIT AI Risk Repository",
    }

    def __init__(self, storage_path: str = ".casura/incidents"):
        self._incidents: dict[str, dict[str, Any]] = {}
        self._storage = Path(storage_path)
        self._lock = threading.Lock()
        self._index_file = self._storage / "incidents.json"
        self._load()

    def _load(self) -> None:
        with self._lock:
            if not self._index_file.exists():
                return
            try:
                payload = json.loads(self._index_file.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                return
            if isinstance(payload, dict):
                self._incidents = {
                    str(key): value
                    for key, value in payload.items()
                    if isinstance(value, dict)
                }

    def _persist(self) -> None:
        self._storage.mkdir(parents=True, exist_ok=True)
        self._index_file.write_text(
            json.dumps(self._incidents, ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    @staticmethod
    def _norm_factor(value: Any, default: float) -> float:
        if isinstance(value, bool):
            return default
        if not isinstance(value, int | float):
            return default
        number = float(value)
        if number <= 1.0:
            return max(0.0, min(1.0, number))
        return max(0.0, min(1.0, number / 10.0))

    def compute_aiss_score(self, factors: dict) -> float:
        """AISS v2.0 scoring: attack_vector × impact × exploitability."""
        payload = factors if isinstance(factors, dict) else {}
        av = self._norm_factor(payload.get("attack_vector"), 0.5)
        impact = self._norm_factor(payload.get("impact"), 0.5)
        exploit = self._norm_factor(payload.get("exploitability"), 0.5)
        score = round(max(0.0, min(10.0, 10.0 * av * impact * exploit)), 2)
        return score

    def _severity_for_score(self, score: float) -> str:
        for level, (min_score, max_score) in self.SEVERITY_LEVELS.items():
            if min_score <= score <= max_score:
                return level
        return "INFORMATIONAL"

    def map_to_frameworks(self, incident: dict) -> dict:
        """Cross-map incident to all frameworks."""
        payload = incident if isinstance(incident, dict) else {}
        text_blob = " ".join(
            [
                str(payload.get("title", "")),
                str(payload.get("description", "")),
                " ".join(str(item) for item in (payload.get("tags") or []) if isinstance(item, str)),
            ]
        ).lower()
        mappings: dict[str, list[str]] = {
            "owasp_agentic": [],
            "mast": [],
            "mitre_atlas": [],
            "eu_ai_act": [],
            "nist": [],
            "mit_risk": [],
        }
        if "prompt" in text_blob or "injection" in text_blob:
            mappings["owasp_agentic"].append("A1 Prompt Injection")
            mappings["mitre_atlas"].append("T0051 Prompt Injection")
        if "loop" in text_blob or "resource" in text_blob:
            mappings["owasp_agentic"].append("A8 Unbounded Consumption")
            mappings["nist"].append("Measure-2 Resource Monitoring")
        if "credential" in text_blob or "secret" in text_blob:
            mappings["mast"].append("MST-SEC-03 Credential Leakage")
            mappings["eu_ai_act"].append("Article 12 Record Keeping")
        if "safety" in text_blob or "policy" in text_blob:
            mappings["eu_ai_act"].append("Article 9 Risk Management")
            mappings["mit_risk"].append("R-12 Policy Misalignment")
        return mappings

    def create_incident(self, data: dict) -> dict:
        """Create new incident with AISS scoring."""
        payload = data if isinstance(data, dict) else {}
        title = str(payload.get("title", "Untitled incident")).strip() or "Untitled incident"
        description = str(payload.get("description", "")).strip()
        tags = [str(item).strip() for item in payload.get("tags", []) if str(item).strip()] if isinstance(
            payload.get("tags"), list
        ) else []
        factors = payload.get("factors") if isinstance(payload.get("factors"), dict) else payload
        score = self.compute_aiss_score(factors)
        severity = self._severity_for_score(score)
        now = datetime.now(timezone.utc)
        with self._lock:
            ordinal = len(self._incidents) + 1
            incident_id = f"CASURA-{now.year}-{ordinal:04d}"
            incident = {
                "incident_id": incident_id,
                "title": title,
                "description": description,
                "aiss_score": score,
                "severity": severity,
                "created_at": now.isoformat(),
                "framework_mappings": {},
                "tags": tags,
                "status": "open",
            }
            incident["framework_mappings"] = self.map_to_frameworks(incident)
            self._incidents[incident_id] = incident
            self._persist()
            return dict(incident)

    def search(self, query: str, filters: dict | None = None) -> list[dict]:
        """Full-text search across incidents."""
        needle = str(query or "").strip().lower()
        constraints = filters if isinstance(filters, dict) else {}
        rows: list[dict[str, Any]] = []
        with self._lock:
            incidents = list(self._incidents.values())
        for item in incidents:
            blob = " ".join(
                [
                    str(item.get("incident_id", "")),
                    str(item.get("title", "")),
                    str(item.get("description", "")),
                    str(item.get("severity", "")),
                    " ".join(str(t) for t in item.get("tags", []) if isinstance(t, str)),
                ]
            ).lower()
            if needle and needle not in blob:
                continue
            sev_filter = constraints.get("severity")
            if isinstance(sev_filter, str) and sev_filter.strip():
                if str(item.get("severity", "")).upper() != sev_filter.strip().upper():
                    continue
            status_filter = constraints.get("status")
            if isinstance(status_filter, str) and status_filter.strip():
                if str(item.get("status", "")).lower() != status_filter.strip().lower():
                    continue
            tag_filter = constraints.get("tag")
            if isinstance(tag_filter, str) and tag_filter.strip():
                tags = [str(t).lower() for t in item.get("tags", []) if isinstance(t, str)]
                if tag_filter.strip().lower() not in tags:
                    continue
            rows.append(dict(item))
        rows.sort(key=lambda row: str(row.get("created_at", "")), reverse=True)
        return rows

    def get_stats(self) -> dict:
        with self._lock:
            incidents = list(self._incidents.values())
        by_severity: dict[str, int] = {key: 0 for key in self.SEVERITY_LEVELS}
        by_framework: dict[str, int] = {key: 0 for key in self.FRAMEWORK_MAPPINGS}
        score_sum = 0.0
        for item in incidents:
            severity = str(item.get("severity", "INFORMATIONAL")).upper()
            if severity in by_severity:
                by_severity[severity] += 1
            score_sum += float(item.get("aiss_score", 0.0) or 0.0)
            framework_map = item.get("framework_mappings", {})
            if isinstance(framework_map, dict):
                for key in by_framework:
                    values = framework_map.get(key, [])
                    if isinstance(values, list) and values:
                        by_framework[key] += 1
        avg = round(score_sum / float(len(incidents)), 3) if incidents else 0.0
        return {
            "total_incidents": len(incidents),
            "by_severity": by_severity,
            "by_framework": by_framework,
            "aiss_avg": avg,
        }
