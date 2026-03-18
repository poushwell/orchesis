"""CASURA incident intelligence and pattern analysis."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from typing import Any


class IncidentIntelligence:
    """Pattern analysis across CASURA incident database."""

    @staticmethod
    def _safe_list(value: Any) -> list[Any]:
        return value if isinstance(value, list) else []

    def analyze_patterns(self, incidents: list[dict]) -> dict:
        rows = [item for item in incidents if isinstance(item, dict)]
        vector_counter: Counter[str] = Counter()
        framework_heatmap: dict[str, int] = defaultdict(int)
        severity_trend: dict[str, int] = defaultdict(int)
        tag_counter: Counter[str] = Counter()

        for item in rows:
            vector = str(item.get("attack_vector", "") or "").strip()
            if not vector:
                factors = item.get("factors")
                if isinstance(factors, dict):
                    vector = str(factors.get("attack_vector", "") or "").strip()
            if vector:
                vector_counter[vector] += 1

            mappings = item.get("framework_mappings")
            if isinstance(mappings, dict):
                for key, values in mappings.items():
                    if isinstance(values, list) and values:
                        framework_heatmap[str(key)] += len(values)

            created_at = str(item.get("created_at", "") or "")
            day = created_at[:10] if len(created_at) >= 10 else "unknown"
            severity = str(item.get("severity", "UNKNOWN") or "UNKNOWN").upper()
            severity_trend[f"{day}:{severity}"] += 1

            for tag in self._safe_list(item.get("tags")):
                if isinstance(tag, str) and tag.strip():
                    tag_counter[tag.strip().lower()] += 1

        top_attack_vectors = [
            {"attack_vector": name, "count": count}
            for name, count in vector_counter.most_common(5)
        ]
        common_tags = [{"tag": name, "count": count} for name, count in tag_counter.most_common(8)]

        emerging_threats = [
            name
            for name, count in tag_counter.items()
            if count == 1 and name in {tag["tag"] for tag in common_tags[:5]}
        ]
        if not emerging_threats:
            emerging_threats = [name for name, _count in common_tags[:3]]

        trend_rows = [
            {"bucket": bucket, "count": count}
            for bucket, count in sorted(severity_trend.items())
        ]

        return {
            "top_attack_vectors": top_attack_vectors,
            "framework_heatmap": dict(framework_heatmap),
            "severity_trend": trend_rows,
            "common_tags": common_tags,
            "emerging_threats": emerging_threats,
        }

    def detect_clusters(self, incidents: list[dict]) -> list[dict]:
        """Group related incidents by similarity."""
        rows = [item for item in incidents if isinstance(item, dict)]
        clusters: dict[str, dict[str, Any]] = {}
        for item in rows:
            tags = [str(tag).strip().lower() for tag in self._safe_list(item.get("tags")) if str(tag).strip()]
            primary = tags[0] if tags else str(item.get("severity", "unknown")).lower()
            row = clusters.setdefault(primary, {"cluster": primary, "count": 0, "incident_ids": []})
            row["count"] += 1
            incident_id = str(item.get("incident_id", "") or "")
            if incident_id:
                row["incident_ids"].append(incident_id)
        output = list(clusters.values())
        output.sort(key=lambda row: int(row.get("count", 0)), reverse=True)
        return output

    def predict_next_incident(self, history: list[dict]) -> dict:
        """Predict likely next incident type based on patterns."""
        rows = [item for item in history if isinstance(item, dict)]
        tag_counter: Counter[str] = Counter()
        for item in rows:
            for tag in self._safe_list(item.get("tags")):
                if isinstance(tag, str) and tag.strip():
                    tag_counter[tag.strip().lower()] += 1
        if not tag_counter:
            return {"predicted_type": "unknown", "confidence": 0.0, "based_on": len(rows)}
        predicted, count = tag_counter.most_common(1)[0]
        confidence = round(count / float(max(1, len(rows))), 3)
        return {
            "predicted_type": predicted,
            "confidence": confidence,
            "based_on": len(rows),
        }

    def generate_threat_brief(self, incidents: list[dict]) -> str:
        """Generate executive threat intelligence brief."""
        rows = [item for item in incidents if isinstance(item, dict)]
        analysis = self.analyze_patterns(rows)
        total = len(rows)
        top = analysis["top_attack_vectors"][0]["attack_vector"] if analysis["top_attack_vectors"] else "n/a"
        emerging = ", ".join(analysis["emerging_threats"][:3]) if analysis["emerging_threats"] else "none"
        return (
            f"CASURA Threat Brief\n"
            f"Total incidents analyzed: {total}\n"
            f"Top attack vector: {top}\n"
            f"Emerging threats: {emerging}\n"
        )

    def get_mitre_coverage(self, incidents: list[dict]) -> dict:
        """Coverage across MITRE ATLAS tactics."""
        rows = [item for item in incidents if isinstance(item, dict)]
        counter: Counter[str] = Counter()
        for item in rows:
            mappings = item.get("framework_mappings")
            if not isinstance(mappings, dict):
                continue
            for entry in self._safe_list(mappings.get("mitre_atlas")):
                if isinstance(entry, str) and entry.strip():
                    counter[entry.strip()] += 1
        total = sum(counter.values())
        coverage = {
            key: {"count": value, "ratio": round(value / float(total), 3) if total > 0 else 0.0}
            for key, value in counter.items()
        }
        return {"total_mitre_mappings": total, "coverage": coverage}
