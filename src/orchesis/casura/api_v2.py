"""CASURA API v2 primitives: bulk incident import and validation."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from uuid import uuid4


class CasuraCategory(Enum):
    prompt_injection = "prompt_injection"
    data_exfiltration = "data_exfiltration"
    model_poisoning = "model_poisoning"
    denial_of_service = "denial_of_service"
    privilege_escalation = "privilege_escalation"
    supply_chain = "supply_chain"
    output_manipulation = "output_manipulation"
    resource_abuse = "resource_abuse"
    privacy_violation = "privacy_violation"
    alignment_failure = "alignment_failure"
    tool_misuse = "tool_misuse"
    context_manipulation = "context_manipulation"


VALID_CATEGORIES = {category.value for category in CasuraCategory}


@dataclass(slots=True)
class ValidationError:
    index: int
    field: str
    message: str
    incident_id: str | None = None


@dataclass(slots=True)
class Incident:
    incident_id: str
    title: str
    severity: float
    category: str
    description: str = ""
    source: str = ""
    timestamp: str = ""
    tags: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)
    affected_systems: list[str] = field(default_factory=list)


@dataclass(slots=True)
class BulkResult:
    imported_count: int
    failed_count: int
    deduped_count: int
    errors: list[ValidationError]
    imported_ids: list[str]


class BulkImporter:
    """Bulk import incidents with schema validation and deduplication."""

    def __init__(self, max_batch_size: int = 1000):
        self.max_batch_size = int(max_batch_size)
        self._store: dict[str, Incident] = {}

    def _validate_incident(self, data: dict, index: int) -> tuple[Optional[Incident], list[ValidationError]]:
        errors: list[ValidationError] = []
        incident_id = str(data.get("incident_id") or f"casura-{uuid4().hex[:12]}")

        title = str(data.get("title", "")).strip()
        if not title:
            errors.append(ValidationError(index=index, field="title", message="title is required", incident_id=incident_id))

        raw_severity = data.get("severity")
        severity: float = 0.0
        try:
            severity = float(raw_severity)
            if severity < 0.0 or severity > 10.0:
                raise ValueError
        except (TypeError, ValueError):
            errors.append(
                ValidationError(
                    index=index,
                    field="severity",
                    message="severity must be a float in range 0.0-10.0",
                    incident_id=incident_id,
                )
            )

        category = str(data.get("category", "")).strip()
        if category not in VALID_CATEGORIES:
            errors.append(
                ValidationError(
                    index=index,
                    field="category",
                    message="category must be one of VALID_CATEGORIES",
                    incident_id=incident_id,
                )
            )

        if errors:
            return None, errors

        incident = Incident(
            incident_id=incident_id,
            title=title,
            severity=severity,
            category=category,
            description=str(data.get("description", "") or ""),
            source=str(data.get("source", "") or ""),
            timestamp=str(data.get("timestamp", "") or ""),
            tags=[str(item) for item in data.get("tags", []) if isinstance(item, str)],
            cve_ids=[str(item) for item in data.get("cve_ids", []) if isinstance(item, str)],
            affected_systems=[str(item) for item in data.get("affected_systems", []) if isinstance(item, str)],
        )
        return incident, []

    def import_incidents(self, incidents: list[dict]) -> BulkResult:
        if len(incidents) > self.max_batch_size:
            return BulkResult(
                imported_count=0,
                failed_count=len(incidents),
                deduped_count=0,
                errors=[
                    ValidationError(
                        index=-1,
                        field="batch",
                        message=f"batch size exceeds max_batch_size={self.max_batch_size}",
                    )
                ],
                imported_ids=[],
            )

        imported_count = 0
        failed_count = 0
        deduped_count = 0
        errors: list[ValidationError] = []
        imported_ids: list[str] = []
        seen_batch: set[str] = set()

        for index, row in enumerate(incidents):
            incident, row_errors = self._validate_incident(row if isinstance(row, dict) else {}, index)
            if row_errors:
                failed_count += 1
                errors.extend(row_errors)
                continue
            if incident is None:
                failed_count += 1
                continue

            if incident.incident_id in self._store or incident.incident_id in seen_batch:
                deduped_count += 1
                continue

            self._store[incident.incident_id] = incident
            seen_batch.add(incident.incident_id)
            imported_count += 1
            imported_ids.append(incident.incident_id)

        return BulkResult(
            imported_count=imported_count,
            failed_count=failed_count,
            deduped_count=deduped_count,
            errors=errors,
            imported_ids=imported_ids,
        )

    def get_all_incidents(self) -> list[Incident]:
        return list(self._store.values())

    def clear(self) -> None:
        self._store.clear()
