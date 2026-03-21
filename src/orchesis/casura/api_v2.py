"""CASURA API v2 primitives: bulk incident import and validation."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from uuid import uuid4

from orchesis.models.ecosystem import IncidentRecord
from orchesis.utils.log import get_logger


logger = get_logger(__name__)
COMPONENT = "casura.api_v2"


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

    def to_canonical(self) -> IncidentRecord:
        ts_value = self.timestamp
        parsed_ts: float
        if isinstance(ts_value, str) and ts_value.strip():
            try:
                dt = datetime.fromisoformat(ts_value.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                parsed_ts = dt.timestamp()
            except ValueError:
                parsed_ts = 0.0
        else:
            parsed_ts = 0.0
        return IncidentRecord(
            incident_id=self.incident_id,
            title=self.title,
            severity=float(self.severity),
            category=self.category,
            description=self.description,
            source=self.source,
            timestamp=parsed_ts,
            tags=list(self.tags),
            cve_ids=list(self.cve_ids),
            affected_systems=list(self.affected_systems),
        )

    @classmethod
    def from_canonical(cls, record: IncidentRecord) -> "Incident":
        ts_text = ""
        try:
            ts_text = datetime.fromtimestamp(float(record.timestamp), tz=timezone.utc).isoformat()
        except (TypeError, ValueError, OSError):
            ts_text = ""
        return cls(
            incident_id=str(record.incident_id),
            title=str(record.title),
            severity=float(record.severity),
            category=str(record.category),
            description=str(record.description),
            source=str(record.source),
            timestamp=ts_text,
            tags=[str(item) for item in record.tags],
            cve_ids=[str(item) for item in record.cve_ids],
            affected_systems=[str(item) for item in record.affected_systems],
        )


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
        logger.info(
            "Starting CASURA bulk import",
            extra={"component": COMPONENT, "batch_size": len(incidents)},
        )
        if len(incidents) > self.max_batch_size:
            logger.warning(
                "CASURA bulk import rejected: batch too large",
                extra={
                    "component": COMPONENT,
                    "batch_size": len(incidents),
                    "max_batch_size": self.max_batch_size,
                },
            )
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
                logger.warning(
                    "CASURA incident failed validation",
                    extra={
                        "component": COMPONENT,
                        "row_index": index,
                        "error_count": len(row_errors),
                    },
                )
                continue
            if incident is None:
                failed_count += 1
                logger.warning(
                    "CASURA incident import skipped after validation",
                    extra={"component": COMPONENT, "row_index": index},
                )
                continue

            if incident.incident_id in self._store or incident.incident_id in seen_batch:
                deduped_count += 1
                logger.info(
                    "CASURA incident deduplicated",
                    extra={
                        "component": COMPONENT,
                        "row_index": index,
                        "incident_id": incident.incident_id,
                    },
                )
                continue

            self._store[incident.incident_id] = incident
            seen_batch.add(incident.incident_id)
            imported_count += 1
            imported_ids.append(incident.incident_id)

        result = BulkResult(
            imported_count=imported_count,
            failed_count=failed_count,
            deduped_count=deduped_count,
            errors=errors,
            imported_ids=imported_ids,
        )
        logger.info(
            "Completed CASURA bulk import",
            extra={
                "component": COMPONENT,
                "imported_count": imported_count,
                "failed_count": failed_count,
                "deduped_count": deduped_count,
            },
        )
        return result

    def get_all_incidents(self) -> list[Incident]:
        return list(self._store.values())

    def clear(self) -> None:
        self._store.clear()
