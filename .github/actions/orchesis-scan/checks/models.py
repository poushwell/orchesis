from __future__ import annotations

from dataclasses import asdict, dataclass

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    id: str
    severity: str
    title: str
    description: str
    file: str
    line: int
    remediation: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def severity_meets_threshold(severity: str, threshold: str) -> bool:
    return SEVERITY_ORDER.get(str(severity).lower(), 0) >= SEVERITY_ORDER.get(str(threshold).lower(), 0)
