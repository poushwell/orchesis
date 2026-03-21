"""Compliance package with compatibility exports and Fleet Compliance Engine."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

from .fce import (
    ALL_RULES,
    ComplianceReport,
    ComplianceRule,
    ComplianceStatus,
    ComplianceViolation,
    FleetComplianceEngine,
)

_LEGACY_PATH = Path(__file__).resolve().parents[1] / "compliance.py"
_LEGACY_SPEC = importlib.util.spec_from_file_location("orchesis._legacy_compliance_module", _LEGACY_PATH)
if _LEGACY_SPEC is not None and _LEGACY_SPEC.loader is not None:
    _legacy_module = importlib.util.module_from_spec(_LEGACY_SPEC)
    sys.modules[_LEGACY_SPEC.name] = _legacy_module
    _LEGACY_SPEC.loader.exec_module(_legacy_module)
    for _name in dir(_legacy_module):
        if _name.startswith("_"):
            continue
        if _name in globals():
            continue
        globals()[_name] = getattr(_legacy_module, _name)

