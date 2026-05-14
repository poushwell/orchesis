"""Shared configuration and utilities for Red Team attacks."""

from __future__ import annotations

import json
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

# Add project root to path so we can import orchesis
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

RED_TEAM_ROOT = PROJECT_ROOT / "red-team"
ATTACKS_ROOT = RED_TEAM_ROOT / "attacks"
RESULTS_ROOT = RED_TEAM_ROOT / "results"
POLICIES_ROOT = RED_TEAM_ROOT / "policies"


class AttackResult(Enum):
    PASS = "PASS"  # Orchesis correctly blocked the attack
    FAIL = "FAIL"  # Attack bypassed Orchesis
    PARTIAL = "PARTIAL"  # Partially blocked (some vectors worked)
    ERROR = "ERROR"  # Test itself errored


@dataclass
class AttackReport:
    name: str
    category: str
    description: str
    result: AttackResult
    details: str = ""
    vectors_tested: int = 0
    vectors_blocked: int = 0
    vectors_bypassed: int = 0
    duration_ms: float = 0.0
    severity: str = "MEDIUM"  # CRITICAL/HIGH/MEDIUM/LOW if bypass found
    fix_suggestion: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["result"] = self.result.value
        return payload


def run_attack(func):
    """Decorator that wraps an attack function with timing and error handling."""

    def wrapper(*args, **kwargs):
        started = time.monotonic()
        try:
            report = func(*args, **kwargs)
            report.duration_ms = (time.monotonic() - started) * 1000.0
            return report
        except Exception as error:  # noqa: BLE001
            return AttackReport(
                name=func.__name__,
                category="unknown",
                description=f"Attack errored: {error}",
                result=AttackResult.ERROR,
                details=str(error),
                duration_ms=(time.monotonic() - started) * 1000.0,
                severity="HIGH",
                fix_suggestion="Investigate unhandled exception path in attack harness or target API.",
            )

    wrapper._is_attack = True
    wrapper.__name__ = func.__name__
    return wrapper


def load_yaml_policy(path: Path) -> dict[str, Any]:
    from orchesis.config import load_policy

    return load_policy(path)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
