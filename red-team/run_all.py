"""Discover and execute all red-team attacks."""

from __future__ import annotations

import importlib.util
import inspect
import sys
from pathlib import Path

from config import ATTACKS_ROOT, AttackReport, AttackResult
from report_generator import generate_reports


def _load_module(path: Path):
    name = f"red_team_{path.stem}_{abs(hash(str(path)))}"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Failed to create spec for {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def discover_attack_functions() -> list[tuple[str, callable]]:
    discovered: list[tuple[str, callable]] = []
    for file_path in sorted(ATTACKS_ROOT.rglob("test_*.py")):
        module = _load_module(file_path)
        for name, obj in inspect.getmembers(module, inspect.isfunction):
            if getattr(obj, "_is_attack", False):
                discovered.append((f"{file_path.relative_to(ATTACKS_ROOT)}::{name}", obj))
    return discovered


def main() -> int:
    print("=== Orchesis Red Team ===")
    attacks = discover_attack_functions()
    print(f"Discovered attacks: {len(attacks)}")
    reports: list[AttackReport] = []
    for label, func in attacks:
        print(f"[RUN] {label}")
        report = func()
        if not isinstance(report, AttackReport):
            report = AttackReport(
                name=func.__name__,
                category="unknown",
                description="Attack did not return AttackReport",
                result=AttackResult.ERROR,
                details=f"Unexpected return type: {type(report)}",
                severity="HIGH",
            )
        reports.append(report)
        print(f"      -> {report.result.value} ({report.duration_ms:.1f}ms)")

    md_path, json_path = generate_reports(reports)
    fail_count = sum(1 for item in reports if item.result == AttackResult.FAIL)
    print("")
    print(f"Report (md): {md_path}")
    print(f"Report (json): {json_path}")
    print(f"FAIL findings: {fail_count}")
    return 1 if fail_count > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
