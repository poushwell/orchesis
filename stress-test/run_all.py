#!/usr/bin/env python3
"""
Orchesis Stress Test Suite - run scenarios and generate report.

Usage:
    python stress-test/run_all.py
    python stress-test/run_all.py --quick
    python stress-test/run_all.py --scenario s01
"""

from __future__ import annotations

import argparse
import importlib
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from lib.report_generator import ReportGenerator

SCENARIO_MODULES = {
    "s01": "scenarios.s01_concurrent_agents",
    "s02": "scenarios.s02_sustained_throughput",
    "s03": "scenarios.s03_memory_stability",
    "s04": "scenarios.s04_adversarial_under_load",
    "s05": "scenarios.s05_cascade_failure",
    "s06": "scenarios.s06_heartbeat_storm",
    "s07": "scenarios.s07_budget_race",
    "s08": "scenarios.s08_policy_hotreload",
}


def _git_hash(repo_root: Path) -> str:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(repo_root),
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        return out.strip() or "unknown"
    except Exception:
        return "unknown"


def _run_one(scenario_id: str, quick: bool) -> dict[str, Any]:
    mod_name = SCENARIO_MODULES[scenario_id]
    mod = importlib.import_module(mod_name)
    if not hasattr(mod, "run"):
        raise RuntimeError(f"Scenario {scenario_id} missing run()")
    return mod.run(quick=quick)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Orchesis stress test suite.")
    parser.add_argument("--scenario", choices=sorted(SCENARIO_MODULES.keys()), help="Run single scenario")
    parser.add_argument("--quick", action="store_true", help="Quick mode (durations /10)")
    args = parser.parse_args()

    stress_root = Path(__file__).resolve().parent
    repo_root = stress_root.parent
    picked = [args.scenario] if args.scenario else list(SCENARIO_MODULES.keys())

    print("Orchesis Stress Test Suite")
    print(f"Mode: {'quick' if args.quick else 'full'}")
    print(f"Scenarios: {', '.join(picked)}")
    print("")

    scenario_results: list[dict[str, Any]] = []
    for scenario_id in picked:
        print(f"[RUN] {scenario_id}")
        try:
            result = _run_one(scenario_id, quick=args.quick)
        except Exception as exc:
            result = {
                "id": scenario_id,
                "name": scenario_id,
                "passed": False,
                "key_metric": f"exception: {exc}",
                "details": {"exception": repr(exc)},
            }
        scenario_results.append(result)
        status = "PASS" if result.get("passed") else "FAIL"
        print(f"[{status}] {result.get('key_metric', '-')}")
        print("")

    results = {
        "meta": {
            "date": datetime.now(timezone.utc).date().isoformat(),
            "version": _git_hash(repo_root),
            "platform": f"{platform.platform()} | Python {platform.python_version()}",
            "quick_mode": bool(args.quick),
        },
        "scenarios": scenario_results,
    }
    generator = ReportGenerator(results)
    report_md = stress_root / "results" / "report.md"
    md_path, json_path = generator.save(str(report_md))
    passed = sum(1 for x in scenario_results if x.get("passed"))
    total = len(scenario_results)
    print(f"Completed: {passed}/{total} scenarios passed")
    print(f"Markdown report: {md_path}")
    print(f"JSON report: {json_path}")


if __name__ == "__main__":
    main()
