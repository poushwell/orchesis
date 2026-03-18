from __future__ import annotations

import json
from pathlib import Path

from orchesis.benchmark import BenchmarkSuite
from orchesis.cli import main
from tests.cli_test_utils import CliRunner


def test_list_cases_command() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["benchmark", "--list-cases"])
    assert result.exit_code == 0
    assert "Available benchmark cases:" in result.output
    assert "Description" in result.output
    assert "SEC-001" in result.output


def test_run_single_case() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["benchmark", "--case", "SEC-001"])
    assert result.exit_code == 0
    assert "Running benchmark suite [1 cases]" in result.output
    assert "(1/1)" in result.output
    assert "Overall:" in result.output


def test_compare_two_results(tmp_path: Path) -> None:
    runner = CliRunner()
    suite = BenchmarkSuite()
    report_a = suite.run()
    report_b = suite.run()
    payload_a = json.loads(json.dumps(report_a, default=lambda o: o.__dict__))
    payload_b = json.loads(json.dumps(report_b, default=lambda o: o.__dict__))
    # Force one improvement and one regression for deterministic output.
    payload_a["results"][0]["passed"] = False
    payload_b["results"][0]["passed"] = True
    payload_a["results"][1]["passed"] = True
    payload_b["results"][1]["passed"] = False
    file_a = tmp_path / "r1.json"
    file_b = tmp_path / "r2.json"
    file_a.write_text(json.dumps(payload_a, ensure_ascii=False, indent=2), encoding="utf-8")
    file_b.write_text(json.dumps(payload_b, ensure_ascii=False, indent=2), encoding="utf-8")

    result = runner.invoke(main, ["benchmark", "--compare", str(file_a), str(file_b)])
    assert result.exit_code == 0
    assert "Comparing results:" in result.output
    assert "✓ Better:" in result.output
    assert "✗ Worse:" in result.output
    assert "= Same:" in result.output


def test_export_results_json(tmp_path: Path) -> None:
    runner = CliRunner()
    export_path = tmp_path / "benchmark_results.json"
    result = runner.invoke(main, ["benchmark", "--case", "SEC-001", "--export", str(export_path)])
    assert result.exit_code == 0
    assert export_path.exists()
    payload = json.loads(export_path.read_text(encoding="utf-8"))
    assert "suite_name" in payload
    assert "results" in payload
    assert len(payload["results"]) == 1


def test_progress_display() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["benchmark", "--run-all"])
    assert result.exit_code == 0
    assert "Running benchmark suite [43 cases]" in result.output
    assert "█" in result.output
    assert "(43/43)" in result.output
