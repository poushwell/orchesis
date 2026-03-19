from __future__ import annotations

import json
from pathlib import Path

from tests.cli_test_utils import CliRunner

from orchesis.cli import main
from orchesis.nlce_exporter import NLCEPaperExporter


def test_claims_table_generated() -> None:
    exporter = NLCEPaperExporter()
    table = exporter.export_claims_table()
    assert "| claim | key metrics | experiment |" in table
    assert "zipf_law" in table
    assert "rg_universality" in table


def test_experiment_results_aggregated(tmp_path: Path) -> None:
    results_dir = tmp_path / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / "exp8_a.json").write_text(
        json.dumps(
            {
                "experiment_id": "exp8",
                "status": "completed",
                "key_metric": 0.82,
                "timestamp": "2026-01-01T00:00:00Z",
                "interpretation": "ok",
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    (results_dir / "exp8_b.json").write_text(
        json.dumps(
            {
                "experiment_id": "exp8",
                "status": "completed",
                "key_metric": 0.92,
                "timestamp": "2026-01-02T00:00:00Z",
                "interpretation": "better",
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    data = NLCEPaperExporter().export_experiment_results(str(results_dir))
    assert data["total_files"] == 2
    assert "exp8" in data["experiments"]
    assert data["experiments"]["exp8"]["runs"] == 2
    assert data["experiments"]["exp8"]["avg_key_metric"] == 0.87


def test_abstract_generated() -> None:
    text = NLCEPaperExporter().generate_abstract()
    assert "Zipf-like token behavior" in text
    assert "n*=16" in text


def test_export_all_creates_files(tmp_path: Path) -> None:
    output_dir = tmp_path / "paper"
    files = NLCEPaperExporter().export_all(str(output_dir))
    names = {Path(path).name for path in files}
    assert "claims_table.md" in names
    assert "methodology.md" in names
    assert "abstract.md" in names
    assert "experiment_results.json" in names
    for path in files:
        assert Path(path).exists()


def test_cli_nlce_export_command(tmp_path: Path) -> None:
    runner = CliRunner()
    out_dir = tmp_path / "paper"
    result_all = runner.invoke(main, ["nlce-export", "--output", str(out_dir)])
    assert result_all.exit_code == 0
    assert "claims_table.md" in result_all.output
    result_section = runner.invoke(
        main,
        ["nlce-export", "--output", str(out_dir), "--section", "abstract"],
    )
    assert result_section.exit_code == 0
    assert "abstract.md" in result_section.output
