from __future__ import annotations

from pathlib import Path

from tests.cli_test_utils import CliRunner

from orchesis.cli import main
from orchesis.nlce_paper import NLCEPaper


def test_abstract_generated() -> None:
    text = NLCEPaper().generate_abstract()
    assert "Network-Level Context Engineering" in text
    assert "Zipf" in text


def test_results_table_has_all_experiments() -> None:
    paper = NLCEPaper()
    table = paper.generate_results_table()
    assert "exp 8" in table
    assert "exp 13" in table
    assert "exp 12" in table


def test_novelty_claims_listed() -> None:
    paper = NLCEPaper()
    section = paper.generate_novelty_section()
    for claim in paper.NOVELTY_CLAIMS:
        assert claim in section


def test_full_paper_structure_complete() -> None:
    payload = NLCEPaper().generate_full_paper()
    for key in (
        "title",
        "abstract",
        "introduction",
        "background",
        "methodology",
        "results",
        "discussion",
        "conclusion",
        "references",
    ):
        assert key in payload


def test_latex_export_creates_files(tmp_path: Path) -> None:
    files = NLCEPaper().export_latex(str(tmp_path / "paper"))
    names = {Path(path).name for path in files}
    assert "main.tex" in names
    assert "references.bib" in names
    for path in files:
        assert Path(path).exists()


def test_markdown_export_creates_files(tmp_path: Path) -> None:
    files = NLCEPaper().export_markdown(str(tmp_path / "paper"))
    names = {Path(path).name for path in files}
    assert "abstract.md" in names
    assert "results.md" in names
    assert "paper.json" in names
    for path in files:
        assert Path(path).exists()


def test_submission_checklist_items() -> None:
    rows = NLCEPaper().get_submission_checklist()
    assert isinstance(rows, list)
    assert len(rows) >= 5
    assert all("item" in row and "done" in row for row in rows)


def test_cli_generate_command(tmp_path: Path) -> None:
    runner = CliRunner()
    out_dir = tmp_path / "paper"
    result = runner.invoke(main, ["nlce-paper", "--generate", "--output", str(out_dir)])
    assert result.exit_code == 0
    assert "abstract.md" in result.output
