from __future__ import annotations

import json
from pathlib import Path

from tests.cli_test_utils import CliRunner

from orchesis.arxiv_validator import ArxivSubmissionValidator
from orchesis.cli import main
from orchesis.nlce_paper import NLCEPaper


def _paper() -> dict:
    return NLCEPaper().generate_full_paper()


def test_valid_paper_passes() -> None:
    validator = ArxivSubmissionValidator()
    result = validator.validate(_paper())
    assert result["valid"] is True
    assert result["checklist"]["abstract_present"] is True


def test_missing_abstract_fails() -> None:
    validator = ArxivSubmissionValidator()
    paper = _paper()
    paper["abstract"] = ""
    result = validator.validate(paper)
    assert result["valid"] is False
    assert result["checklist"]["abstract_present"] is False


def test_categories_suggested() -> None:
    validator = ArxivSubmissionValidator()
    cats = validator.suggest_categories(_paper())
    assert "cs.AI" in cats


def test_references_formatted() -> None:
    validator = ArxivSubmissionValidator()
    formatted = validator.format_references(["Ref A", "Ref B"])
    assert "[1] Ref A" in formatted
    assert "[2] Ref B" in formatted


def test_submission_package_generated(tmp_path: Path) -> None:
    validator = ArxivSubmissionValidator()
    pkg = validator.generate_submission_package(_paper(), str(tmp_path / "submission"))
    assert pkg["main_file"].endswith("main.tex")
    assert isinstance(pkg["files"], list)
    for path in pkg["files"]:
        assert Path(path).exists()


def test_checklist_all_items() -> None:
    validator = ArxivSubmissionValidator()
    result = validator.validate(_paper())
    for item in validator.CHECKLIST:
        assert item in result["checklist"]


def test_cli_validate_command(tmp_path: Path) -> None:
    runner = CliRunner()
    paper_dir = tmp_path / "paper"
    NLCEPaper().export_markdown(str(paper_dir))
    result = runner.invoke(main, ["arxiv-validate", "--paper", str(paper_dir)])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert "valid" in payload


def test_cli_package_command(tmp_path: Path) -> None:
    runner = CliRunner()
    paper_dir = tmp_path / "paper"
    out_dir = tmp_path / "submission"
    NLCEPaper().export_markdown(str(paper_dir))
    result = runner.invoke(main, ["arxiv-package", "--paper", str(paper_dir), "--output", str(out_dir)])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["main_file"].endswith("main.tex")
