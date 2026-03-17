from __future__ import annotations

import json
from pathlib import Path

from tests.cli_test_utils import CliRunner

from orchesis.cli import main
from orchesis.experiment_runner import NLCEExperimentRunner


def test_zipf_experiment_runs(tmp_path: Path) -> None:
    runner = NLCEExperimentRunner({"results_dir": str(tmp_path / "results")})
    data = [{"token_count": 100}, {"token_count": 50}, {"token_count": 33}, {"token_count": 25}]
    result = runner.run("exp8", data)
    assert result["status"] == "completed"
    assert result["experiment_id"] == "exp8"
    assert "zipf_score" in result["results"]


def test_collapse_experiment_detects_growth(tmp_path: Path) -> None:
    runner = NLCEExperimentRunner({"results_dir": str(tmp_path / "results")})
    data = [{"token_count": 100}, {"token_count": 130}, {"token_count": 260}]
    result = runner.run("exp4", data)
    assert result["status"] == "completed"
    assert result["results"]["collapse_detected"] is True
    assert result["key_metric"] >= 2.0


def test_baseline_experiment_computes_dna(tmp_path: Path) -> None:
    runner = NLCEExperimentRunner({"results_dir": str(tmp_path / "results")})
    data = [
        {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "hello"}],
            "tools": ["web_search"],
            "topic": "research",
            "duration_ms": 120.0,
            "cache_hit": True,
            "decision": "ALLOW",
        },
        {
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "investigate"}],
            "tools": [],
            "topic": "ops",
            "duration_ms": 180.0,
            "cache_hit": False,
            "decision": "DENY",
        },
    ]
    result = runner.run("exp1", data)
    assert result["status"] == "completed"
    baseline = result["results"]["baseline"]
    assert "avg_prompt_length" in baseline
    assert "cache_hit_rate" in baseline


def test_results_saved_to_disk(tmp_path: Path) -> None:
    runner = NLCEExperimentRunner({"results_dir": str(tmp_path / "results")})
    result = runner.run("exp8", [{"token_count": 10}, {"token_count": 5}])
    path = runner.save(result)
    assert Path(path).exists()
    loaded = json.loads(Path(path).read_text(encoding="utf-8"))
    assert loaded["experiment_id"] == "exp8"


def test_list_results_returns_all(tmp_path: Path) -> None:
    runner = NLCEExperimentRunner({"results_dir": str(tmp_path / "results")})
    runner.save(runner.run("exp8", [{"token_count": 10}, {"token_count": 5}]))
    runner.save(runner.run("exp4", [{"token_count": 10}, {"token_count": 30}]))
    items = runner.list_results()
    ids = {item.get("experiment_id") for item in items}
    assert "exp8" in ids
    assert "exp4" in ids


def test_cli_experiment_command(tmp_path: Path) -> None:
    data_path = tmp_path / "decisions.jsonl"
    data_path.write_text(
        "\n".join(
            [
                json.dumps({"token_count": 100}),
                json.dumps({"token_count": 50}),
                json.dumps({"token_count": 33}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    runner = CliRunner()
    with runner.isolated_filesystem():
        result_list = runner.invoke(main, ["experiment", "--list"])
        assert result_list.exit_code == 0
        assert "exp8" in result_list.output
        result_run = runner.invoke(
            main,
            [
                "experiment",
                "--id",
                "exp8",
                "--data",
                str(data_path),
                "--results-dir",
                str(tmp_path / "results"),
            ],
        )
        assert result_run.exit_code == 0
        assert '"experiment_id": "exp8"' in result_run.output
        result_results = runner.invoke(
            main,
            ["experiment", "--results", "--results-dir", str(tmp_path / "results")],
        )
        assert result_results.exit_code == 0
        assert '"exp8"' in result_results.output

