from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path


def _node_exe() -> str | None:
    return shutil.which("node")


def _run_cli(args: list[str], mock_payload: list[dict] | dict) -> subprocess.CompletedProcess[str]:
    node = _node_exe()
    if node is None:
        raise RuntimeError("node not found")
    script = Path("integrations/npm-cli/index.js").resolve()
    env = dict(**__import__("os").environ)
    env["ORCHESIS_SCAN_MOCK_JSON"] = json.dumps(mock_payload, ensure_ascii=False)
    return subprocess.run(
        [node, str(script), *args],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(Path.cwd()),
    )


def _sample_findings() -> dict:
    return {
        "target": "mock-target",
        "risk_score": 42,
        "findings": [
            {"severity": "low", "description": "Low issue", "location": "a"},
            {"severity": "medium", "description": "Medium issue", "location": "b"},
            {"severity": "high", "description": "High issue", "location": "c", "remediation": "Pin package version to X.X.X"},
            {"severity": "critical", "description": "Critical issue", "location": "d"},
        ],
    }


def test_severity_filter_excludes_low() -> None:
    if _node_exe() is None:
        return
    result = _run_cli(["--severity", "high", "--format", "json", "--fail-on", "critical"], _sample_findings())
    assert result.returncode in {0, 1}
    payload = json.loads(result.stdout)
    severities = {item["severity"] for item in payload.get("findings", [])}
    assert "low" not in severities
    assert "medium" not in severities
    assert "high" in severities


def test_fix_flag_shows_remediation() -> None:
    if _node_exe() is None:
        return
    result = _run_cli(["--severity", "high", "--fix", "--fail-on", "critical"], _sample_findings())
    assert "Remediation:" in result.stdout
    assert "Pin package version to X.X.X" in result.stdout


def test_output_flag_saves_json(tmp_path: Path) -> None:
    if _node_exe() is None:
        return
    out = tmp_path / "report.json"
    result = _run_cli(["--output", str(out), "--severity", "medium", "--fail-on", "critical"], _sample_findings())
    assert result.returncode in {0, 1}
    assert out.exists()
    saved = json.loads(out.read_text(encoding="utf-8"))
    assert "results" in saved
    assert isinstance(saved["results"], list)


def test_summary_line_format() -> None:
    if _node_exe() is None:
        return
    result = _run_cli(["--severity", "low", "--fail-on", "critical"], _sample_findings())
    assert "Summary:" in result.stdout
    assert "critical" in result.stdout and "high" in result.stdout and "medium" in result.stdout and "low" in result.stdout


def test_color_coding_by_severity() -> None:
    if _node_exe() is None:
        return
    result = _run_cli(["--severity", "low", "--fail-on", "critical"], _sample_findings())
    # critical should include bold + red ANSI
    assert "\x1b[1m\x1b[31mCRITICAL" in result.stdout
    # medium should include yellow
    assert "\x1b[33mMEDIUM" in result.stdout
