"""End-to-end integration smoke tests for the public Orchesis surface area."""

from __future__ import annotations

import importlib
import json
import pkgutil
from datetime import date
from pathlib import Path

import pytest

from orchesis import Decision, McpConfigScanner, PolicyEngine
from orchesis.config import load_policy, validate_policy
from orchesis.core.evidence_ledger import EvidenceLedger
from orchesis.cost_tracker import CostTracker
from orchesis.openclaw_presets import get_named_preset
from orchesis.plugins import PluginInfo, PluginRegistry
from orchesis.scanner import (
    McpConfigScanner as McpScannerClass,
    grade_from_findings,
    report_to_html,
    report_to_json,
)
from orchesis.state import RateLimitTracker
from orchesis.verify import OrchesisVerifier

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_smoke_import_all_public() -> None:
    """Import every public symbol from orchesis package."""
    from orchesis import __version__, PolicyEngine, Decision, OrchesisClient
    from orchesis import SkillScanner, McpConfigScanner, PolicyScanner

    assert __version__ == "0.5.0"
    assert PolicyEngine is not None
    assert Decision is not None
    assert OrchesisClient is not None
    assert SkillScanner is not None
    assert McpConfigScanner is not None
    assert PolicyScanner is not None


def test_smoke_load_minimal_policy(tmp_path: Path) -> None:
    """Load a minimal valid policy, verify it normalizes."""
    p = tmp_path / "minimal.yaml"
    p.write_text('version: "1.0"\nrules: []\n', encoding="utf-8")
    policy = load_policy(p)
    assert isinstance(policy, dict)
    assert isinstance(policy.get("rules"), list)
    assert validate_policy(policy) == []


def test_smoke_load_complex_policy() -> None:
    """Load a policy with all sections populated."""
    example = REPO_ROOT / "examples" / "policy.yaml"
    if not example.is_file():
        pytest.skip("examples/policy.yaml not present")
    policy = load_policy(example)
    assert isinstance(policy, dict)
    assert "rules" in policy
    assert "agents" in policy
    errs = validate_policy(policy)
    assert errs == [], f"validation errors: {errs}"


def _five_server_mcp_json() -> str:
    return json.dumps(
        {
            "mcpServers": {
                "fs": {
                    "command": "npx",
                    "args": [
                        "-y",
                        "@modelcontextprotocol/server-filesystem@1.0.0",
                        "/tmp",
                    ],
                },
                "git": {"command": "uvx", "args": ["mcp-server-git==1.0.0"]},
                "search": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-brave-search@0.1.0"],
                },
                "remote": {"url": "https://mcp.example.com/v1"},
                "local": {"command": "python", "args": ["-m", "mcp_test_server"]},
            }
        },
        indent=2,
    )


def test_smoke_scanner_real_config(tmp_path: Path) -> None:
    """Scan a realistic MCP config with 5 servers."""
    cfg = tmp_path / "mcp.json"
    cfg.write_text(_five_server_mcp_json(), encoding="utf-8")
    scanner = McpConfigScanner()
    report = scanner.scan(str(cfg))
    assert isinstance(report.findings, list)
    assert report.target_type == "mcp_config"
    assert getattr(report, "rules_checked", 0) == len(McpScannerClass.RULE_REGISTRY)
    assert isinstance(getattr(report, "unique_findings", 0), int)
    assert isinstance(getattr(report, "dedup_count", 0), int)
    d = report.__dict__
    assert "findings" in d and "risk_score" in d


def test_smoke_scanner_json_export(tmp_path: Path) -> None:
    """Scan → JSON export → parse JSON → verify structure."""
    cfg = tmp_path / "mcp.json"
    cfg.write_text(_five_server_mcp_json(), encoding="utf-8")
    report = McpConfigScanner().scan(str(cfg))
    raw = report_to_json(report)
    data = json.loads(raw)
    assert "findings" in data
    assert "grade" in data
    assert "letter" in data["grade"] and "score" in data["grade"]
    assert "export_metadata" in data


def test_smoke_scanner_html_export(tmp_path: Path) -> None:
    """Scan → HTML export → verify self-contained HTML."""
    cfg = tmp_path / "mcp.json"
    cfg.write_text(_five_server_mcp_json(), encoding="utf-8")
    report = McpConfigScanner().scan(str(cfg))
    html = report_to_html(report)
    lower = html.lower()
    assert "<!doctype html>" in lower or "<html" in lower
    assert "scan report" in lower
    assert (
        "http://fonts.googleapis.com" not in lower and "https://fonts.googleapis.com" not in lower
    )


def test_smoke_scanner_grade(tmp_path: Path) -> None:
    """Scan → grade → verify letter-grade scale."""
    cfg = tmp_path / "mcp.json"
    cfg.write_text(_five_server_mcp_json(), encoding="utf-8")
    report = McpConfigScanner().scan(str(cfg))
    letter, score = grade_from_findings(report.findings)
    assert letter in {"A+", "A", "B", "C", "D", "F"}
    assert 0 <= score <= 100


def test_smoke_engine_evaluate() -> None:
    """PolicyEngine.evaluate on a sample request."""
    engine = PolicyEngine(policy={"rules": []})
    decision = engine.evaluate({"tool": "read_file"})
    assert isinstance(decision, Decision)
    assert decision.allowed is True
    assert isinstance(decision.reasons, list)


def test_smoke_cost_tracker_lifecycle() -> None:
    """Create → record 10 calls → check budget → get daily → reset."""
    ct = CostTracker()
    for i in range(10):
        ct.record_call("read_file", cost_override=0.01)
    today_key = date.today().isoformat()
    assert ct.get_daily_total(today_key) >= 0.09
    status = ct.check_budget({"daily": 1.0, "soft_limit_percent": 80})
    assert "daily_spent" in status and "over_budget" in status
    ct.reset_daily()
    assert ct.get_daily_total(today_key) == 0.0


def test_smoke_verify_basic(tmp_path: Path) -> None:
    """OrchesisVerifier.run() returns valid report structure."""
    pol = tmp_path / "policy.yaml"
    pol.write_text('version: "1.0"\nrules: []\n', encoding="utf-8")
    out = OrchesisVerifier().run(policy_path=str(pol))
    assert set(out.keys()) >= {"passed", "failed", "warnings", "total", "checks", "ready"}
    assert isinstance(out["checks"], dict)
    for cid, row in out["checks"].items():
        assert "status" in row, cid


def test_smoke_cli_help() -> None:
    """orchesis --help exits 0."""
    from orchesis.cli import main

    from tests.cli_test_utils import CliRunner

    runner = CliRunner()
    r = runner.invoke(main, ["--help"])
    assert r.exit_code == 0
    assert "Orchesis" in (r.stdout or r.output or "")


def test_smoke_cli_version() -> None:
    """orchesis --version shows correct version."""
    from orchesis.cli import main

    from tests.cli_test_utils import CliRunner

    runner = CliRunner()
    r = runner.invoke(main, ["--version"])
    assert r.exit_code == 0
    combined = f"{r.stdout or ''}{r.stderr or ''}{r.output or ''}"
    assert "0.5.0" in combined


def test_smoke_cli_verify_help() -> None:
    """orchesis verify --help exits 0."""
    from orchesis.cli import main

    from tests.cli_test_utils import CliRunner

    runner = CliRunner()
    r = runner.invoke(main, ["verify", "--help"])
    assert r.exit_code == 0


def test_smoke_cli_scan_help() -> None:
    """orchesis scan --help exits 0."""
    from orchesis.cli import main

    from tests.cli_test_utils import CliRunner

    runner = CliRunner()
    r = runner.invoke(main, ["scan", "--help"])
    assert r.exit_code == 0


def test_smoke_preset_openclaw() -> None:
    """Load OpenClaw preset, verify structure."""
    preset = get_named_preset("openclaw")
    assert isinstance(preset, dict)
    assert "capabilities" in preset
    assert preset.get("default_action") == "allow"


def test_smoke_preset_paperclip() -> None:
    """Load Paperclip preset, verify structure."""
    preset = get_named_preset("paperclip")
    assert isinstance(preset, dict)
    assert "paperclip" in preset
    assert "loop_detection" in preset


def test_smoke_plugin_registry() -> None:
    """Create plugin, register, fire hook, unregister."""

    class _SmokeHandler:
        def evaluate(self, rule, request, *, state, agent_id, session_id):
            return (["smoke"], ["smoke_rule"])

    reg = PluginRegistry()
    reg.register(
        PluginInfo(
            name="smoke",
            rule_type="smoke_e2e_custom",
            version="1",
            description="smoke",
            handler=_SmokeHandler(),
        )
    )
    handler = reg.get_handler("smoke_e2e_custom")
    assert handler is not None
    reasons, checked = handler.evaluate(
        {}, {}, state=RateLimitTracker(persist_path=None), agent_id="a", session_id="s"
    )
    assert reasons == ["smoke"] and checked == ["smoke_rule"]
    reg.unregister("smoke_e2e_custom")
    assert reg.get_handler("smoke_e2e_custom") is None


def test_smoke_evidence_ledger(tmp_path: Path) -> None:
    """Create ledger → record 5 events → flush → verify chain."""
    path = tmp_path / "ledger.jsonl"
    ledger = EvidenceLedger(path, flush_interval=0.0, max_buffer_size=1000)
    try:
        for i in range(5):
            ledger.record({"event": "smoke", "i": i})
        ledger.flush()
        assert ledger.verify_chain() is True
    finally:
        ledger.close()


def test_smoke_all_modules_import() -> None:
    """Walk orchesis package, import every module (skip optional third-party deps)."""
    import orchesis

    errors: list[str] = []

    def _optional_third_party_missing(exc: BaseException) -> bool:
        if isinstance(exc, ModuleNotFoundError):
            name = (exc.name or "").strip()
            if name == "orchesis" or name.startswith("orchesis."):
                return False
            return bool(name)
        return False

    for info in pkgutil.walk_packages(orchesis.__path__, orchesis.__name__ + "."):
        try:
            importlib.import_module(info.name)
        except Exception as e:  # noqa: BLE001
            if _optional_third_party_missing(e):
                continue
            errors.append(f"{info.name}: {e}")
    assert not errors, f"Import errors: {errors}"
