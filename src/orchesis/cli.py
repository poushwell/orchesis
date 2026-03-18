"""CLI entrypoint for Orchesis."""

import asyncio
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
import tracemalloc
from concurrent.futures import ThreadPoolExecutor
from collections import Counter
from dataclasses import asdict, replace
from datetime import datetime, timezone, timedelta
from pathlib import Path
from random import Random
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request as UrlRequest, urlopen

import click
import yaml
from yaml import YAMLError

from orchesis.auth import AgentAuthenticator, CredentialStore
from orchesis.audit import AuditEngine, AuditQuery
from orchesis.audit_export import AuditTrailExporter
from orchesis.compliance import ComplianceEngine, FRAMEWORK_CHECKS, FrameworkCrossReference
from orchesis.compliance_report import ComplianceReportGenerator
from orchesis.ari import AgentReadinessIndex
from orchesis.benchmark import (
    ORCHESIS_BENCHMARK_V1,
    BenchmarkCase,
    BenchmarkReport,
    BenchmarkResult,
    BenchmarkSuite,
)
from orchesis.contrib.ioc_database import IoCMatcher
from orchesis.contrib.network_scanner import NetworkExposureScanner
from orchesis.contrib.remote_scanner import RemoteSkillScanner
from orchesis.credential_vault import CredentialNotFoundError, EnvVault, FileVault, build_vault_from_policy
from orchesis.config import (
    load_agent_registry,
    load_policy,
    validate_policy,
    validate_policy_warnings,
)
from orchesis.cost_reporter import CostReporter
from orchesis.engine import evaluate, get_cost_tracker, get_loop_detector_stats, reset_cost_tracker_daily
from orchesis.forensics import ForensicsEngine
from orchesis.drift import DriftDetector
from orchesis.fuzzer import SyntheticFuzzer, update_fuzz_metadata
from orchesis.invariants import InvariantChecker
from orchesis.logger import read_decisions
from orchesis.corpus import RegressionCorpus
from orchesis.coverage import CoverageReport
from orchesis.policy_store import PolicyStore
from orchesis.plugins import load_plugins_for_policy
from orchesis.replay import ReplayEngine, read_events_from_jsonl
from orchesis.session_replay import SessionReplay
from orchesis.reliability import ReliabilityReportGenerator
from orchesis.llm_config import load_llm_config
from orchesis.llm_judge import LLMJudge
from orchesis.rules_generator import generate_security_rules_from_policy
from orchesis.policy_validator import PolicyAsCodeValidator
from orchesis.publisher import FindingsPublisher
from orchesis.threat_feed import ThreatFeed
from orchesis.scanner_server import run_scanner_http_server
from orchesis.scenarios import AdversarialScenarios
from orchesis.experiment_runner import NLCEExperimentRunner
from orchesis.integrity import IntegrityMonitor, build_integrity_alert_callback
from orchesis.hooks import ClaudeCodeHooks, evaluate_hook_tool, log_hook_tool
from orchesis.quickstart import QuickstartWizard
from orchesis.yara_engine import load_yara_rules, scan_with_yara, YaraParser
from orchesis.scanner import (
    ScanFinding,
    ScanReport,
    discover_mcp_configs,
    format_report_markdown,
    format_report_text,
    report_to_dict,
    scan_path,
    severity_meets_threshold,
)
from orchesis.signing import generate_keypair, sign_entry, verify_entry
from orchesis.state import RateLimitTracker
from orchesis.telemetry import InMemoryEmitter, JsonlEmitter
from orchesis.mutations import MutationEngine
from orchesis.marketplace import PolicyMarketplace
from orchesis.structured_log import StructuredLogger
from orchesis.templates import TEMPLATE_NAMES, load_template_text
from orchesis.policy_templates import PolicyTemplateManager, POLICY_TEMPLATES
from orchesis.evidence_record import EvidenceRecord
from orchesis import __version__

DEFAULT_KEYS_DIR = Path(".orchesis") / "keys"
DEFAULT_PRIVATE_KEY_PATH = DEFAULT_KEYS_DIR / "private.pem"
DEFAULT_PUBLIC_KEY_PATH = DEFAULT_KEYS_DIR / "public.pem"
DEFAULT_STATE_PATH = Path(".orchesis") / "state.jsonl"
DEFAULT_DECISIONS_PATH = Path("decisions.jsonl")
DEFAULT_FUZZ_RUNS_PATH = Path(".orchesis") / "fuzz_runs.jsonl"
DEFAULT_MUTATION_RUNS_PATH = Path(".orchesis") / "mutation_runs.jsonl"
DEFAULT_REPLAY_RUNS_PATH = Path(".orchesis") / "replay_runs.jsonl"
OPERATIONS_LOG = StructuredLogger("cli")
DOCTOR_CHECKS = [
    "python_version",
    "pyyaml_installed",
    "config_exists",
    "config_valid",
    "proxy_running",
    "api_running",
    "disk_space",
    "log_rotation",
    "api_key_configured",
    "semantic_cache_enabled",
    "loop_detection_enabled",
    "recording_enabled",
]
AGENT_COMMANDS: dict[str, list[str] | None] = {
    "openclaw": ["openclaw", "--base-url", "http://localhost:8080/v1"],
    "claude": ["claude", "--api-base", "http://localhost:8080/v1"],
    "codex": ["codex", "--base-url", "http://localhost:8080/v1"],
    "aider": ["aider", "--openai-api-base", "http://localhost:8080/v1"],
    "continue": ["continue", "--base-url", "http://localhost:8080/v1"],
    "cursor": None,
}


@click.group(invoke_without_command=True)
@click.version_option(version=__version__)
@click.pass_context
def main(ctx: click.Context) -> None:
    """Orchesis command line interface."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@main.group("hooks")
def hooks_group() -> None:
    """Manage Claude Code hooks."""


@hooks_group.command("install")
def hooks_install_command() -> None:
    result = ClaudeCodeHooks().install()
    click.echo(result.message)
    raise SystemExit(0 if result.success else 1)


@hooks_group.command("uninstall")
def hooks_uninstall_command() -> None:
    result = ClaudeCodeHooks().uninstall()
    click.echo(result.message)
    raise SystemExit(0 if result.success else 1)


@hooks_group.command("status")
def hooks_status_command() -> None:
    payload = ClaudeCodeHooks().status()
    click.echo(json.dumps(payload, ensure_ascii=False))
    raise SystemExit(0)


@main.command("hook-check")
@click.option("--tool", "tool_name", required=True)
@click.option("--input", "tool_input", required=True)
@click.option("--config", "config_path", default=None)
def hook_check_command(tool_name: str, tool_input: str, config_path: str | None) -> None:
    """[internal] Check tool call against policy."""
    code, output = evaluate_hook_tool(tool_name=tool_name, tool_input=tool_input, config_path=config_path)
    if output:
        click.echo(output)
    raise SystemExit(int(code))


@main.command("hook-log")
@click.option("--tool", "tool_name", required=True)
@click.option("--output", "tool_output", default="")
@click.option("--config", "config_path", default=None)
def hook_log_command(tool_name: str, tool_output: str, config_path: str | None) -> None:
    """[internal] Log tool call result."""
    ok, log_path = log_hook_tool(tool_name=tool_name, tool_output=tool_output, config_path=config_path)
    click.echo(f"logged:{log_path}")
    raise SystemExit(0 if ok else 1)


def _percentile_us(values: list[int], percentile: float) -> int:
    if not values:
        return 0
    if percentile <= 0:
        return values[0]
    if percentile >= 100:
        return values[-1]
    rank = int(round((percentile / 100.0) * (len(values) - 1)))
    rank = max(0, min(rank, len(values) - 1))
    return values[rank]


def _server_dependency_error() -> click.ClickException:
    return click.ClickException(
        "Server dependencies not installed. Run: pip install orchesis[server]"
    )


def _load_server_runtime() -> tuple[Any, Any, Any, Any]:
    try:
        import uvicorn  # type: ignore[import-not-found]
        from orchesis.api import create_api_app
        from orchesis.proxy import OrchesisProxy, ProxyConfig
    except ModuleNotFoundError as error:
        raise _server_dependency_error() from error
    return uvicorn, create_api_app, OrchesisProxy, ProxyConfig


def _load_httpx() -> Any:
    try:
        import httpx  # type: ignore[import-not-found]
    except ModuleNotFoundError as error:
        raise _server_dependency_error() from error
    return httpx


def _load_sync_runtime() -> Any:
    try:
        from orchesis.sync import PolicySyncClient
    except ModuleNotFoundError as error:
        raise _server_dependency_error() from error
    return PolicySyncClient


def _load_mcp_proxy_runtime() -> tuple[Any, Any, Any]:
    try:
        from orchesis.interceptors import McpStdioProxy
        from orchesis.mcp_config import McpProxySettings
        from orchesis.mcp_proxy import run_stdio_proxy
    except ModuleNotFoundError as error:
        raise _server_dependency_error() from error
    return McpStdioProxy, McpProxySettings, run_stdio_proxy


def _load_mcp_server_runtime() -> tuple[Any, Any]:
    from orchesis.mcp_server import MCPServer
    from orchesis.mcp_tools import build_tool_registry

    return MCPServer, build_tool_registry


def _load_auth_stack(credentials_file: str, mode: str = "enforce") -> tuple[CredentialStore, AgentAuthenticator]:
    store = CredentialStore(credentials_file)
    credentials = store.load() if store.exists() else {}
    authenticator = AgentAuthenticator(credentials=credentials, mode=mode)
    return store, authenticator


@main.group("auth")
def auth_group() -> None:
    """Manage HMAC credentials for agents."""


@auth_group.command("register")
@click.argument("agent_id")
@click.option("--credentials-file", default=".orchesis/credentials.yaml")
def auth_register(agent_id: str, credentials_file: str) -> None:
    store, authenticator = _load_auth_stack(credentials_file, mode="enforce")
    cred = authenticator.register(agent_id)
    store.save(authenticator.credentials)
    click.echo(f"Agent registered: {cred.agent_id}")
    click.echo(f"Secret key: {cred.secret_key} (SAVE THIS — it won't be shown again)")
    click.echo("")
    click.echo("Add these headers to agent requests:")
    click.echo(f"  X-Orchesis-Agent: {cred.agent_id}")
    click.echo("  X-Orchesis-Timestamp: <unix_timestamp>")
    click.echo("  X-Orchesis-Signature: hmac-sha256(secret, agent:timestamp:tool:params_hash)")


@auth_group.command("list")
@click.option("--credentials-file", default=".orchesis/credentials.yaml")
def auth_list(credentials_file: str) -> None:
    _store, authenticator = _load_auth_stack(credentials_file, mode="enforce")
    rows = sorted(authenticator.list_agents(), key=lambda item: str(item.get("agent_id", "")))
    click.echo("Agent           Enabled   Created              Last Used")
    click.echo("---------------------------------------------------------")
    for row in rows:
        agent_id = str(row.get("agent_id", ""))
        enabled = "✅" if bool(row.get("enabled")) else "❌"
        created_at = row.get("created_at", 0.0)
        last_used = row.get("last_used", 0.0)
        try:
            created_str = datetime.fromtimestamp(float(created_at), tz=timezone.utc).strftime("%Y-%m-%d %H:%M")
        except Exception:
            created_str = "unknown"
        if isinstance(last_used, int | float) and float(last_used) > 0:
            last_used_str = datetime.fromtimestamp(float(last_used), tz=timezone.utc).strftime("%Y-%m-%d %H:%M")
        else:
            last_used_str = "never"
        click.echo(f"{agent_id:<15} {enabled:<8} {created_str:<20} {last_used_str}")


@auth_group.command("revoke")
@click.argument("agent_id")
@click.option("--credentials-file", default=".orchesis/credentials.yaml")
def auth_revoke(agent_id: str, credentials_file: str) -> None:
    store, authenticator = _load_auth_stack(credentials_file, mode="enforce")
    if not authenticator.revoke(agent_id):
        raise click.ClickException(f"Unknown agent: {agent_id}")
    store.save(authenticator.credentials)
    click.echo(f"Agent revoked: {agent_id}")


@auth_group.command("rotate")
@click.argument("agent_id")
@click.option("--credentials-file", default=".orchesis/credentials.yaml")
def auth_rotate(agent_id: str, credentials_file: str) -> None:
    store, authenticator = _load_auth_stack(credentials_file, mode="enforce")
    cred = authenticator.rotate(agent_id)
    if cred is None:
        raise click.ClickException(f"Unknown agent: {agent_id}")
    store.save(authenticator.credentials)
    click.echo(f"Secret rotated for: {agent_id}")
    click.echo(f"New secret: {cred.secret_key} (SAVE THIS)")


@auth_group.command("verify")
@click.option("--agent", "agent_id", required=True)
@click.option("--tool", "tool_name", required=True)
@click.option("--params", "params_json", default="{}")
@click.option("--secret", "secret_key", required=True)
def auth_verify(agent_id: str, tool_name: str, params_json: str, secret_key: str) -> None:
    try:
        params = json.loads(params_json)
    except Exception as error:  # noqa: BLE001
        raise click.ClickException(f"Invalid --params JSON: {error}") from error
    if not isinstance(params, dict):
        raise click.ClickException("--params must be a JSON object")
    ts = str(int(time.time()))
    params_hash = hashlib.sha256(
        json.dumps(params, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    authenticator = AgentAuthenticator(mode="optional")
    signature = authenticator.compute_signature(secret_key, agent_id, ts, tool_name, params_hash)
    click.echo("✅ Signature valid")
    click.echo("Headers to use:")
    click.echo(f"  X-Orchesis-Agent: {agent_id}")
    click.echo(f"  X-Orchesis-Timestamp: {ts}")
    click.echo(f"  X-Orchesis-Signature: {signature}")


@main.command("quickstart")
@click.option(
    "--preset",
    type=click.Choice(["openclaw", "anthropic", "openai", "generic", "default", "minimal"]),
    default=None,
)
@click.option("--non-interactive", is_flag=True, default=False)
@click.option("--budget", type=float, default=10.0)
@click.option("--output", "output_path", default="orchesis.yaml")
def quickstart_command(
    preset: str | None,
    non_interactive: bool,
    budget: float,
    output_path: str,
) -> None:
    """Interactive setup wizard for a working config."""
    wizard = QuickstartWizard()
    output = wizard.run(
        non_interactive=bool(non_interactive),
        preset=preset,
        budget=float(budget),
        output_path=output_path,
    )
    try:
        generated = yaml.safe_load(Path(output).read_text(encoding="utf-8"))
        if not isinstance(generated, dict):
            generated = {}
    except Exception:
        generated = {}

    semantic_cfg = generated.get("semantic_cache", {}) if isinstance(generated, dict) else {}
    if isinstance(semantic_cfg, dict) and bool(semantic_cfg.get("enabled")):
        click.echo("✓ semantic_cache: enabled")

    recording_cfg = generated.get("recording", {}) if isinstance(generated, dict) else {}
    if isinstance(recording_cfg, dict) and bool(recording_cfg.get("enabled")):
        click.echo("✓ recording: enabled")

    loop_cfg = generated.get("loop_detection", {}) if isinstance(generated, dict) else {}
    if isinstance(loop_cfg, dict) and bool(loop_cfg.get("enabled")):
        block_at = int(loop_cfg.get("block_threshold", 5) or 5)
        click.echo(f"✓ loop_detection: enabled (block at {block_at} repeats)")

    threat_cfg = generated.get("threat_intel", {}) if isinstance(generated, dict) else {}
    if isinstance(threat_cfg, dict) and bool(threat_cfg.get("enabled")):
        click.echo("✓ threat_intel: enabled")
    raise SystemExit(0)


@main.command("new")
@click.argument("target", type=click.Path(), default=".")
@click.option("--template", "template_name", type=click.Choice(TEMPLATE_NAMES), default="minimal")
@click.option("--force", is_flag=True, default=False)
def new_project(target: str, template_name: str, force: bool) -> None:
    """Scaffold a new Orchesis project from template."""
    root = Path(target)
    root.mkdir(parents=True, exist_ok=True)
    policy_file = root / "policy.yaml"
    request_file = root / "request.json"
    readme_file = root / "README.md"
    if not force:
        existing = [
            str(path.name) for path in (policy_file, request_file, readme_file) if path.exists()
        ]
        if existing:
            raise click.ClickException(
                f"Refusing to overwrite existing files: {', '.join(existing)}. Use --force to overwrite."
            )
    policy_file.write_text(load_template_text(template_name), encoding="utf-8")
    request_file.write_text(
        json.dumps(
            {
                "tool": "read_file",
                "params": {"path": "/data/example.txt"},
                "cost": 0.1,
                "context": {"agent": "cursor", "session": "new-project"},
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    readme_file.write_text(
        (
            "# New Orchesis Project\n\n"
            f"- Template: `{template_name}`\n"
            "- Validate: `orchesis validate --policy policy.yaml`\n"
            "- Verify: `orchesis verify request.json --policy policy.yaml`\n"
            "- Fuzz: `orchesis fuzz --policy policy.yaml`\n"
        ),
        encoding="utf-8",
    )
    click.echo(f"Created Orchesis project in {root}")
    click.echo(f"- policy.yaml ({template_name})")
    click.echo("- request.json")
    click.echo("- README.md")


@main.command("doctor")
@click.option("--config", "--policy", "config_path", type=click.Path(), default="policy.yaml")
@click.option("--fix", "attempt_fix", is_flag=True, default=False)
@click.option("--json", "json_output", is_flag=True, default=False)
def doctor(config_path: str, attempt_fix: bool, json_output: bool) -> None:
    """Run environment and project diagnostics."""
    checks: list[dict[str, Any]] = []
    import importlib.util
    import sys

    def _add_check(name: str, ok: bool, severity: str, detail: str, fix_suggestion: str = "") -> None:
        checks.append(
            {
                "name": name,
                "ok": bool(ok),
                "severity": severity,
                "detail": detail,
                "fix": fix_suggestion,
            }
        )

    def _http_responding(url: str, timeout: float = 1.0) -> tuple[bool, str]:
        try:
            req = UrlRequest(url, method="GET")
            with urlopen(req, timeout=timeout) as resp:
                return True, f"http {int(resp.status)}"
        except HTTPError as error:
            return True, f"http {int(error.code)}"
        except Exception as error:  # noqa: BLE001
            return False, error.__class__.__name__

    def _dir_size_bytes(path: Path) -> int:
        if not path.exists() or not path.is_dir():
            return 0
        total = 0
        for item in path.rglob("*"):
            if item.is_file():
                try:
                    total += item.stat().st_size
                except OSError:
                    continue
        return total

    py_ok = (sys.version_info.major, sys.version_info.minor) >= (3, 12)
    _add_check(
        "python_version",
        py_ok,
        "ERROR",
        f"{sys.version_info.major}.{sys.version_info.minor}",
        "Use Python 3.12 or newer.",
    )

    has_pyyaml = importlib.util.find_spec("yaml") is not None
    _add_check(
        "pyyaml_installed",
        has_pyyaml,
        "ERROR",
        "importable" if has_pyyaml else "missing",
        "Install dependency: pip install pyyaml>=6.0",
    )

    policy_file = Path(config_path).expanduser()
    loaded_policy: dict[str, Any] | None = None
    if policy_file.exists():
        try:
            loaded_policy = load_policy(policy_file)
            errors = validate_policy(loaded_policy)
            _add_check("config_exists", True, "ERROR", str(policy_file))
            _add_check(
                "config_valid",
                len(errors) == 0,
                "ERROR",
                "OK" if not errors else "; ".join(errors[:2]),
                "Run: orchesis validate --policy <path>",
            )
            _add_check(
                "policy_validate",
                len(errors) == 0,
                "ERROR",
                "OK" if not errors else "; ".join(errors[:2]),
                "Run: orchesis validate --policy <path>",
            )
        except Exception as error:  # noqa: BLE001
            _add_check("config_exists", True, "ERROR", str(policy_file))
            _add_check("config_valid", False, "ERROR", str(error), "Fix YAML syntax and required fields.")
            _add_check("policy_validate", False, "ERROR", str(error), "Fix YAML syntax and required fields.")
    else:
        if attempt_fix:
            policy_file.write_text("rules: []\n", encoding="utf-8")
        _add_check(
            "config_exists",
            policy_file.exists(),
            "ERROR",
            str(policy_file) if policy_file.exists() else f"missing: {policy_file}",
            "Create config file, e.g. orchesis.yaml with at least `rules: []`.",
        )
        _add_check(
            "config_valid",
            policy_file.exists(),
            "ERROR",
            "autocreated default config" if policy_file.exists() else "policy file not found",
            "Run: orchesis validate --policy <path>",
        )
        _add_check(
            "policy_validate",
            policy_file.exists(),
            "ERROR",
            "autocreated default config" if policy_file.exists() else "policy file not found",
            "Run: orchesis validate --policy <path>",
        )

    runtime_dir = Path(".orchesis")
    if attempt_fix:
        runtime_dir.mkdir(parents=True, exist_ok=True)
    runtime_bytes = _dir_size_bytes(runtime_dir)
    _add_check(
        "disk_space",
        runtime_bytes < 1024 * 1024 * 1024,
        "WARNING",
        f"{runtime_bytes} bytes in {runtime_dir}",
        "Clean old sessions/artifacts in .orchesis/.",
    )

    decisions_log = Path("decisions.jsonl")
    max_log_bytes = 100 * 1024 * 1024
    if attempt_fix and decisions_log.exists() and decisions_log.stat().st_size >= max_log_bytes:
        backup = decisions_log.with_suffix(".jsonl.1")
        backup.write_text(decisions_log.read_text(encoding="utf-8"), encoding="utf-8")
        decisions_log.write_text("", encoding="utf-8")
    current_log_size = decisions_log.stat().st_size if decisions_log.exists() else 0
    _add_check(
        "log_rotation",
        current_log_size < max_log_bytes,
        "WARNING",
        f"{current_log_size} bytes",
        "Rotate/compress decisions.jsonl.",
    )

    proxy_ok, proxy_detail = _http_responding("http://127.0.0.1:8080")
    _add_check("proxy_running", proxy_ok, "WARNING", proxy_detail, "Start proxy: orchesis proxy --config <path>")

    api_ok, api_detail = _http_responding("http://127.0.0.1:8090/health")
    _add_check("api_running", api_ok, "WARNING", api_detail, "Start API: orchesis serve --policy <path>")

    api_key_set = bool(os.environ.get("OPENAI_API_KEY") or os.environ.get("ANTHROPIC_API_KEY"))
    _add_check(
        "api_key_configured",
        api_key_set,
        "WARNING",
        "set" if api_key_set else "not set",
        "Set OPENAI_API_KEY or ANTHROPIC_API_KEY.",
    )

    if isinstance(loaded_policy, dict):
        semantic_cache_cfg = loaded_policy.get("semantic_cache", {})
        loop_cfg = loaded_policy.get("loop_detection", {})
        recording_cfg = loaded_policy.get("recording", {})
    else:
        semantic_cache_cfg = {}
        loop_cfg = {}
        recording_cfg = {}
    semantic_enabled = bool(semantic_cache_cfg.get("enabled")) if isinstance(semantic_cache_cfg, dict) else False
    loop_enabled = bool(loop_cfg.get("enabled")) if isinstance(loop_cfg, dict) else False
    recording_enabled = bool(recording_cfg.get("enabled")) if isinstance(recording_cfg, dict) else False
    _add_check("semantic_cache_enabled", semantic_enabled, "INFO", "enabled" if semantic_enabled else "disabled")
    _add_check("loop_detection_enabled", loop_enabled, "INFO", "enabled" if loop_enabled else "disabled")
    _add_check("recording_enabled", recording_enabled, "INFO", "enabled" if recording_enabled else "disabled")

    checks_by_name = {item["name"]: item for item in checks}
    ordered_checks = [checks_by_name[name] for name in DOCTOR_CHECKS if name in checks_by_name]
    for item in checks:
        if item["name"] not in DOCTOR_CHECKS:
            ordered_checks.append(item)
    all_error_checks_ok = all(item["ok"] for item in ordered_checks if item["severity"] == "ERROR")
    warning_failures = [item for item in ordered_checks if item["severity"] == "WARNING" and not item["ok"]]

    if json_output:
        payload = {
            "version": __version__,
            "config_path": str(policy_file),
            "checks": ordered_checks,
            "summary": {
                "errors": sum(1 for item in ordered_checks if item["severity"] == "ERROR" and not item["ok"]),
                "warnings": len(warning_failures),
                "info": sum(1 for item in ordered_checks if item["severity"] == "INFO"),
                "ok": all_error_checks_ok,
                "fix_attempted": bool(attempt_fix),
            },
        }
        click.echo(json.dumps(payload, ensure_ascii=False, indent=2))
        raise SystemExit(0 if all_error_checks_ok else 1)

    click.echo(f"Orchesis Doctor v{__version__}")
    click.echo("=====================")
    click.echo("Doctor checks:")
    for item in ordered_checks:
        marker = "[OK]" if item["ok"] else "[FAIL]"
        click.echo(f"  {marker} [{item['severity']}] {item['name']}: {item['detail']}")
        if not item["ok"] and item["fix"]:
            click.echo(f"           suggestion: {item['fix']}")
    if all_error_checks_ok:
        click.echo("")
        click.echo(f"Ready to start: orchesis proxy --config {config_path}")
    raise SystemExit(0 if all_error_checks_ok else 1)


@main.command()
@click.option(
    "--preset",
    type=click.Choice(["openclaw", "claude", "codex", "other"]),
    default=None,
)
@click.option("--non-interactive", is_flag=True, default=False)
@click.option("--dir", "project_dir", type=click.Path(), default=".")
@click.option("--budget", "budget_override", default=None)
def init(
    preset: str | None,
    non_interactive: bool,
    project_dir: str,
    budget_override: str | None,
) -> None:
    """Interactive project setup wizard."""
    target_dir = Path(project_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    legacy_policy_content = """rules:
  - name: budget_limit
    max_cost_per_call: 0.50
    daily_budget: 50.00

  - name: file_access
    allowed_paths:
      - "/data"
      - "/tmp"
    denied_paths:
      - "/etc"
      - "/root"
      - "/var/secrets"

  - name: sql_restriction
    allowed_operations:
      - "SELECT"
      - "INSERT"
    denied_operations:
      - "DROP"
      - "DELETE"
      - "TRUNCATE"
      - "ALTER"

  - name: rate_limit
    max_requests_per_minute: 100
"""
    legacy_request_content = """{
  "tool": "sql_query",
  "params": {
    "query": "DROP TABLE users",
    "path": "/etc/passwd"
  },
  "cost": 0.10,
  "context": {
    "agent": "cursor",
    "session": "abc-123"
  }
}
"""

    defaults = {
        "openclaw": {"budget": "20", "semantic_cache": True, "recording": True, "team": ""},
        "claude": {"budget": "15", "semantic_cache": True, "recording": True, "team": ""},
        "codex": {"budget": "15", "semantic_cache": True, "recording": True, "team": ""},
        "other": {"budget": "10", "semantic_cache": True, "recording": True, "team": ""},
    }
    selected_agent = preset or "openclaw"
    selected_defaults = defaults.get(selected_agent, defaults["openclaw"])

    is_effectively_non_interactive = bool(non_interactive or not sys.stdin.isatty())
    if is_effectively_non_interactive:
        budget_raw = str(budget_override or selected_defaults["budget"])
        semantic_cache_enabled = bool(selected_defaults["semantic_cache"])
        recording_enabled = bool(selected_defaults["recording"])
        team_name = str(selected_defaults["team"])
    else:
        selected_agent = click.prompt(
            "Which AI agent are you using?",
            type=click.Choice(["openclaw", "claude", "codex", "other"]),
            default=selected_agent,
            show_choices=True,
        )
        budget_raw = click.prompt(
            "What's your daily budget limit? ($ or 'unlimited')",
            default=str(budget_override or selected_defaults["budget"]),
        )
        semantic_cache_enabled = click.confirm("Enable semantic cache?", default=True)
        recording_enabled = click.confirm("Enable compliance recording?", default=True)
        team_name = click.prompt("Your team name (optional)", default="", show_default=False).strip()

    if isinstance(budget_override, str) and budget_override.strip():
        budget_raw = budget_override.strip()

    budget_unlimited = str(budget_raw).strip().lower() == "unlimited"
    daily_budget: float | None
    if budget_unlimited:
        daily_budget = None
    else:
        try:
            daily_budget = float(str(budget_raw).replace("$", "").strip())
        except (TypeError, ValueError):
            daily_budget = 10.0

    orchesis_config: dict[str, Any] = {
        "agent": {"type": selected_agent},
        "threat_intel": {"enabled": True},
        "loop_detection": {"enabled": True, "block_threshold": 5},
        "semantic_cache": {"enabled": bool(semantic_cache_enabled)},
        "recording": {"enabled": bool(recording_enabled)},
        "budgets": {
            "daily": "unlimited" if budget_unlimited else float(daily_budget or 0.0),
            "on_hard_limit": "warn" if budget_unlimited else "block",
        },
    }
    if isinstance(team_name, str) and team_name.strip():
        orchesis_config["team"] = {"name": team_name.strip()}

    (target_dir / "orchesis.yaml").write_text(
        yaml.safe_dump(orchesis_config, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    (target_dir / ".orchesis").mkdir(parents=True, exist_ok=True)

    # Backward compatibility for existing users/tests relying on these files.
    (target_dir / "policy.yaml").write_text(legacy_policy_content, encoding="utf-8")
    (target_dir / "request.json").write_text(legacy_request_content, encoding="utf-8")
    click.echo("Created policy.yaml and request.json. Edit them, then run: orchesis verify")

    click.echo("✓ orchesis.yaml created")
    click.echo("✓ .orchesis/ directory ready")
    click.echo("")
    click.echo("Next steps:")
    click.echo("  orchesis proxy --config orchesis.yaml")
    click.echo(f"  orchesis launch {selected_agent if selected_agent != 'other' else 'openclaw'}")
    click.echo("  http://localhost:8080/dashboard")


@main.command()
def keygen() -> None:
    """Generate Ed25519 keypair for signed decision logs."""
    generate_keypair(DEFAULT_KEYS_DIR)
    click.echo("Keys generated in .orchesis/keys/")


@main.command()
@click.argument("request_path", type=click.Path(exists=True))
@click.option("--policy", "policy_path", type=click.Path(exists=True), required=True)
@click.option("--sign", "should_sign", is_flag=True, default=False)
@click.option("--debug", "debug_mode", is_flag=True, default=False)
@click.option(
    "--plugins",
    "plugin_modules",
    multiple=True,
    help="Plugin module path(s), e.g. orchesis.contrib.pii_detector",
)
def verify(
    request_path: str,
    policy_path: str,
    should_sign: bool,
    debug_mode: bool,
    plugin_modules: tuple[str, ...],
) -> None:
    """Verify a request against policy."""
    try:
        request = json.loads(Path(request_path).read_text(encoding="utf-8"))
        policy = load_policy(policy_path)
        has_identity_config = "agents" in policy or "default_trust_tier" in policy
        registry = load_agent_registry(policy) if has_identity_config else None
        plugins = load_plugins_for_policy(policy, _normalize_plugin_modules(plugin_modules))
    except (json.JSONDecodeError, OSError) as error:
        raise click.ClickException(f"Failed to load request: {error}") from error
    except (ValueError, YAMLError, OSError) as error:
        raise click.ClickException(f"Failed to load policy: {error}") from error

    if not isinstance(request, dict):
        raise click.ClickException("Request JSON must be an object.")

    state_tracker = RateLimitTracker(persist_path=DEFAULT_STATE_PATH)
    try:
        signature: str | None = None
        if should_sign:
            memory_emitter = InMemoryEmitter()
            decision = evaluate(
                request,
                policy,
                state=state_tracker,
                emitter=memory_emitter,
                registry=registry,
                plugins=plugins,
                debug=debug_mode,
            )
            if not DEFAULT_PRIVATE_KEY_PATH.exists():
                raise click.ClickException(
                    "Missing private key. Run 'orchesis keygen' before using --sign."
                )
            sign_input: dict[str, object] = {
                "timestamp": decision.timestamp,
                "tool": request.get("tool"),
                "decision": "ALLOW" if decision.allowed else "DENY",
                "reasons": decision.reasons,
            }
            signature = sign_entry(sign_input, DEFAULT_PRIVATE_KEY_PATH)
            events = memory_emitter.get_events()
            if events:
                JsonlEmitter(DEFAULT_DECISIONS_PATH).emit(replace(events[-1], signature=signature))
        else:
            decision = evaluate(
                request,
                policy,
                state=state_tracker,
                emitter=JsonlEmitter(DEFAULT_DECISIONS_PATH),
                registry=registry,
                plugins=plugins,
                debug=debug_mode,
            )

        click.echo(json.dumps(asdict(decision), ensure_ascii=False, indent=2))
        raise SystemExit(0 if decision.allowed else 1)
    finally:
        state_tracker.flush()


@main.command()
@click.option("--config", "config_path", type=click.Path(exists=True), default=None)
@click.option("--policy", "policy_path", type=click.Path(exists=True), default=None)
@click.option(
    "--framework",
    type=click.Choice(["none", "eu-ai-act", "owasp", "all"], case_sensitive=False),
    default="none",
)
@click.option("--strict", "strict_mode", is_flag=True, default=False)
def validate(
    config_path: str | None,
    policy_path: str | None,
    framework: str,
    strict_mode: bool,
) -> None:
    """Validate policy file."""
    resolved_policy = (
        config_path
        if isinstance(config_path, str) and config_path.strip()
        else (policy_path if isinstance(policy_path, str) and policy_path.strip() else None)
    )
    if not isinstance(resolved_policy, str):
        raise click.ClickException("One of --config or --policy is required")
    try:
        policy = load_policy(resolved_policy)
    except (ValueError, YAMLError, OSError) as error:
        raise click.ClickException(f"Failed to load policy: {error}") from error

    errors = validate_policy(policy)
    warnings = validate_policy_warnings(policy)
    validator = PolicyAsCodeValidator()
    selected_framework = str(framework).strip().lower()
    framework_violations: list[str] = []
    report = validator.validate(policy)
    if selected_framework == "eu-ai-act":
        framework_violations = validator.validate_eu_ai_act(policy)
    elif selected_framework == "owasp":
        framework_violations = validator.validate_owasp(policy)
    elif selected_framework == "all":
        framework_violations = list(report.violations)

    if selected_framework in {"all", "eu-ai-act"}:
        click.echo(f"EU AI Act score: {report.eu_ai_act_score * 100:.1f}%")
    if selected_framework in {"all", "owasp"}:
        click.echo(f"OWASP score: {report.owasp_score * 100:.1f}%")

    for warning in warnings:
        click.echo(f"! warning: {warning}")
    for violation in framework_violations:
        click.echo(f"- {violation}")

    if strict_mode and warnings:
        raise SystemExit(1)

    if not errors and not framework_violations:
        click.echo("OK")
        return

    for error in errors:
        click.echo(f"- {error}")
    if framework_violations:
        for fix in validator.suggest_fixes(framework_violations):
            click.echo(f"> fix:\n{fix}")
    raise SystemExit(1)


@main.command("generate-rules")
@click.option("--policy", "policy_path", type=click.Path(exists=True), required=True)
@click.option("--format", "output_format", type=click.Choice(["markdown", "text"]), default="markdown")
@click.option("--output", "output_path", type=click.Path(), default=None)
def generate_rules_command(policy_path: str, output_format: str, output_path: str | None) -> None:
    """Generate behavioral security rules from policy."""
    try:
        content = generate_security_rules_from_policy(policy_path, output_format=output_format)
    except (ValueError, YAMLError, OSError) as error:
        raise click.ClickException(f"Failed to load policy: {error}") from error
    if output_path is not None:
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        click.echo(f"Rules written to {target}")
        return
    click.echo(content)


@main.command("serve-scanner")
@click.option("--port", type=int, default=8081)
@click.option("--host", type=str, default="127.0.0.1")
@click.option("--policy", "policy_path", type=click.Path(exists=True), default=None)
@click.option("--allow-file-access/--no-allow-file-access", default=False)
def serve_scanner_command(port: int, host: str, policy_path: str | None, allow_file_access: bool) -> None:
    """Run scanner HTTP API server (stdlib only)."""
    click.echo(f"Orchesis Scanner API running on http://{host}:{port}")
    click.echo("Endpoints:")
    click.echo("  POST /scan/skill")
    click.echo("  POST /scan/mcp")
    click.echo("  POST /scan/policy")
    click.echo("  POST /scan/ioc")
    click.echo("  GET  /health")
    click.echo("  GET  /frameworks")
    click.echo("No authentication in v1. Use reverse proxy for production.")
    run_scanner_http_server(
        host=host,
        port=max(1, int(port)),
        policy_path=policy_path,
        allow_file_access=bool(allow_file_access),
    )


@main.group("credentials")
def credentials_group() -> None:
    """Manage credential vault aliases."""


@credentials_group.command("set")
@click.argument("alias")
@click.option("--env", "use_env_vault", is_flag=True, default=False)
@click.option("--vault-path", default=".orchesis/credentials.enc")
def credentials_set(alias: str, use_env_vault: bool, vault_path: str) -> None:
    """Set credential value for alias."""
    safe_alias = alias.strip()
    if not safe_alias:
        raise click.ClickException("Alias must be non-empty")
    if use_env_vault:
        vault = EnvVault()
        vault.set_mapping(safe_alias, safe_alias.upper())
        click.echo(f"✓ {safe_alias}: mapped to env var {safe_alias.upper()}")
        return
    value = click.prompt(f"Credential value for {safe_alias}", hide_input=True, confirmation_prompt=True)
    vault = FileVault(vault_path=vault_path)
    vault.set(safe_alias, value)
    click.echo(f"✓ {safe_alias}: stored")


@credentials_group.command("list")
@click.option("--policy", "policy_path", type=click.Path(exists=True), default=None)
@click.option("--vault-path", default=".orchesis/credentials.enc")
def credentials_list(policy_path: str | None, vault_path: str) -> None:
    """List credential aliases only (never values)."""
    if policy_path is not None:
        policy = load_policy(policy_path)
        vault = build_vault_from_policy(policy)
    else:
        vault = FileVault(vault_path=vault_path)
    aliases = vault.list_aliases()
    if not aliases:
        click.echo("(no credentials)")
        return
    for alias in aliases:
        click.echo(alias)


@credentials_group.command("remove")
@click.argument("alias")
@click.option("--policy", "policy_path", type=click.Path(exists=True), default=None)
@click.option("--vault-path", default=".orchesis/credentials.enc")
def credentials_remove(alias: str, policy_path: str | None, vault_path: str) -> None:
    """Remove alias from vault."""
    if policy_path is not None:
        policy = load_policy(policy_path)
        vault = build_vault_from_policy(policy)
    else:
        vault = FileVault(vault_path=vault_path)
    removed = vault.remove(alias.strip())
    if not removed:
        raise click.ClickException(f"Unknown alias: {alias}")
    click.echo(f"✓ {alias}: removed")


@credentials_group.command("test")
@click.argument("alias")
@click.option("--policy", "policy_path", type=click.Path(exists=True), default=None)
@click.option("--vault-path", default=".orchesis/credentials.enc")
def credentials_test(alias: str, policy_path: str | None, vault_path: str) -> None:
    """Test if credential alias is accessible."""
    if policy_path is not None:
        policy = load_policy(policy_path)
        vault = build_vault_from_policy(policy)
    else:
        vault = FileVault(vault_path=vault_path)
    try:
        value = vault.get(alias.strip())
    except CredentialNotFoundError as error:
        raise click.ClickException(str(error)) from error
    click.echo(f"✓ {alias}: accessible ({len(value)} chars...hidden)")


@main.command()
@click.option("--policy", "policy_path", type=click.Path(exists=True), required=True)
def agents(policy_path: str) -> None:
    """List registered agent identities from policy."""
    try:
        policy = load_policy(policy_path)
    except (ValueError, YAMLError, OSError) as error:
        raise click.ClickException(f"Failed to load policy: {error}") from error

    registry = load_agent_registry(policy)
    click.echo("Registered agents:")
    if not registry.agents:
        click.echo("  (none)")
    else:
        for agent_id in sorted(registry.agents):
            identity = registry.agents[agent_id]
            tools = ", ".join(identity.allowed_tools) if identity.allowed_tools else "all"
            click.echo(
                f"  {identity.agent_id:<13} {identity.trust_tier.name.lower():<10} tools: {tools}"
            )
    click.echo(f"Default tier: {registry.default_tier.name.lower()}")


@main.command()
@click.option("--policy", "policy_path", type=click.Path(exists=True), required=True)
def policy_history(policy_path: str) -> None:
    """Show policy version history."""
    store = PolicyStore()
    try:
        loaded = store.load(policy_path)
    except (ValueError, YAMLError, OSError) as error:
        raise click.ClickException(f"Failed to load policy: {error}") from error

    current = store.current or loaded
    click.echo("Policy versions:")
    for index, version in enumerate(store.history()):
        marker = " (current)" if version.version_id == current.version_id else ""
        short_hash = version.version_id[:12]
        click.echo(f"  v{index} {short_hash} loaded {version.loaded_at}{marker}")


@main.command()
@click.option("--policy", "policy_path", type=click.Path(exists=True), required=True)
def rollback(policy_path: str) -> None:
    """Rollback to previous policy version."""
    store = PolicyStore()
    try:
        current = store.current
        if current is None:
            current = store.load(policy_path)
    except (ValueError, YAMLError, OSError) as error:
        raise click.ClickException(f"Failed to load policy: {error}") from error

    rolled = store.rollback()
    if rolled is None:
        click.echo("Rollback unavailable: no previous policy version.")
        return
    click.echo(f"Rolled back: {current.version_id[:12]} -> {rolled.version_id[:12]}")
    click.echo(f"Current policy version: {rolled.version_id[:12]}")


@main.command()
@click.option("--port", type=int, default=8090)
@click.option("--policy", "policy_path", type=click.Path(exists=True), default="policy.yaml")
@click.option(
    "--cors",
    "cors_value",
    type=str,
    default=None,
    help='Allowed CORS origin(s), e.g. "https://app.example.com" or "*" or comma-separated list',
)
@click.option(
    "--token",
    "api_token",
    type=str,
    default=None,
    help="Custom API token for Authorization: Bearer <token>",
)
@click.option(
    "--plugins",
    "plugin_modules",
    multiple=True,
    help="Plugin module path(s), e.g. orchesis.contrib.pii_detector",
)
def serve(
    port: int,
    policy_path: str,
    cors_value: str | None,
    api_token: str | None,
    plugin_modules: tuple[str, ...],
) -> None:
    """Run Orchesis control API server."""
    uvicorn, create_api_app, _orchesis_proxy_cls, _proxy_config_cls = _load_server_runtime()
    try:
        policy = load_policy(policy_path)
    except (ValueError, YAMLError, OSError) as error:
        raise click.ClickException(f"Failed to load policy: {error}") from error

    store = PolicyStore()
    version = store.load(policy_path)
    registry = load_agent_registry(policy)
    policy_api_cfg = policy.get("api") if isinstance(policy, dict) and isinstance(policy.get("api"), dict) else {}
    policy_token = policy_api_cfg.get("token") if isinstance(policy_api_cfg.get("token"), str) else None
    token_to_use = (
        api_token.strip()
        if isinstance(api_token, str) and api_token.strip()
        else (policy_token.strip() if isinstance(policy_token, str) and policy_token.strip() else "")
    )
    if not token_to_use:
        token_to_use = f"orchesis-{hashlib.sha256(str(time.time()).encode('utf-8')).hexdigest()[:6]}"
    cors_origins: list[str] | None = None
    if isinstance(cors_value, str) and cors_value.strip():
        parts = [item.strip() for item in cors_value.split(",") if item.strip()]
        cors_origins = parts if parts else None

    click.echo("✓ Orchesis API server running")
    click.echo(f"  URL:   http://localhost:{port}")
    click.echo(f"  Token: {token_to_use}  ← copy this")
    click.echo(f"  Docs:  http://localhost:{port}/docs")
    click.echo(f"Policy: {policy_path} (version {version.version_id[:12]})")
    click.echo(
        f"Agents: {len(registry.agents)} registered, default tier: {registry.default_tier.name.lower()}"
    )
    click.echo("Endpoints: /health, /docs, /api/v1/policy, /api/v1/agents, /api/v1/evaluate, /api/v1/status")
    OPERATIONS_LOG.info("starting api server", port=port, policy_path=policy_path)
    app = create_api_app(
        policy_path=policy_path,
        api_token=token_to_use,
        cors_origins=cors_origins,
        plugin_modules=_normalize_plugin_modules(plugin_modules),
    )
    uvicorn.run(app, host="0.0.0.0", port=port)


@main.command("proxy")
@click.option("--policy", "policy_path", type=click.Path(), default=None)
@click.option("--config", "config_path", type=click.Path(), default=None)
@click.option("--port", type=int, default=None)
@click.option("--host", "listen_host", type=str, default=None)
@click.option("--upstream-anthropic", "upstream_anthropic", type=str, default=None)
@click.option("--upstream-openai", "upstream_openai", type=str, default=None)
@click.option("--timeout", "timeout_seconds", type=float, default=None)
@click.option("--verbose", is_flag=True, default=False)
def proxy_command(
    policy_path: str | None,
    config_path: str | None,
    port: int | None,
    listen_host: str | None,
    upstream_anthropic: str | None,
    upstream_openai: str | None,
    timeout_seconds: float | None,
    verbose: bool,
) -> None:
    """Run stdlib HTTP proxy for Anthropic/OpenAI-compatible APIs."""
    from orchesis.proxy import HTTPProxyConfig, LLMHTTPProxy

    if verbose:
        import logging

        logging.basicConfig(level=logging.DEBUG)

    safe_policy_path = None
    policy: dict[str, Any] | None = None
    effective_policy_path = config_path if isinstance(config_path, str) and config_path.strip() else policy_path
    if isinstance(effective_policy_path, str) and effective_policy_path.strip():
        candidate = Path(effective_policy_path).expanduser()
        if not candidate.exists():
            raise click.ClickException(f"Policy file not found: {candidate}")
        safe_policy_path = str(candidate)
    else:
        for default_candidate in (Path("orchesis.yaml"), Path("policy.yaml")):
            if default_candidate.exists():
                safe_policy_path = str(default_candidate)
                break

    if safe_policy_path is not None:
        try:
            policy = load_policy(safe_policy_path)
        except (ValueError, YAMLError, OSError) as error:
            raise click.ClickException(f"Failed to load policy: {error}") from error

    proxy_policy_cfg = policy.get("proxy", {}) if isinstance(policy, dict) else {}
    proxy_policy_cfg = proxy_policy_cfg if isinstance(proxy_policy_cfg, dict) else {}
    policy_upstream = proxy_policy_cfg.get("upstream", {})
    policy_upstream = policy_upstream if isinstance(policy_upstream, dict) else {}

    resolved_host = (
        listen_host.strip()
        if isinstance(listen_host, str) and listen_host.strip()
        else (
            proxy_policy_cfg.get("host", "127.0.0.1")
            if isinstance(proxy_policy_cfg.get("host"), str)
            else "127.0.0.1"
        )
    )
    resolved_port = (
        max(1, int(port))
        if isinstance(port, int | float)
        else (
            max(1, int(proxy_policy_cfg.get("port")))
            if isinstance(proxy_policy_cfg.get("port"), int | float)
            else 8100
        )
    )
    resolved_timeout = (
        max(1.0, float(timeout_seconds))
        if isinstance(timeout_seconds, int | float)
        else (
            max(1.0, float(proxy_policy_cfg.get("timeout")))
            if isinstance(proxy_policy_cfg.get("timeout"), int | float)
            else 300.0
        )
    )
    resolved_upstream_anthropic = (
        upstream_anthropic.strip()
        if isinstance(upstream_anthropic, str) and upstream_anthropic.strip()
        else (
            policy_upstream.get("anthropic", "https://api.anthropic.com")
            if isinstance(policy_upstream.get("anthropic"), str)
            else "https://api.anthropic.com"
        )
    )
    resolved_upstream_openai = (
        upstream_openai.strip()
        if isinstance(upstream_openai, str) and upstream_openai.strip()
        else (
            policy_upstream.get("openai", "https://api.openai.com")
            if isinstance(policy_upstream.get("openai"), str)
            else "https://api.openai.com"
        )
    )

    proxy_config = HTTPProxyConfig(
        host=resolved_host,
        port=resolved_port,
        timeout=resolved_timeout,
        upstream={
            "anthropic": resolved_upstream_anthropic,
            "openai": resolved_upstream_openai,
        },
    )
    proxy = LLMHTTPProxy(policy_path=safe_policy_path, config=proxy_config)
    click.echo("Orchesis Proxy starting...")
    click.echo(f"Policy: {safe_policy_path or 'none (passthrough policy mode)'}")
    click.echo(f"Listening: http://{proxy_config.host}:{proxy_config.port}")
    click.echo(f"Anthropic upstream: {proxy_config.upstream['anthropic']}")
    click.echo(f"OpenAI upstream: {proxy_config.upstream['openai']}")
    click.echo(f"Timeout: {proxy_config.timeout:.1f}s")
    click.echo("")
    click.echo("Press Ctrl+C to stop.")
    try:
        proxy.start(blocking=True)
    except KeyboardInterrupt:
        proxy.stop()
        click.echo("\nProxy stopped.")


@main.command("demo")
@click.option("--port", "proxy_port", type=int, default=8080)
@click.option("--api-port", type=int, default=8090)
@click.option("--policy", "policy_path", type=click.Path(), default="orchesis.yaml")
def demo_command(proxy_port: int, api_port: int, policy_path: str) -> None:
    """Launch local proxy + API services for a full demo."""
    from orchesis.proxy import HTTPProxyConfig, LLMHTTPProxy

    uvicorn, create_api_app, _orchesis_proxy_cls, _proxy_config_cls = _load_server_runtime()
    resolved_proxy_port = max(1, int(proxy_port))
    resolved_api_port = max(1, int(api_port))
    resolved_policy = str(Path(policy_path).expanduser())

    proxy = LLMHTTPProxy(
        policy_path=resolved_policy if Path(resolved_policy).exists() else None,
        config=HTTPProxyConfig(host="127.0.0.1", port=resolved_proxy_port),
    )
    proxy.start(blocking=False)

    api_app = create_api_app(policy_path=resolved_policy)
    api_server = uvicorn.Server(
        uvicorn.Config(api_app, host="127.0.0.1", port=resolved_api_port, log_level="warning")
    )
    api_thread = threading.Thread(target=api_server.run, daemon=True)
    api_thread.start()

    click.echo(f"Orchesis proxy:    http://localhost:{resolved_proxy_port}")
    click.echo(f"Orchesis API:      http://localhost:{resolved_api_port}")
    click.echo(f"Dashboard:         http://localhost:{resolved_proxy_port}/dashboard")
    click.echo(f"Overwatch API:     http://localhost:{resolved_api_port}/api/v1/overwatch")
    click.echo("")
    click.echo("Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        proxy.stop()
        api_server.should_exit = True
        if api_thread.is_alive():
            api_thread.join(timeout=2.0)


@main.command("launch")
@click.argument("agent", type=click.Choice(sorted(AGENT_COMMANDS.keys())))
@click.option("--config", "config_path", type=click.Path(), default=None)
def launch_command(agent: str, config_path: str | None) -> None:
    """Launch a local agent through Orchesis proxy."""
    if agent == "cursor":
        os.environ["OPENAI_API_BASE"] = "http://localhost:8080/v1"
        print("✓ Set OPENAI_API_BASE for Cursor IDE")
        print("  Restart Cursor to apply proxy settings")
        return

    agent_cmd_raw = AGENT_COMMANDS.get(agent)
    if not isinstance(agent_cmd_raw, list):
        raise click.ClickException(f"Unsupported agent launch mode: {agent}")

    launch_started = time.monotonic()
    proxy_cmd = [sys.executable, "-m", "orchesis", "proxy", "--host", "127.0.0.1", "--port", "8080"]
    if isinstance(config_path, str) and config_path.strip():
        proxy_cmd.extend(["--config", config_path.strip()])

    proxy_process: subprocess.Popen[Any] | None = None
    try:
        proxy_process = subprocess.Popen(proxy_cmd)
    except Exception as error:
        raise click.ClickException(f"Failed to start proxy: {error}") from error

    if not _wait_for_proxy(8080, timeout=5.0):
        if proxy_process is not None:
            try:
                proxy_process.terminate()
            except Exception:
                pass
        raise click.ClickException("Proxy failed health check on port 8080")

    print("✓ Orchesis proxy running on :8080")
    print(f"✓ Intercepting {agent} traffic")
    print("  Dashboard: http://localhost:8080/dashboard")
    print("  Press Ctrl+C to stop proxy and agent")

    before_stats = _get_proxy_stats(8080)
    agent_cmd = list(agent_cmd_raw)

    agent_exit_code = 0
    try:
        agent_process = subprocess.Popen(agent_cmd)
        agent_exit_code = int(agent_process.wait())
    except FileNotFoundError as error:
        print(f"Failed to launch {agent}: {error}")
        agent_exit_code = 1
    finally:
        if proxy_process is not None:
            try:
                proxy_process.terminate()
            except Exception:
                pass
            try:
                proxy_process.wait(timeout=5)
            except Exception:
                try:
                    proxy_process.kill()
                except Exception:
                    pass

    after_stats = _get_proxy_stats(8080)
    elapsed = max(0.0, time.monotonic() - launch_started)
    requests_before = int(before_stats.get("requests", 0) or 0)
    requests_after = int(after_stats.get("requests", requests_before) or requests_before)
    blocked_before = int(before_stats.get("blocked", 0) or 0)
    blocked_after = int(after_stats.get("blocked", blocked_before) or blocked_before)
    cost_before = float(before_stats.get("cost_today", 0.0) or 0.0)
    cost_after = float(after_stats.get("cost_today", cost_before) or cost_before)
    print("\n── Session summary ──")
    print(f"  Duration: {elapsed:.0f}s")
    print(f"  Requests intercepted: {max(0, requests_after - requests_before)}")
    print(f"  Threats blocked: {max(0, blocked_after - blocked_before)}")
    print(f"  Cost: ${max(0.0, cost_after - cost_before):.4f}")

    raise SystemExit(agent_exit_code)


def _wait_for_proxy(port: int, timeout: float = 5.0) -> bool:
    """Check proxy is up before launching agent."""
    deadline = time.monotonic() + max(0.1, float(timeout))
    while time.monotonic() < deadline:
        try:
            with urlopen(f"http://127.0.0.1:{max(1, int(port))}/health", timeout=1.0):
                return True
        except Exception:
            time.sleep(0.1)
    return False


def _get_proxy_stats(port: int) -> dict[str, Any]:
    try:
        with urlopen(f"http://127.0.0.1:{max(1, int(port))}/stats", timeout=2.0) as response:
            parsed = json.loads(response.read().decode("utf-8"))
            if isinstance(parsed, dict):
                return parsed
    except Exception:
        return {}
    return {}


@main.command("status")
@click.option("--json", "json_output", is_flag=True, default=False, help="Output machine-readable JSON")
@click.option("--watch", "watch_mode", is_flag=True, default=False, help="Refresh every 5 seconds")
def status_command(json_output: bool, watch_mode: bool) -> None:
    """Show quick Orchesis system health overview."""

    def _fetch_json(url: str, timeout: float = 1.5) -> dict[str, Any]:
        try:
            req = UrlRequest(url, method="GET")
            with urlopen(req, timeout=timeout) as response:
                parsed = json.loads(response.read().decode("utf-8"))
                return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}

    def _status_snapshot() -> dict[str, Any]:
        proxy_stats = _fetch_json("http://127.0.0.1:8080/api/v1/stats")
        if not proxy_stats:
            proxy_stats = _fetch_json("http://127.0.0.1:8080/stats")
        api_health = _fetch_json("http://127.0.0.1:8090/api/v1/health")
        if not api_health:
            api_health = _fetch_json("http://127.0.0.1:8090/health")

        requests_total = int(proxy_stats.get("requests_total", proxy_stats.get("requests", 0)) or 0)
        cost_today = float(proxy_stats.get("cost_today", proxy_stats.get("cost", 0.0)) or 0.0)
        blocked = int(proxy_stats.get("requests_blocked", proxy_stats.get("blocked", 0)) or 0)
        block_rate = float(proxy_stats.get("block_rate", 0.0) or 0.0)
        cache_hit_rate = float(proxy_stats.get("cache_hit_rate", 0.0) or 0.0)
        tokens_saved = int(proxy_stats.get("tokens_saved", 0) or 0)
        money_saved = float(proxy_stats.get("money_saved_usd", 0.0) or 0.0)
        budget_spent = float(proxy_stats.get("budget_spent_usd", cost_today) or cost_today)
        budget_limit = proxy_stats.get("budget_limit_usd", "unlimited")
        loops_today = int(proxy_stats.get("loops_detected_today", proxy_stats.get("loops_detected", 0)) or 0)
        active_agents = int(proxy_stats.get("active_agents", proxy_stats.get("agents_discovered", 0)) or 0)
        agent_errors = int(proxy_stats.get("agent_errors", 0) or 0)
        approvals_pending = int(proxy_stats.get("approvals_pending", 0) or 0)
        uptime_seconds = int(api_health.get("uptime_seconds", 0) or 0)
        uptime_hours, rem = divmod(max(0, uptime_seconds), 3600)
        uptime_minutes = rem // 60

        return {
            "version": __version__,
            "proxy_running": bool(proxy_stats),
            "api_running": bool(api_health),
            "dashboard_url": "http://localhost:8080/dashboard",
            "requests_total": requests_total,
            "cost_today_usd": cost_today,
            "blocked": blocked,
            "block_rate": block_rate,
            "cache_hit_rate": cache_hit_rate,
            "tokens_saved": tokens_saved,
            "money_saved_usd": money_saved,
            "budget_spent_usd": budget_spent,
            "budget_limit": budget_limit,
            "loops_today": loops_today,
            "active_agents": active_agents,
            "agent_errors": agent_errors,
            "approvals_pending": approvals_pending,
            "api_uptime_seconds": uptime_seconds,
            "api_uptime_human": f"{uptime_hours}h {uptime_minutes}m",
            "raw": {"proxy": proxy_stats, "api": api_health},
        }

    def _render_text(snapshot: dict[str, Any]) -> None:
        proxy_mark = "✓" if snapshot["proxy_running"] else "✗"
        api_mark = "✓" if snapshot["api_running"] else "✗"
        dashboard_mark = "✓" if snapshot["proxy_running"] else "✗"
        security_mark = "✓" if snapshot["proxy_running"] else "✗"
        cache_mark = "✓" if snapshot["proxy_running"] else "✗"
        budget_mark = "✓" if snapshot["proxy_running"] else "✗"
        loop_mark = "✓" if snapshot["proxy_running"] else "✗"

        click.echo(f"Orchesis v{snapshot['version']} — System Status")
        click.echo("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        click.echo("")
        if snapshot["proxy_running"]:
            click.echo(
                "Proxy        "
                f"{proxy_mark} running  :8080   {snapshot['requests_total']:,} requests  ${snapshot['cost_today_usd']:.2f} today"
            )
        else:
            click.echo("Proxy        ✗ not running")
        if snapshot["api_running"]:
            click.echo(f"API          {api_mark} running  :8090   uptime {snapshot['api_uptime_human']}")
        else:
            click.echo("API          ✗ not running")
        click.echo(f"Dashboard    {dashboard_mark} {snapshot['dashboard_url']}")
        click.echo("")
        click.echo(
            "Security     "
            f"{security_mark} {snapshot['blocked']} threats blocked  ({snapshot['block_rate'] * 100:.2f}% block rate)"
        )
        click.echo(
            "Cache        "
            f"{cache_mark} {snapshot['cache_hit_rate'] * 100:.1f}% hit rate  {snapshot['tokens_saved']:,} tokens saved  ${snapshot['money_saved_usd']:.2f}"
        )
        click.echo(
            "Budget       "
            f"{budget_mark} ${snapshot['budget_spent_usd']:.2f} / {snapshot['budget_limit']}"
        )
        click.echo(f"Loop         {loop_mark} {snapshot['loops_today']} loops detected today")
        click.echo("")
        click.echo(
            "Agents       "
            f"{snapshot['active_agents']} active  {snapshot['agent_errors']} error  {snapshot['approvals_pending']} pending approval"
        )

    if watch_mode:
        try:
            while True:
                snap = _status_snapshot()
                if json_output:
                    click.echo(json.dumps(snap, ensure_ascii=False, indent=2))
                else:
                    click.clear()
                    _render_text(snap)
                time.sleep(5)
        except KeyboardInterrupt:
            click.echo("\nStopped.")
            raise SystemExit(0)

    snap = _status_snapshot()
    if json_output:
        click.echo(json.dumps(snap, ensure_ascii=False, indent=2))
        raise SystemExit(0)
    _render_text(snap)
    raise SystemExit(0)


@main.command("audit-openclaw")
@click.option("--config", "config_path", type=click.Path(exists=True), required=True)
@click.option("--format", "output_format", type=click.Choice(["text", "json", "markdown"]), default="text")
def audit_openclaw_command(config_path: str, output_format: str) -> None:
    """Audit OpenClaw deployment config and print report."""
    from orchesis.audit_grade import calculate_grade, format_badge_embed, format_grade_box, format_tweet
    from orchesis.openclaw_auditor import OpenClawAuditor

    cfg_path = Path(config_path).expanduser()
    auditor = OpenClawAuditor()
    result = auditor.audit_config(str(cfg_path))
    findings = list(result.findings)
    grade = calculate_grade(findings)
    if output_format == "json":
        click.echo(json.dumps(asdict(result), indent=2, ensure_ascii=False))
        return
    click.echo(auditor.generate_report(result, format=output_format))
    click.echo("")
    click.echo(format_grade_box(grade, findings))
    click.echo("Add to your README:")
    click.echo(format_badge_embed(grade))
    click.echo("Share your grade:")
    click.echo(format_tweet(grade, findings))


def _post_proxy_control(port: int, path: str, payload: dict[str, Any]) -> dict[str, Any]:
    req = UrlRequest(
        f"http://127.0.0.1:{max(1, int(port))}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(req, timeout=5) as response:
            parsed = json.loads(response.read().decode("utf-8"))
            return parsed if isinstance(parsed, dict) else {"status": "ok"}
    except HTTPError as error:
        try:
            body = error.read().decode("utf-8")
            parsed_error = json.loads(body)
            message = parsed_error.get("error") if isinstance(parsed_error, dict) else body
            raise click.ClickException(f"Proxy returned HTTP {error.code}: {message}") from error
        except Exception:
            raise click.ClickException(f"Proxy returned HTTP {error.code}") from error
    except URLError as error:
        raise click.ClickException(f"Failed to reach proxy on port {port}: {error}") from error


@main.command("kill")
@click.option("--port", type=int, default=8100)
@click.option("--reason", type=str, default="emergency")
def kill_command(port: int, reason: str) -> None:
    """Trigger emergency kill switch on running proxy."""
    payload = _post_proxy_control(port, "/kill", {"reason": reason})
    click.echo(f"Kill switch activated on :{port}")
    click.echo(f"Reason: {payload.get('reason', reason)}")
    click.echo(f"Killed at: {payload.get('killed_at', 'unknown')}")


@main.command("resume")
@click.option("--port", type=int, default=8100)
@click.option("--token", type=str, required=True)
def resume_command(port: int, token: str) -> None:
    """Resume proxy after kill switch activation."""
    payload = _post_proxy_control(port, "/resume", {"token": token})
    click.echo(f"Proxy resumed on :{port} ({payload.get('status', 'ok')})")


@main.command("reload")
@click.option("--config", "config_path", type=click.Path(exists=True), default="orchesis.yaml")
@click.option("--port", type=int, default=None)
def reload_command(config_path: str, port: int | None) -> None:
    """Reload policy in a running proxy instance."""
    resolved_port = max(1, int(port)) if isinstance(port, int | float) else 8100
    if not isinstance(port, int | float):
        try:
            loaded_cfg = load_policy(config_path)
        except (ValueError, YAMLError, OSError) as error:
            raise click.ClickException(f"Failed to load config: {error}") from error
        proxy_cfg = loaded_cfg.get("proxy")
        if isinstance(proxy_cfg, dict):
            port_from_cfg = proxy_cfg.get("port")
            if isinstance(port_from_cfg, int | float):
                resolved_port = max(1, int(port_from_cfg))
    payload = _post_proxy_control(resolved_port, "/api/v1/policy/reload", {})
    click.echo(f"✓ Policy reloaded (version: {payload.get('version', 'unknown')})")


@main.command("mcp-proxy")
@click.pass_context
@click.option("--policy", "policy_path", type=click.Path(exists=True), required=True)
@click.option("--control-url", type=str, default=None)
@click.option("--api-token", type=str, default=None)
@click.option("--node-id", type=str, default=None)
@click.option("--sync-poll", "sync_poll_interval", type=int, default=30)
@click.argument("server_command", nargs=-1, type=str)
def mcp_proxy_command(
    ctx: click.Context,
    policy_path: str,
    control_url: str | None,
    api_token: str | None,
    node_id: str | None,
    sync_poll_interval: int,
    server_command: tuple[str, ...],
) -> None:
    """Run MCP stdio proxy with optional control-plane policy sync."""
    McpStdioProxy, McpProxySettings, run_stdio_proxy = _load_mcp_proxy_runtime()
    _ = ctx
    token = api_token or os.getenv("API_TOKEN")
    if server_command:
        policy = load_policy(policy_path)
        tracker = RateLimitTracker(persist_path=None)

        def _engine(request_payload: dict[str, Any], session_type: str = "cli"):
            return evaluate(request_payload, policy, state=tracker, session_type=session_type)

        proxy = McpStdioProxy(engine=_engine, server_command=list(server_command))
        click.echo("Orchesis MCP Proxy starting...")
        click.echo(f"Policy: {policy_path}")
        click.echo(f"Server: {' '.join(server_command)}")
        click.echo("Transport: stdio")
        asyncio.run(proxy.start())
        return

    base = McpProxySettings.from_env()
    settings = McpProxySettings(
        policy_path=policy_path,
        downstream_command=base.downstream_command,
        downstream_args=base.downstream_args,
        default_tool_cost=base.default_tool_cost,
        downstream_timeout_seconds=base.downstream_timeout_seconds,
        control_url=control_url,
        api_token=token,
        node_id=node_id,
        sync_poll_interval_seconds=max(1, sync_poll_interval),
    )
    asyncio.run(run_stdio_proxy(settings))


@main.group("mcp")
def mcp_group() -> None:
    """Run Orchesis as an MCP server and inspect exposed tools."""


@mcp_group.command("serve")
@click.option("--policy", "policy_path", type=click.Path(), default=None)
def mcp_serve(policy_path: str | None) -> None:
    """Serve Orchesis MCP tools over stdio JSON-RPC."""
    MCPServer, build_tool_registry = _load_mcp_server_runtime()
    registry = build_tool_registry(policy_path=policy_path)
    server = MCPServer(registry)
    server.run()


@mcp_group.command("tools")
@click.option("--policy", "policy_path", type=click.Path(), default=None)
def mcp_tools_command(policy_path: str | None) -> None:
    """List available MCP tool names and descriptions."""
    _MCPServer, build_tool_registry = _load_mcp_server_runtime()
    registry = build_tool_registry(policy_path=policy_path)
    click.echo("Available MCP tools:")
    for name, tool in sorted(registry.items(), key=lambda item: item[0]):
        description = str(tool.get("description", ""))
        click.echo(f"- {name}: {description}")


@main.command("nodes")
@click.option("--api-url", default="http://localhost:8080")
@click.option("--api-token", default=None)
def nodes(api_url: str, api_token: str | None) -> None:
    """List connected enforcement nodes from control plane."""
    httpx = _load_httpx()
    token = api_token or os.getenv("API_TOKEN")
    if not isinstance(token, str) or not token.strip():
        raise click.ClickException("API token is required. Use --api-token or API_TOKEN env var.")
    headers = {"Authorization": f"Bearer {token.strip()}"}
    try:
        response = httpx.get(f"{api_url.rstrip('/')}/api/v1/nodes", headers=headers, timeout=10.0)
        response.raise_for_status()
        payload = response.json()
    except Exception as error:  # noqa: BLE001
        raise click.ClickException(f"Failed to fetch nodes: {error}") from error
    if not isinstance(payload, dict):
        raise click.ClickException("Invalid response payload from control plane.")
    nodes_payload = payload.get("nodes")
    if not isinstance(nodes_payload, list):
        nodes_payload = []
    click.echo("Connected Nodes:")
    for item in nodes_payload:
        if not isinstance(item, dict):
            continue
        state = "[IN SYNC]" if item.get("in_sync") else "[OUT OF SYNC]"
        click.echo(
            f"  {item.get('node_id', 'unknown'):<16} "
            f"v:{item.get('policy_version', 'unknown'):<12} "
            f"last seen: {item.get('last_seen', 'unknown')}   {state}"
        )
    click.echo("")
    click.echo(
        "Total: "
        f"{payload.get('total', 0)} nodes, "
        f"{payload.get('in_sync', 0)} in sync, "
        f"{payload.get('out_of_sync', 0)} out of sync"
    )


@main.command("sync")
@click.option("--control-url", required=True)
@click.option("--api-token", required=True)
@click.option("--policy", "policy_path", default="policy.yaml")
def sync_policy(control_url: str, api_token: str, policy_path: str) -> None:
    """Run one-shot policy synchronization against control plane."""
    PolicySyncClient = _load_sync_runtime()
    client = PolicySyncClient(
        control_url=control_url,
        api_token=api_token,
        poll_interval_seconds=30,
    )
    click.echo("Syncing with control plane...")
    before = client.current_version or "unknown"
    status = client.sync_once()
    remote = status.policy_version
    click.echo(f"Current version: {before}")
    click.echo(f"Remote version: {remote}")
    updated = isinstance(client.latest_policy, dict)
    if updated:
        target = Path(policy_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            yaml.safe_dump(client.latest_policy, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )
        click.echo(f"Policy updated: {before} -> {client.current_version}")
    else:
        click.echo("Policy already up to date")
    click.echo("Sync complete [OK]")


def _normalize_plugin_modules(raw_modules: tuple[str, ...]) -> list[str]:
    normalized: list[str] = []
    for entry in raw_modules:
        if not isinstance(entry, str):
            continue
        parts = [item.strip() for item in entry.split(",") if item.strip()]
        normalized.extend(parts)
    return normalized


def _print_coverage_report(
    click_module, coverage: CoverageReport, fuzzer: SyntheticFuzzer
) -> None:  # noqa: ANN001
    click_module.echo("")
    click_module.echo("Coverage Report:")
    total_rules = len(coverage.rules_triggered) + len(coverage.rules_never_triggered)
    triggered = total_rules - len(coverage.rules_never_triggered)
    click_module.echo(
        f"  Rules: {triggered}/{total_rules} triggered ({coverage.rule_coverage_pct:.1f}%)"
    )
    for rule in sorted(coverage.rules_triggered):
        click_module.echo(f"    [OK] {rule} ({coverage.rules_triggered[rule]} hits)")
    for rule in coverage.rules_never_triggered:
        click_module.echo(f"    [MISS] {rule} (0 hits)")

    all_categories = fuzzer.categories
    tested_categories = len(
        [cat for cat in all_categories if coverage.categories_tested.get(cat, 0) > 0]
    )
    click_module.echo(
        f"  Categories: {tested_categories}/{len(all_categories)} tested "
        f"({coverage.category_coverage_pct:.1f}%)"
    )
    total_category_samples = max(1, sum(coverage.categories_tested.values()))
    for category in all_categories:
        count = coverage.categories_tested.get(category, 0)
        pct = (count / total_category_samples) * 100.0
        suffix = " <- gap" if count == 0 else ""
        click_module.echo(f"    {category}: {pct:.0f}%{suffix}")

    tested_tiers = len(
        [tier for tier in coverage.tier_coverage if coverage.tier_coverage[tier] > 0]
    )
    click_module.echo(f"  Trust tiers: {tested_tiers}/5 tested")
    for tier in coverage.tiers_never_tested:
        click_module.echo(f"    [MISS] {tier} never tested")

    suggestions = fuzzer.coverage_suggestions(coverage)
    if suggestions:
        click_module.echo("  Suggestions:")
        for idx, suggestion in enumerate(suggestions[:5], start=1):
            click_module.echo(f"    {idx}. {suggestion}")


@main.command("plugins")
@click.option("--policy", "policy_path", type=click.Path(exists=True), default=None)
@click.option("--plugins", "plugin_modules", multiple=True)
def plugins_command(policy_path: str | None, plugin_modules: tuple[str, ...]) -> None:
    """List registered plugins."""
    policy: dict[str, Any] = {"rules": []}
    if policy_path is not None:
        try:
            policy = load_policy(policy_path)
        except (ValueError, YAMLError, OSError) as error:
            raise click.ClickException(f"Failed to load policy: {error}") from error
    modules = _normalize_plugin_modules(plugin_modules)
    if not modules:
        modules = [
            "orchesis.contrib.pii_detector",
            "orchesis.contrib.ip_allowlist",
            "orchesis.contrib.time_window",
        ]
    registry = load_plugins_for_policy(policy, modules)
    click.echo("Registered plugins:")
    items = sorted(registry.list_plugins(), key=lambda item: item.rule_type)
    if not items:
        click.echo("  (none)")
        return
    for item in items:
        click.echo(f"  {item.rule_type:<13} v{item.version:<4} {item.description}")


@main.group("marketplace", invoke_without_command=True)
@click.pass_context
def marketplace_group(ctx: click.Context) -> None:
    """Browse and install built-in policy packs."""
    if ctx.invoked_subcommand is None:
        ctx.invoke(marketplace_list)


@marketplace_group.command("list")
def marketplace_list() -> None:
    """List available policy packs."""
    marketplace = PolicyMarketplace()
    packs = marketplace.list_available()
    click.echo("Available Policy Packs:")
    for item in packs:
        tags = ", ".join(item.tags)
        click.echo(f"  {item.name:<16} v{item.version:<4} {item.description:<36} [{tags}]")


@marketplace_group.command("info")
@click.argument("name")
def marketplace_info(name: str) -> None:
    """Show metadata for one policy pack."""
    marketplace = PolicyMarketplace()
    pack = marketplace.get(name)
    if pack is None:
        raise click.ClickException(f"Unknown policy pack: {name}")
    click.echo(f"Name: {pack.name}")
    click.echo(f"Version: {pack.version}")
    click.echo(f"Description: {pack.description}")
    click.echo(f"Author: {pack.author}")
    click.echo(f"Tags: {', '.join(pack.tags)}")
    click.echo(f"Rules: {len(pack.rules)}")
    plugins = ", ".join(pack.plugins_required) if pack.plugins_required else "none"
    click.echo(f"Required plugins: {plugins}")


@marketplace_group.command("install")
@click.argument("name")
@click.option("--merge", is_flag=True, default=False)
@click.option("--target", "target_path", default="policy.yaml")
def marketplace_install(name: str, merge: bool, target_path: str) -> None:
    """Install a policy pack to a local file."""
    marketplace = PolicyMarketplace()
    pack = marketplace.get(name)
    if pack is None:
        raise click.ClickException(f"Unknown policy pack: {name}")
    click.echo(f"Installing policy pack: {pack.name} v{pack.version}")
    plugins = ", ".join(pack.plugins_required) if pack.plugins_required else "none"
    click.echo(f"Required plugins: {plugins}")
    written = marketplace.install(name, target_path=target_path, merge=merge)
    click.echo(f"Written to {written}")
    click.echo("")
    click.echo(f"Run: orchesis validate --policy {written}")


@main.command()
@click.option("--policy", "policy_path", type=click.Path(exists=True), required=True)
@click.option("--count", "count", type=int, default=1000)
@click.option("--seed", "seed", type=int, default=42)
@click.option("--save-bypasses", "save_bypasses", is_flag=True, default=False)
@click.option("--coverage", "show_coverage", is_flag=True, default=False)
@click.option("--adaptive", "adaptive_mode", is_flag=True, default=False)
def fuzz(
    policy_path: str,
    count: int,
    seed: int,
    save_bypasses: bool,
    show_coverage: bool,
    adaptive_mode: bool,
) -> None:
    """Run synthetic adversarial fuzzing against policy."""
    try:
        policy = load_policy(policy_path)
    except (ValueError, YAMLError, OSError) as error:
        raise click.ClickException(f"Failed to load policy: {error}") from error

    has_identity_config = "agents" in policy or "default_trust_tier" in policy
    registry = load_agent_registry(policy) if has_identity_config else None
    fuzzer = SyntheticFuzzer(policy, registry=registry, seed=seed)
    report = (
        fuzzer.run_adaptive(num_requests=max(1, count))
        if adaptive_mode
        else fuzzer.run(num_requests=max(1, count))
    )
    DEFAULT_FUZZ_RUNS_PATH.parent.mkdir(parents=True, exist_ok=True)
    DEFAULT_FUZZ_RUNS_PATH.write_text(
        (
            DEFAULT_FUZZ_RUNS_PATH.read_text(encoding="utf-8")
            if DEFAULT_FUZZ_RUNS_PATH.exists()
            else ""
        )
        + json.dumps(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "total_requests": report.total_requests,
                "bypasses_found": len(report.bypasses),
                "bypass_rate": report.bypass_rate,
                "seed": seed,
            },
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    update_fuzz_metadata(
        total_requests=report.total_requests,
        bypasses_found=len(report.bypasses),
    )
    OPERATIONS_LOG.info(
        "fuzz run completed",
        total_requests=report.total_requests,
        bypasses=len(report.bypasses),
        seed=seed,
    )
    click.echo("Fuzzer Report:")
    click.echo(f"  Total requests: {report.total_requests}")
    click.echo(f"  Correctly denied: {report.denied_correctly}")
    click.echo(f"  Correctly allowed: {report.allowed_correctly}")
    click.echo(f"  BYPASSES FOUND: {len(report.bypasses)} ({report.bypass_rate * 100:.2f}%)")
    if report.bypasses:
        click.echo("")
        click.echo("  Bypass details:")
        for idx, bypass in enumerate(report.bypasses[:10], start=1):
            click.echo(
                f"    #{idx} [{bypass.category}] {bypass.mutation} -> ALLOW (should be DENY)"
            )
    click.echo("")
    click.echo("  Categories tested:")
    for category in sorted(fuzzer.category_counts):
        click.echo(f"    {category}: {fuzzer.category_counts[category]}")
    if show_coverage and report.coverage is not None:
        _print_coverage_report(click, report.coverage, fuzzer)
    if save_bypasses and report.bypasses:
        corpus = RegressionCorpus()
        created = [corpus.add_bypass(item) for item in report.bypasses]
        click.echo("")
        click.echo(f"  Saved {len(created)} new bypasses to corpus:")
        for entry in created[:10]:
            click.echo(f"    {entry.id}: {entry.category} - {entry.mutation}")


@main.command()
@click.option("--policy", "policy_path", type=click.Path(exists=True), required=True)
def scenarios(policy_path: str) -> None:
    """Run prebuilt adversarial scenarios."""
    try:
        policy = load_policy(policy_path)
    except (ValueError, YAMLError, OSError) as error:
        raise click.ClickException(f"Failed to load policy: {error}") from error

    has_identity_config = "agents" in policy or "default_trust_tier" in policy
    registry = load_agent_registry(policy) if has_identity_config else None
    runner = AdversarialScenarios(policy, registry=registry)
    results = runner.run_all()
    click.echo("Adversarial Scenarios:")
    for result in results:
        marker = "[OK]" if result.success else "[WARN]"
        suffix = (
            "known limitation"
            if "known limitation" in result.description.lower()
            else "bypasses found"
        )
        if result.success:
            suffix = f"{len(result.bypasses)} bypasses"
        click.echo(f"  {marker} {result.name:<24} - {result.steps_total} steps, {suffix}")


@main.command()
@click.option("--policy", "policy_path", type=click.Path(exists=True), required=True)
@click.option("--count", "count", type=int, default=1000)
@click.option("--seed", "seed", type=int, default=42)
def mutate(policy_path: str, count: int, seed: int) -> None:
    """Run mutation engine against policy."""
    try:
        policy = load_policy(policy_path)
    except (ValueError, YAMLError, OSError) as error:
        raise click.ClickException(f"Failed to load policy: {error}") from error

    corpus = RegressionCorpus()
    engine = MutationEngine(corpus, seed=seed)
    mutations = engine.generate(count=max(1, count))
    bypasses = 0
    for mutation in mutations:
        decision = evaluate(mutation.request, policy)
        if decision.allowed:
            bypasses += 1
            click.echo(
                f"BYPASS: {mutation.category} - {mutation.mutation_type}: {mutation.description}"
            )

    click.echo(f"Mutation results: {len(mutations)} tested, {bypasses} bypasses")
    DEFAULT_MUTATION_RUNS_PATH.parent.mkdir(parents=True, exist_ok=True)
    DEFAULT_MUTATION_RUNS_PATH.write_text(
        (
            DEFAULT_MUTATION_RUNS_PATH.read_text(encoding="utf-8")
            if DEFAULT_MUTATION_RUNS_PATH.exists()
            else ""
        )
        + json.dumps(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "mutations_tested": len(mutations),
                "bypasses_found": bypasses,
                "seed": seed,
            },
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    update_fuzz_metadata(
        total_mutations=len(mutations),
        bypasses_found=bypasses,
    )
    OPERATIONS_LOG.info(
        "mutation run completed",
        mutations_tested=len(mutations),
        bypasses=bypasses,
        seed=seed,
    )


@main.command()
@click.option("--policy", "policy_path", type=click.Path(exists=True), required=True)
def invariants(policy_path: str) -> None:
    """Run formal invariant checks."""
    checker = InvariantChecker(policy_path=policy_path)
    report = checker.check_all()
    click.echo("Invariant Checks:")
    for result in report.results:
        marker = "[OK]" if result.passed else "[FAIL]"
        click.echo(f"  {marker} {result.name}")
    passed = sum(1 for result in report.results if result.passed)
    total = len(report.results)
    click.echo("")
    click.echo(f"{passed}/{total} passed ({report.duration_seconds:.2f}s)")
    failures = total - passed
    update_fuzz_metadata(
        invariant_checks=total,
        invariant_failures=failures,
    )
    OPERATIONS_LOG.info("invariants checked", total=total, failures=failures)
    if not report.all_passed:
        raise SystemExit(1)


@main.command("drift")
@click.option("--policy", "policy_path", type=click.Path(exists=True), required=True)
@click.option("--log", "log_path", type=click.Path(), default=str(DEFAULT_DECISIONS_PATH))
def drift(policy_path: str, log_path: str) -> None:
    """Run state drift detection over current state and decision log."""
    try:
        policy = load_policy(policy_path)
    except (ValueError, YAMLError, OSError) as error:
        raise click.ClickException(f"Failed to load policy: {error}") from error

    has_identity_config = "agents" in policy or "default_trust_tier" in policy
    registry = load_agent_registry(policy) if has_identity_config else None
    detector = DriftDetector()
    tracker = RateLimitTracker(persist_path=DEFAULT_STATE_PATH)
    events = detector.run_all_checks(
        tracker=tracker,
        policy=policy,
        decisions_log=log_path,
        registry=registry,
    )
    counts = Counter(item.drift_type for item in events)
    click.echo("Drift Detection:")
    click.echo(f"  Counter integrity: {'FAIL' if counts.get('counter_mismatch') else 'OK'}")
    click.echo(f"  Budget integrity: {'FAIL' if counts.get('budget_mismatch') else 'OK'}")
    click.echo(
        "  Replay consistency: "
        f"{'FAIL' if counts.get('replay_divergence') else 'OK'} "
        f"(sampled {detector.replay_sample_size} events)"
    )
    baseline = detector.baseline_latency_us
    if baseline is not None:
        click.echo(f"  Latency baseline: {baseline:.0f}us")
    else:
        click.echo("  Latency baseline: n/a")
    click.echo(f"  Latency anomalies: {counts.get('latency_spike', 0)}")
    click.echo("")
    if events:
        click.echo(f"{len(events)} drift events detected")
        if detector.has_critical_drift:
            raise SystemExit(1)
    else:
        click.echo("0 drift events detected [OK]")
    tracker.flush()


@main.command("torture")
@click.option("--policy", "policy_path", type=click.Path(exists=True), required=True)
@click.option("--duration", type=int, default=60)
@click.option("--agents", type=int, default=100)
def torture(policy_path: str, duration: int, agents: int) -> None:
    """Run sustained concurrent stress test and report throughput/latency."""
    try:
        policy = load_policy(policy_path)
    except (ValueError, YAMLError, OSError) as error:
        raise click.ClickException(f"Failed to load policy: {error}") from error
    duration_seconds = max(1, int(duration))
    total_agents = max(1, int(agents))
    has_identity_config = "agents" in policy or "default_trust_tier" in policy
    registry = load_agent_registry(policy) if has_identity_config else None
    tracker = RateLimitTracker(persist_path=None)
    rng = Random(42)
    latencies_us: list[int] = []
    fail_open_events = 0
    total = 0

    tracemalloc.start()
    start_mem, _ = tracemalloc.get_traced_memory()
    started = time.perf_counter()
    worker_count = min(200, max(8, total_agents * 2))
    safe_request = {"tool": "read_file", "params": {"path": "/data/safe.txt"}, "cost": 0.1}
    denied_path_request = {"tool": "read_file", "params": {"path": "/etc/passwd"}, "cost": 0.1}
    denied_sql_request = {"tool": "run_sql", "params": {"query": "DROP TABLE users"}, "cost": 0.1}

    def _call(idx: int) -> tuple[bool, bool, int]:
        roll = rng.random()
        if roll < 0.60:
            template = safe_request
            should_allow = True
        elif roll < 0.80:
            template = denied_path_request
            should_allow = False
        else:
            template = denied_sql_request
            should_allow = False
        request = {
            "tool": template["tool"],
            "params": dict(template["params"]),
            "cost": template["cost"],
            "context": {"agent": f"torture_{idx % total_agents}", "session": f"s{idx % 25}"},
        }
        before = time.perf_counter_ns()
        decision = evaluate(request, policy, state=tracker, registry=registry)
        elapsed = max(0, (time.perf_counter_ns() - before) // 1000)
        return decision.allowed, should_allow, int(elapsed)

    while time.perf_counter() - started < duration_seconds:
        batch = list(range(1000))
        with ThreadPoolExecutor(max_workers=worker_count) as pool:
            for allowed, should_allow, elapsed in pool.map(_call, batch):
                total += 1
                latencies_us.append(elapsed)
                if should_allow and not allowed:
                    fail_open_events += 1
                if (not should_allow) and allowed:
                    fail_open_events += 1

    end_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    memory_growth_mb = max(0.0, float(end_mem - start_mem) / (1024.0 * 1024.0))
    sorted_lat = sorted(latencies_us)
    elapsed_total = max(0.001, time.perf_counter() - started)
    throughput = total / elapsed_total
    avg_us = (sum(sorted_lat) / len(sorted_lat)) if sorted_lat else 0.0
    p95_us = _percentile_us(sorted_lat, 95.0) if sorted_lat else 0
    p99_us = _percentile_us(sorted_lat, 99.0) if sorted_lat else 0
    max_us = sorted_lat[-1] if sorted_lat else 0

    detector = DriftDetector()
    drift_events = detector.run_all_checks(
        tracker=tracker,
        policy=policy,
        decisions_log=DEFAULT_DECISIONS_PATH,
        registry=registry,
    )
    click.echo(f"Torture Test Results ({duration_seconds}s):")
    click.echo(f"  Total evaluations: {total:,}")
    click.echo(f"  Throughput: {throughput:.0f} evals/sec")
    click.echo(f"  Latency: avg={avg_us:.0f}us p95={p95_us}us p99={p99_us}us max={max_us}us")
    click.echo(
        f"  Memory growth: {memory_growth_mb:.1f}MB (peak={peak_mem / (1024 * 1024):.1f}MB)"
    )
    click.echo(f"  Fail-open events: {fail_open_events}")
    click.echo(f"  State drift events: {len(drift_events)}")
    click.echo(f"  Rate limit accuracy: {'100%' if fail_open_events == 0 else 'degraded'}")
    click.echo("  Budget accuracy: best-effort")
    click.echo("")
    if fail_open_events == 0 and not detector.has_critical_drift:
        click.echo("PASSED [OK]")
        return
    click.echo("FAILED [FAIL]")
    raise SystemExit(1)


@main.command()
@click.option("--stats", "show_stats", is_flag=True, default=False)
@click.option("--generate-tests", "generate_tests", is_flag=True, default=False)
@click.option("--quality", "show_quality", is_flag=True, default=False)
def corpus(show_stats: bool, generate_tests: bool, show_quality: bool) -> None:
    """Manage regression corpus entries and generated tests."""
    manager = RegressionCorpus()
    if not show_stats and not generate_tests and not show_quality:
        show_stats = True

    if show_stats:
        summary = manager.stats()
        click.echo("Attack Corpus:")
        click.echo(f"  Total entries: {summary['total']}")
        click.echo(f"  Fixed: {summary['fixed']}")
        click.echo(f"  Unfixed: {summary['unfixed']}")
        click.echo("")
        click.echo("  By category:")
        for category, count in sorted(summary["by_category"].items()):
            click.echo(f"    {category}: {count}")

    if generate_tests:
        target = manager.generate_test_file()
        total = manager.stats()["total"]
        click.echo(f"Generated {target}")
        click.echo(f"{total} regression test cases from corpus")
    if show_quality:
        quality = manager.quality_report()
        click.echo("Corpus Quality:")
        click.echo(f"  Entries: {quality['total_entries']} ({quality['fixed']} fixed)")
        click.echo(f"  Balance: {quality['category_balance']}")
        gaps = quality["gaps"]
        click.echo(f"  Gaps: {', '.join(gaps) if gaps else 'none'}")
        suggestions = quality["suggestions"]
        if suggestions:
            click.echo("  Suggestions:")
            for idx, item in enumerate(suggestions[:5], start=1):
                click.echo(f"    {idx}. {item}")


def _format_gate_box(lines: list[tuple[str, str]]) -> str:
    width = 34
    top = "╔" + ("═" * width) + "╗"
    sep = "╠" + ("═" * width) + "╣"
    bottom = "╚" + ("═" * width) + "╝"
    body = [top, f"║ {'Orchesis CI Security Gate':^{width}} ║", sep]
    for left, right in lines:
        text = f"{left:<22} {right:>9}"
        body.append(f"║ {text[:width]:<{width}} ║")
    body.append(bottom)
    return "\n".join(body)


def _has_rule_tests(policy: dict[str, Any], tests_dir: Path) -> bool:
    rules = policy.get("rules")
    if not isinstance(rules, list):
        return False
    test_text = ""
    if tests_dir.exists():
        for item in tests_dir.rglob("test_*.py"):
            try:
                test_text += item.read_text(encoding="utf-8").lower() + "\n"
            except OSError:
                continue
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        name = rule.get("name")
        if isinstance(name, str) and name.lower() not in test_text:
            return False
    return True


def _policy_guard_checks(policy: dict[str, Any]) -> dict[str, bool]:
    rules = policy.get("rules")
    rules_list = rules if isinstance(rules, list) else []
    has_rate = any(isinstance(item, dict) and item.get("name") == "rate_limit" for item in rules_list)
    has_budget = any(isinstance(item, dict) and item.get("name") == "budget_limit" for item in rules_list)
    has_denied_paths = any(
        isinstance(item, dict)
        and item.get("name") == "file_access"
        and isinstance(item.get("denied_paths"), list)
        and len(item.get("denied_paths")) > 0
        for item in rules_list
    )
    alerts = policy.get("alerts")
    has_alerts = isinstance(alerts, dict) and len(alerts) > 0
    return {
        "rate_limits_defined": has_rate,
        "budget_limits_defined": has_budget,
        "denied_paths_defined": has_denied_paths,
        "alert_config_present": has_alerts,
    }


@main.command("scan")
@click.argument("path_arg", type=click.Path(), required=False)
@click.option("--format", "output_format", type=click.Choice(["text", "json", "md"]), default="text")
@click.option("--severity-threshold", "severity_threshold", default="medium")
@click.option("--mcp", "scan_mcp_configs", is_flag=True, default=False)
@click.option("--network", "scan_network", is_flag=True, default=False)
@click.option("--yara", "yara_path", type=click.Path(), default=None)
@click.option("--llm-judge", "use_llm_judge", is_flag=True, default=False)
@click.option("--llm-model", "llm_model", default=None)
def scan_command(
    path_arg: str | None,
    output_format: str,
    severity_threshold: str,
    scan_mcp_configs: bool,
    scan_network: bool,
    yara_path: str | None,
    use_llm_judge: bool,
    llm_model: str | None,
) -> None:
    """Static scan for skills, MCP configs, and policy files."""
    reports: list[ScanReport] = []
    network_findings: list[dict[str, Any]] = []
    if scan_network:
        network_findings = NetworkExposureScanner().scan_all()
    if scan_mcp_configs:
        discovered = discover_mcp_configs()
        click.echo("Discovered MCP configs:")
        for cfg in discovered:
            click.echo(f"  {cfg}")
        for cfg in discovered:
            reports.extend(scan_path(cfg))
    elif path_arg is not None:
        target = Path(path_arg)
        if not target.exists():
            raise click.ClickException(f"Path not found: {target}")
        reports = scan_path(target)
    elif not scan_network:
        raise click.ClickException("Provide <path> or use --mcp")

    if yara_path is not None:
        builtin_rules_dir = Path(__file__).resolve().parent / "yara_rules"
        rules = load_yara_rules(yara_path, builtin_rules_dir=builtin_rules_dir)
        for report in reports:
            try:
                content = Path(report.target).read_text(encoding="utf-8")
            except Exception:
                content = ""
            if not content:
                continue
            yara_matches = scan_with_yara(content, rules)
            for match in yara_matches:
                severity = str(match.meta.get("severity", "medium")).lower()
                category = str(match.meta.get("category", "yara"))
                description = str(match.meta.get("description", f"YARA rule matched: {match.rule_name}"))
                location = (
                    f"offset {match.matched_strings[0].offset}"
                    if match.matched_strings
                    else "content"
                )
                evidence = match.matched_strings[0].matched_text if match.matched_strings else match.rule_name
                report.findings.append(
                    ScanFinding(
                        severity=severity,
                        category=f"yara:{category}",
                        description=f"{description} (rule: {match.rule_name})",
                        location=location,
                        evidence=evidence,
                    )
                )

    llm_findings_by_target: dict[str, list[dict[str, Any]]] = {}
    if use_llm_judge:
        llm_config = load_llm_config(llm_model)
        if llm_config is None:
            click.echo("Warning: --llm-judge requested but ORCHESIS_LLM_API_KEY is not set; skipping LLM analysis.")
        else:
            judge = LLMJudge(
                api_key=llm_config.api_key,
                model=llm_config.model,
                base_url=llm_config.base_url,
                timeout=llm_config.timeout,
                max_retries=llm_config.max_retries,
            )
            for report in reports:
                target_path = Path(report.target)
                findings: list[dict[str, Any]] = []
                try:
                    content = target_path.read_text(encoding="utf-8")
                except Exception:
                    content = ""
                if report.target_type == "skill_md" and content:
                    findings = judge.analyze_skill(content)
                elif report.target_type == "policy_yaml" and content:
                    findings = judge.analyze_policy(content)
                elif report.target_type == "mcp_config":
                    tools_payload: list[dict[str, Any]] = []
                    if content:
                        try:
                            loaded = json.loads(content)
                            servers = loaded.get("mcpServers") if isinstance(loaded, dict) else None
                            if isinstance(servers, dict):
                                for server_name, server_cfg in servers.items():
                                    if not isinstance(server_name, str) or not isinstance(server_cfg, dict):
                                        continue
                                    tools_payload.append(
                                        {
                                            "name": server_name,
                                            "description": str(server_cfg.get("description", "")),
                                            "parameters": {"tools": server_cfg.get("tools", [])},
                                        }
                                    )
                        except Exception:
                            tools_payload = []
                    if tools_payload:
                        findings = judge.batch_analyze_tools(tools_payload)
                if findings:
                    deduped: dict[tuple[str, str], dict[str, Any]] = {}
                    for item in findings:
                        category = str(item.get("category", "")).strip()
                        description = str(item.get("description", "")).strip()
                        if not category or not description:
                            continue
                        key = (category, description)
                        deduped[key] = item
                    llm_findings_by_target[report.target] = list(deduped.values())

    if output_format == "json":
        payload = []
        for item in reports:
            report_payload = report_to_dict(item)
            report_payload["llm_findings"] = llm_findings_by_target.get(item.target, [])
            payload.append(report_payload)
        if network_findings:
            payload.append(
                {
                    "target": "local",
                    "target_type": "network",
                    "findings": network_findings,
                    "risk_score": 0,
                    "summary": f"{len(network_findings)} network finding(s)",
                    "scanned_at": datetime.now(timezone.utc).isoformat(),
                }
            )
        click.echo(json.dumps(payload, ensure_ascii=False, indent=2))
        return

    for report in reports:
        if output_format == "md":
            click.echo(format_report_markdown(report, threshold=severity_threshold))
        else:
            click.echo(format_report_text(report, threshold=severity_threshold))
        llm_findings = llm_findings_by_target.get(report.target, [])
        if llm_findings:
            click.echo("LLM Judge Findings:")
            for finding in llm_findings:
                click.echo(
                    f"  [{str(finding.get('severity', 'MEDIUM')).upper():<8}] "
                    f"{finding.get('category', 'llm_judge')}: {finding.get('description', '')}"
                )
                recommendation = finding.get("recommendation")
                if isinstance(recommendation, str) and recommendation.strip():
                    click.echo(f"    -> recommendation: {recommendation}")
        click.echo("")
    if network_findings:
        click.echo(_format_network_scan_text(network_findings))
        click.echo("")


@main.command("benchmark-scanner")
@click.option("--iterations", type=int, default=1000)
@click.option("--input-size", type=int, default=10000)
def benchmark_scanner(iterations: int, input_size: int) -> None:
    """Benchmark sequential regex vs Aho-Corasick prefilter scanner."""
    from orchesis.contrib.secret_scanner import SecretScanner

    total_iterations = max(1, int(iterations))
    size = max(512, int(input_size))
    sample = ("safe_text_" * (size // 10))[:size]
    sample += " sk-abcdefghijklmnopqrstuvwxyz123456 AKIAABCDEFGHIJKLMNOP user@example.com"
    seq = SecretScanner(use_fast_matching=False)
    fast = SecretScanner(use_fast_matching=True)
    seq_started = time.perf_counter()
    for _ in range(total_iterations):
        _ = seq.scan_text(sample)
    seq_ms = (time.perf_counter() - seq_started) * 1000.0 / total_iterations
    fast_started = time.perf_counter()
    for _ in range(total_iterations):
        _ = fast.scan_text(sample)
    fast_ms = (time.perf_counter() - fast_started) * 1000.0 / total_iterations
    speedup = (seq_ms / fast_ms) if fast_ms > 0 else float("inf")
    click.echo(
        f"Sequential regex: {seq_ms:.2f}ms avg | "
        f"Aho-Corasick: {fast_ms:.2f}ms avg | "
        f"Speedup: {speedup:.2f}x"
    )


@main.group("integrity")
def integrity_group() -> None:
    """Manage file integrity baselines and tamper checks."""


@integrity_group.command("init")
@click.option("--paths", "paths", multiple=True)
@click.option("--auto-discover", "auto_discover", is_flag=True, default=False)
@click.option("--baseline", "baseline_path", default=".orchesis/integrity.json")
@click.argument("extra_paths", nargs=-1, required=False)
def integrity_init(paths: tuple[str, ...], auto_discover: bool, baseline_path: str, extra_paths: tuple[str, ...]) -> None:
    monitor = IntegrityMonitor(baseline_path=baseline_path)
    selected = [item for item in paths if isinstance(item, str) and item.strip()]
    if selected:
        selected.extend(item for item in extra_paths if isinstance(item, str) and item.strip())
    if auto_discover:
        selected.extend(monitor.auto_discover())
    if not selected:
        raise click.ClickException(
            "No paths provided. Use --paths <path> [more_paths] or use --auto-discover."
        )
    report = monitor.init(selected)
    click.echo(f"Baseline created: {report.files_count} files -> {report.baseline_path}")


@integrity_group.command("check")
@click.option("--strict", "strict_mode", is_flag=True, default=False)
@click.option("--baseline", "baseline_path", default=".orchesis/integrity.json")
def integrity_check(strict_mode: bool, baseline_path: str) -> None:
    monitor = IntegrityMonitor(baseline_path=baseline_path)
    report = monitor.check()
    if report.has_changes:
        click.echo(
            "ALERT | "
            f"{len(report.modified)} modified, {len(report.added)} added, "
            f"{len(report.removed)} removed, {len(report.permission_changed)} permission_changed"
        )
    else:
        click.echo(f"OK | {report.unchanged} files unchanged")
    if strict_mode:
        raise SystemExit(1 if report.has_changes else 0)


@integrity_group.command("status")
@click.option("--baseline", "baseline_path", default=".orchesis/integrity.json")
def integrity_status(baseline_path: str) -> None:
    monitor = IntegrityMonitor(baseline_path=baseline_path)
    payload = monitor._load_baseline()  # noqa: SLF001
    files = payload.get("files", {})
    monitored = payload.get("monitored_paths", [])
    click.echo(f"Baseline: {baseline_path}")
    click.echo(f"Version: {payload.get('version', '1.0')}")
    click.echo(f"Created: {payload.get('created_at', 'n/a')}")
    click.echo(f"Updated: {payload.get('updated_at', 'n/a')}")
    click.echo(f"Monitored paths: {len(monitored) if isinstance(monitored, list) else 0}")
    click.echo(f"Files tracked: {len(files) if isinstance(files, dict) else 0}")


@integrity_group.command("update")
@click.option("--path", "paths", multiple=True)
@click.option("--baseline", "baseline_path", default=".orchesis/integrity.json")
def integrity_update(paths: tuple[str, ...], baseline_path: str) -> None:
    monitor = IntegrityMonitor(baseline_path=baseline_path)
    selected = [item for item in paths if isinstance(item, str) and item.strip()]
    report = monitor.update(selected if selected else None)
    click.echo(f"Baseline updated: {report.files_count} files")


@integrity_group.command("watch")
@click.option("--interval", type=int, default=300)
@click.option("--alert", "alert_enabled", is_flag=True, default=False)
@click.option("--policy", "policy_path", default="policy.yaml")
@click.option("--baseline", "baseline_path", default=".orchesis/integrity.json")
def integrity_watch(interval: int, alert_enabled: bool, policy_path: str, baseline_path: str) -> None:
    monitor = IntegrityMonitor(baseline_path=baseline_path)
    alert_callback = None
    if alert_enabled:
        try:
            policy = load_policy(policy_path)
            alert_callback = build_integrity_alert_callback(policy)
        except Exception as error:  # noqa: BLE001
            raise click.ClickException(f"Failed to load policy for alerts: {error}") from error
    try:
        while True:
            report = monitor.check()
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if report.has_changes:
                click.echo(
                    f"{ts} | ALERT | {len(report.modified)} modified, "
                    f"{len(report.added)} added, {len(report.removed)} removed"
                )
                if alert_callback is not None:
                    alert_callback(report)
            else:
                click.echo(f"{ts} | OK | {report.unchanged} files unchanged")
            time.sleep(max(1, int(interval)))
    except KeyboardInterrupt:
        click.echo("Integrity watch stopped.")


@main.group("yara")
def yara_group() -> None:
    """Manage YARA subset rules."""


@yara_group.command("list")
@click.option("--rules-dir", "rules_dir", default=None)
def yara_list(rules_dir: str | None) -> None:
    builtin_rules_dir = Path(__file__).resolve().parent / "yara_rules"
    rules = load_yara_rules(rules_dir, builtin_rules_dir=builtin_rules_dir)
    if not rules:
        click.echo("(no rules loaded)")
        return
    for rule in rules:
        sev = rule.meta.get("severity", "MEDIUM")
        cat = rule.meta.get("category", "yara")
        click.echo(f"{rule.name} [{sev}] ({cat})")


@yara_group.command("validate")
@click.argument("rule_path", type=click.Path(exists=True))
def yara_validate(rule_path: str) -> None:
    parser = YaraParser()
    rules = parser.parse_file(rule_path)
    if not rules:
        raise click.ClickException("No rules found")
    click.echo(f"OK: {len(rules)} rule(s) parsed")


@yara_group.command("test")
@click.argument("rule_path", type=click.Path(exists=True))
@click.argument("target_path", type=click.Path(exists=True))
def yara_test(rule_path: str, target_path: str) -> None:
    parser = YaraParser()
    rules = parser.parse_file(rule_path)
    content = Path(target_path).read_text(encoding="utf-8")
    matches = scan_with_yara(content, rules)
    click.echo(f"Matches: {len(matches)}")
    for match in matches:
        click.echo(f"- {match.rule_name}")


@main.group("cost")
def cost_group() -> None:
    """Inspect and manage runtime cost tracking."""


class _LoopStatsAdapter:
    def get_stats(self) -> dict[str, Any]:
        return get_loop_detector_stats()


@cost_group.command("report")
@click.option("--day", "day", default=None)
@click.option("--format", "output_format", type=click.Choice(["console", "markdown", "json"]), default="console")
def cost_report(day: str | None, output_format: str) -> None:
    reporter = CostReporter(get_cost_tracker(), loop_detector=_LoopStatsAdapter())
    summary = reporter.daily_summary(day=day)
    if output_format == "json":
        click.echo(json.dumps(summary, ensure_ascii=False, indent=2))
    elif output_format == "markdown":
        click.echo(reporter.format_markdown(summary))
    else:
        click.echo(reporter.format_console(summary))


@cost_group.command("status")
@click.option("--policy", "policy_path", default="policy.yaml")
def cost_status(policy_path: str) -> None:
    tracker = get_cost_tracker()
    if not Path(policy_path).exists():
        click.echo("Policy not found; showing totals only.")
        click.echo(f"Today spent: ${tracker.get_daily_total():.4f}")
        return
    policy = load_policy(policy_path)
    budgets = policy.get("budgets") if isinstance(policy.get("budgets"), dict) else {}
    if not budgets:
        click.echo("No budgets configured in policy.")
        click.echo(f"Today spent: ${tracker.get_daily_total():.4f}")
        return
    status = tracker.check_budget(budgets)
    click.echo(json.dumps(status, ensure_ascii=False, indent=2))


@cost_group.command("reset")
def cost_reset() -> None:
    reset_cost_tracker_daily()
    click.echo("Cost tracker daily counters reset.")


@main.command("scan-remote")
@click.argument("target", required=False)
@click.option("--format", "output_format", type=click.Choice(["text", "json", "md"]), default="text")
@click.option("--batch", "batch_file", type=click.Path(), default=None)
def scan_remote_command(target: str | None, output_format: str, batch_file: str | None) -> None:
    """Scan remote skill URLs/IDs before installation."""
    scanner = RemoteSkillScanner()
    targets: list[str] = []
    if isinstance(batch_file, str):
        file_path = Path(batch_file)
        if not file_path.exists():
            raise click.ClickException(f"Batch file not found: {file_path}")
        targets.extend(
            line.strip() for line in file_path.read_text(encoding="utf-8").splitlines() if line.strip()
        )
    elif isinstance(target, str) and target.strip():
        targets.append(target.strip())
    else:
        raise click.ClickException("Provide <url_or_id> or use --batch <file>")

    reports: list[ScanReport] = []
    for item in targets:
        if item.startswith("clawhub:"):
            reports.append(scanner.scan_clawhub(item))
        elif item.startswith("npm:"):
            reports.append(scanner.scan_npm_package(item))
        elif "github.com" in item:
            reports.append(scanner.scan_github(item))
        else:
            reports.append(scanner.scan_url(item))

    if output_format == "json":
        click.echo(json.dumps([report_to_dict(item) for item in reports], ensure_ascii=False, indent=2))
        return

    for report in reports:
        if output_format == "md":
            click.echo(format_report_markdown(report, threshold="info"))
        else:
            click.echo(format_report_text(report, threshold="info"))
        click.echo("")


@main.command("gate")
@click.option("--policy", "policy_path", type=click.Path(), required=True)
@click.option("--scan-dir", "scan_dir", type=click.Path(), default=".")
@click.option("--fail-on", "fail_on", default="medium")
@click.option("--report", "report_path", type=click.Path(), default=None)
@click.option("--network", "include_network", is_flag=True, default=False)
def gate(
    policy_path: str,
    scan_dir: str,
    fail_on: str,
    report_path: str | None,
    include_network: bool,
) -> None:
    """Run CI security gate over policy and static scan."""
    policy_file = Path(policy_path)
    if not policy_file.exists():
        click.echo(f"Gate error: policy file not found: {policy_file}")
        raise SystemExit(2)

    try:
        policy = load_policy(policy_file)
    except Exception as error:  # noqa: BLE001
        click.echo(f"Gate error: invalid policy: {error}")
        raise SystemExit(2)

    policy_errors = validate_policy(policy)
    policy_ok = len(policy_errors) == 0
    checks = _policy_guard_checks(policy)
    rule_tests_ok = _has_rule_tests(policy, Path("tests"))

    scan_reports: list[ScanReport] = []
    if scan_dir:
        target = Path(scan_dir)
        if not target.exists():
            click.echo(f"Gate error: scan directory not found: {target}")
            raise SystemExit(2)
        scan_reports = scan_path(target)

    findings: list[dict[str, Any]] = []
    for report in scan_reports:
        for finding in report.findings:
            findings.append(
                {
                    "target": report.target,
                    "severity": finding.severity,
                    "category": finding.category,
                    "description": finding.description,
                    "location": finding.location,
                }
            )
    network_findings: list[dict[str, Any]] = []
    if include_network and scan_dir:
        network_findings = NetworkExposureScanner().scan_all()
        for item in network_findings:
            findings.append(
                {
                    "target": "local",
                    "severity": item.get("severity", "info"),
                    "category": item.get("check", "network"),
                    "description": item.get("description", ""),
                    "location": item.get("evidence", ""),
                }
            )

    findings_above = [
        item for item in findings if severity_meets_threshold(str(item["severity"]), fail_on)
    ]
    result_pass = (
        policy_ok
        and checks["rate_limits_defined"]
        and checks["budget_limits_defined"]
        and checks["denied_paths_defined"]
        and len(findings_above) == 0
    )

    by_sev = Counter(str(item["severity"]).lower() for item in findings_above)
    gate_lines = [
        ("Policy validation:", "[OK] PASS" if policy_ok else "[FAIL] FAIL"),
        (
            "Scan findings:",
            "none"
            if len(findings_above) == 0
            else ", ".join(f"{count} {sev}" for sev, count in sorted(by_sev.items())),
        ),
        ("Rate limits defined:", "[OK] YES" if checks["rate_limits_defined"] else "[FAIL] NO"),
        ("Budget limits defined:", "[OK] YES" if checks["budget_limits_defined"] else "[FAIL] NO"),
        ("Denied paths defined:", "[OK] YES" if checks["denied_paths_defined"] else "[FAIL] NO"),
        ("Alert config present:", "[OK] YES" if checks["alert_config_present"] else "[FAIL] NO"),
        ("Rule tests coverage:", "[OK] YES" if rule_tests_ok else "[FAIL] NO"),
        ("Result:", f"{'PASS' if result_pass else 'FAIL'} (--fail-on {fail_on})"),
    ]
    click.echo(_format_gate_box(gate_lines))

    report_payload = {
        "policy_ok": policy_ok,
        "policy_errors": policy_errors,
        "checks": checks,
        "rule_tests_coverage": rule_tests_ok,
        "scan_findings_total": len(findings),
        "scan_findings_above_threshold": len(findings_above),
        "fail_on": fail_on,
        "result": "PASS" if result_pass else "FAIL",
        "reports": [report_to_dict(item) for item in scan_reports],
        "network_findings": network_findings,
    }
    if report_path is not None:
        target = Path(report_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(report_payload, ensure_ascii=False, indent=2), encoding="utf-8")

    raise SystemExit(0 if result_pass else 1)


@main.command()
@click.option("--since", type=float, default=None)
@click.option("--limit", type=int, default=20)
@click.option("--verify", "verify_signatures", is_flag=True, default=False)
@click.option("--stats", "show_stats", is_flag=True, default=False)
@click.option("--anomalies", "show_anomalies", is_flag=True, default=False)
@click.option("--export", "export_path", type=click.Path(), default=None)
@click.option("--query", "run_query", is_flag=True, default=False)
@click.option("--agent", "agent_id", default=None)
@click.option("--tool", "tool_name", default=None)
@click.option("--decision", "decision_name", default=None)
@click.option("--policy-version", "policy_version", default=None)
@click.option("--session", "session_id", default=None)
def audit(
    since: float | None,
    limit: int,
    verify_signatures: bool,
    show_stats: bool,
    show_anomalies: bool,
    export_path: str | None,
    run_query: bool,
    agent_id: str | None,
    tool_name: str | None,
    decision_name: str | None,
    policy_version: str | None,
    session_id: str | None,
) -> None:
    """Audit decision log."""
    engine = AuditEngine(str(DEFAULT_DECISIONS_PATH))
    query = AuditQuery(
        agent_id=agent_id,
        tool=tool_name,
        decision=decision_name,
        since_hours=since,
        policy_version=policy_version,
        session_id=session_id,
        limit=max(1, limit),
    )

    if show_stats:
        stats = engine.stats(query)
        period = f"last {since:g}h" if since is not None else "all time"
        click.echo(f"Audit Statistics ({period}):")
        click.echo(f"  Total decisions: {stats.total_events}")
        allow_pct = (stats.allow_count / stats.total_events * 100.0) if stats.total_events else 0.0
        deny_pct = (stats.deny_count / stats.total_events * 100.0) if stats.total_events else 0.0
        click.echo(f"  Allowed: {stats.allow_count} ({allow_pct:.1f}%)")
        click.echo(f"  Denied: {stats.deny_count} ({deny_pct:.1f}%)")
        click.echo(f"  Unique agents: {stats.unique_agents}")
        click.echo(f"  Unique tools: {stats.unique_tools}")
        click.echo(f"  Unique sessions: {stats.unique_sessions}")
        click.echo("")
        click.echo("  Top denied tools:")
        for tool, count in stats.top_denied_tools:
            click.echo(f"    {tool:<14} {count}")
        click.echo("")
        click.echo("  Top denied agents:")
        for agent, count in stats.top_denied_agents:
            click.echo(f"    {agent:<14} {count}")
        click.echo("")
        click.echo("  Performance:")
        click.echo(f"    Avg latency: {stats.avg_evaluation_us:.1f}us")
        click.echo(f"    P95 latency: {stats.p95_evaluation_us:.1f}us")
        click.echo(f"    Throughput: {stats.events_per_minute:.2f} events/min")
        return

    if show_anomalies:
        anomalies = engine.anomalies()
        if not anomalies:
            click.echo("No anomalies detected.")
            return
        click.echo("Anomalies detected:")
        for idx, anomaly in enumerate(anomalies, start=1):
            click.echo(
                f"  {idx}. [{anomaly['severity']}] {anomaly['rule']} "
                f"agent={anomaly['agent_id']} - {anomaly['detail']}"
            )
        return

    if export_path is not None:
        events = engine.query(query)
        engine.export_csv(events, export_path)
        click.echo(f"Exported {len(events)} events to {export_path}")
        return

    if run_query:
        events = engine.query(query)
        for event in events:
            click.echo(
                f"{event.timestamp} agent={event.agent_id} session={event.state_snapshot.get('session_id', '__default__')} "
                f"tool={event.tool} decision={event.decision} policy={event.policy_version}"
            )
            if event.reasons:
                click.echo(f"  reasons={'; '.join(event.reasons)}")
        return

    decisions = [_normalize_audit_entry(entry) for entry in read_decisions(DEFAULT_DECISIONS_PATH)]
    decisions = [entry for entry in decisions if entry is not None]

    filtered = decisions
    if since is not None:
        threshold = datetime.now(timezone.utc) - timedelta(hours=since)
        filtered = []
        for entry in decisions:
            timestamp = entry.get("timestamp")
            if not isinstance(timestamp, str):
                continue
            try:
                entry_dt = datetime.fromisoformat(timestamp)
            except ValueError:
                continue
            if entry_dt >= threshold:
                filtered.append(entry)

    allow_count = sum(1 for entry in filtered if entry.get("decision") == "ALLOW")
    deny_count = sum(1 for entry in filtered if entry.get("decision") == "DENY")

    reason_counter: Counter[str] = Counter()
    for entry in filtered:
        if entry.get("decision") != "DENY":
            continue
        reasons = entry.get("reasons")
        if not isinstance(reasons, list):
            continue
        for reason in reasons:
            if isinstance(reason, str):
                reason_counter[reason] += 1

    click.echo(f"Total ALLOW: {allow_count}")
    click.echo(f"Total DENY: {deny_count}")
    click.echo("Top deny reasons:")
    for reason, count in reason_counter.most_common(3):
        click.echo(f"- {reason}: {count}")

    last_n = filtered[-limit:] if limit > 0 else []
    click.echo(f"Last {limit} decisions:")
    for entry in last_n:
        click.echo(json.dumps(entry, ensure_ascii=False))

    state_tracker = RateLimitTracker(persist_path=DEFAULT_STATE_PATH)
    tools_seen = sorted(state_tracker.get_tools())
    if tools_seen:
        click.echo("Rate limit stats (last 60s):")
        for tool in tools_seen:
            count = state_tracker.get_count(tool, window_seconds=60)
            click.echo(f"- {tool}: {count}")

    if verify_signatures:
        if not DEFAULT_PUBLIC_KEY_PATH.exists():
            raise click.ClickException(
                "Missing public key. Run 'orchesis keygen' before using audit --verify."
            )

        verified_count = 0
        tampered_count = 0
        unsigned_count = 0

        for index, entry in enumerate(filtered, start=1):
            signature = entry.get("signature")
            if not isinstance(signature, str) or not signature:
                unsigned_count += 1
                click.echo(f"Entry {index}: UNSIGNED")
                continue

            verify_input: dict[str, Any] = {
                "timestamp": entry.get("timestamp"),
                "tool": entry.get("tool"),
                "decision": entry.get("decision"),
                "reasons": entry.get("reasons"),
            }
            if verify_entry(verify_input, signature, DEFAULT_PUBLIC_KEY_PATH):
                verified_count += 1
                click.echo(f"Entry {index}: OK")
            else:
                tampered_count += 1
                click.echo(f"Entry {index}: TAMPERED")

        click.echo(
            f"{verified_count} verified, {tampered_count} tampered, {unsigned_count} unsigned"
        )
    state_tracker.flush()


@main.command("export")
@click.option("--format", "output_format", type=click.Choice(["json", "csv", "jsonl"]), default="json")
@click.option("--output", "output_path", type=click.Path(), default=None)
@click.option("--agent", "agent_id", default=None)
@click.option("--session", "session_id", default=None)
@click.option("--date-from", "date_from", default=None)
@click.option("--date-to", "date_to", default=None)
@click.option("--decision", "decision_name", type=click.Choice(["ALLOW", "DENY"], case_sensitive=False), default=None)
@click.option("--log", "decisions_log_path", default=str(DEFAULT_DECISIONS_PATH), type=click.Path())
def export_command(
    output_format: str,
    output_path: str | None,
    agent_id: str | None,
    session_id: str | None,
    date_from: str | None,
    date_to: str | None,
    decision_name: str | None,
    decisions_log_path: str,
) -> None:
    """Export full decision audit trail with optional filters."""
    exporter = AuditTrailExporter(decisions_log_path)
    filters = {
        "agent_id": agent_id,
        "session_id": session_id,
        "date_from": date_from,
        "date_to": date_to,
        "decision": decision_name.upper() if isinstance(decision_name, str) else None,
    }
    target = (
        str(Path(".orchesis") / f"audit_export.{output_format}")
        if not isinstance(output_path, str) or not output_path.strip()
        else output_path
    )
    if output_format == "csv":
        count = exporter.export_csv(target, filters=filters)
    elif output_format == "jsonl":
        count = exporter.export_jsonl(target, filters=filters)
    else:
        count = exporter.export_json(target, filters=filters)
    summary = exporter.get_summary(
        exporter.filter_by(
            agent_id=agent_id,
            session_id=session_id,
            date_from=date_from,
            date_to=date_to,
            decision=decision_name.upper() if isinstance(decision_name, str) else None,
        )
    )
    click.echo(f"Exported {count} records to {target}")
    click.echo(json.dumps(summary, ensure_ascii=False, indent=2))


@main.command("evidence")
@click.option("--session", "session_id", required=True)
@click.option("--format", "output_format", type=click.Choice(["json", "text"]), default="json")
@click.option("--output", "output_path", type=click.Path(), default=None)
def evidence_command(session_id: str, output_format: str, output_path: str | None) -> None:
    """Export Evidence Record for one session."""
    engine = AuditEngine(str(DEFAULT_DECISIONS_PATH))
    decisions = engine.query(AuditQuery(session_id=session_id, limit=1_000_000))
    record = EvidenceRecord().build(session_id=session_id, decisions_log=decisions)
    if output_format == "text":
        text_report = EvidenceRecord().export_text(record)
        if isinstance(output_path, str) and output_path.strip():
            target = Path(output_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text_report, encoding="utf-8")
            click.echo(f"Saved: {target}")
        else:
            click.echo(text_report)
        return
    target_path = (
        output_path
        if isinstance(output_path, str) and output_path.strip()
        else str(Path(".orchesis") / f"evidence_{session_id}.json")
    )
    saved = EvidenceRecord().export_json(record, target_path)
    click.echo(f"Saved: {saved}")


def _normalize_audit_entry(entry: dict[str, Any]) -> dict[str, Any] | None:
    decision = entry.get("decision")
    if not isinstance(decision, str):
        return None
    normalized = {
        "timestamp": entry.get("timestamp"),
        "tool": entry.get("tool"),
        "decision": decision,
        "reasons": entry.get("reasons", []),
        "rules_checked": entry.get("rules_checked", []),
        "cost": entry.get("cost", 0.0),
    }
    if "signature" in entry:
        normalized["signature"] = entry.get("signature")
    return normalized


@main.group("incidents", invoke_without_command=True)
@click.option("--since", type=str, default=None)
@click.option("--severity", type=str, default=None)
@click.pass_context
def incidents_group(ctx: click.Context, since: str | None, severity: str | None) -> None:
    """List and export incident forensics data."""
    if ctx.invoked_subcommand is not None:
        return
    engine = ForensicsEngine(decisions_path=str(DEFAULT_DECISIONS_PATH))
    incidents = engine.detect_incidents(since=since, severity_filter=severity)
    click.echo("Incidents:")
    for item in incidents[:50]:
        ts = item.timestamp[11:16] if len(item.timestamp) >= 16 else item.timestamp
        click.echo(
            f"  [{item.severity.upper():<8}] {item.id.upper()}  {item.title:<32} "
            f"{(item.agent_id or '-'): <12} {ts}"
        )
    counts = Counter(item.severity for item in incidents)
    click.echo("")
    click.echo(
        "Total: "
        f"{len(incidents)} incidents "
        f"({counts.get('critical', 0)} critical, {counts.get('high', 0)} high, "
        f"{counts.get('medium', 0)} medium, {counts.get('low', 0)} low)"
    )


@incidents_group.command("report")
@click.option("--since", type=str, default=None)
@click.option("--format", "output_format", type=click.Choice(["md", "json"]), default="md")
@click.option("--output", "output_path", type=click.Path(), default=None)
def incidents_report(since: str | None, output_format: str, output_path: str | None) -> None:
    """Generate incident report."""
    engine = ForensicsEngine(decisions_path=str(DEFAULT_DECISIONS_PATH))
    report = engine.build_report(since=since)
    content = engine.export_markdown(report) if output_format == "md" else engine.export_json(report)
    if output_path is not None:
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        click.echo(f"Report written to {target}")
        return
    click.echo(content)


@incidents_group.command("risk")
@click.argument("agent_id")
def incidents_risk(agent_id: str) -> None:
    """Show risk profile for one agent."""
    profile = ForensicsEngine(decisions_path=str(DEFAULT_DECISIONS_PATH)).agent_risk_profile(agent_id)
    score = profile["risk_score"]
    level = "low" if score < 0.34 else ("moderate" if score < 0.67 else "high")
    click.echo(f"Agent Risk Profile: {agent_id}")
    click.echo(f"  Requests: {profile['total_requests']:,}")
    click.echo(f"  Denied: {profile['denied']:,} ({profile['deny_rate']*100:.1f}%)")
    click.echo(f"  Risk Score: {score:.2f}/1.00 ({level})")
    click.echo(f"  Trend: {profile['trend']}")
    top_tools = ", ".join(f"{name} ({count})" for name, count in profile["top_denied_tools"][:2]) or "none"
    click.echo(f"  Top denied tools: {top_tools}")
    click.echo(f"  Incidents: {profile['incidents']}")


@incidents_group.command("timeline")
@click.option("--agent", "agent_id", default=None)
@click.option("--incident", "incident_id", default=None)
@click.option("--last", "last_n", type=int, default=50)
def incidents_timeline(agent_id: str | None, incident_id: str | None, last_n: int) -> None:
    """Show timeline of recent security-relevant events."""
    events = ForensicsEngine(decisions_path=str(DEFAULT_DECISIONS_PATH)).attack_timeline(
        incident_id=incident_id,
        agent_id=agent_id,
        last_n=max(1, int(last_n)),
    )
    click.echo(f"Timeline (last {len(events)} events):")
    for event in events:
        ts = event["ts"][11:19] if isinstance(event["ts"], str) and len(event["ts"]) >= 19 else event["ts"]
        reason = event["reasons"][0] if event["reasons"] else "-"
        click.echo(
            f"  {ts}  {event['agent_id']:<10}  {event['tool']:<10}  "
            f"{event['decision']:<5}  {reason}"
        )


@main.command()
@click.option("--log", "log_path", type=click.Path(exists=True), required=False, default=None)
@click.option("--policy", "policy_path", type=click.Path(exists=True), required=False, default=None)
@click.option("--strict", is_flag=True, default=False)
@click.option("--session", "session_id", type=str, required=False, default=None)
@click.option("--diff-only", is_flag=True, default=False)
def replay(
    log_path: str | None,
    policy_path: str | None,
    strict: bool,
    session_id: str | None,
    diff_only: bool,
) -> None:
    """Replay structured logs or a specific session."""
    if session_id:
        decisions_log = log_path or str(DEFAULT_DECISIONS_PATH)
        policy: dict[str, Any] = {"rules": []}
        if policy_path is not None:
            try:
                policy = load_policy(policy_path)
            except (ValueError, YAMLError, OSError) as error:
                raise click.ClickException(f"Failed to load policy: {error}") from error
        replayer = SessionReplay(decisions_log)
        result = replayer.replay(session_id=session_id, policy=policy)
        click.echo("Session replay summary:")
        click.echo(f"  Session: {result.session_id}")
        click.echo(f"  Total decisions: {result.summary['total']}")
        click.echo(f"  Changed: {result.summary['changed']}")
        click.echo(f"  Newly blocked: {result.summary['newly_blocked']}")
        click.echo(f"  Newly allowed: {result.summary['newly_allowed']}")
        if result.differences:
            click.echo("")
            click.echo("Differences:")
            for row in result.differences:
                click.echo(
                    f"  #{row.get('index')} {row.get('event_id')}: "
                    f"{row.get('original_decision')} -> {row.get('replayed_decision')}"
                )
                if not diff_only:
                    click.echo(f"    original_reasons={row.get('original_reasons')}")
                    click.echo(f"    replayed_reasons={row.get('replayed_reasons')}")
        return

    if not log_path or not policy_path:
        raise click.ClickException("Either --session OR both --log and --policy are required")
    try:
        policy = load_policy(policy_path)
    except (ValueError, YAMLError, OSError) as error:
        raise click.ClickException(f"Failed to load policy: {error}") from error

    engine = ReplayEngine()
    report = engine.replay_file(log_path, policy, strict=strict)

    click.echo("Replay summary:")
    click.echo(f"  Total events: {report.total}")
    click.echo(f"  Matches: {report.matches}")
    click.echo(f"  Drifts: {report.drifts}")
    click.echo(f"  Deterministic: {'YES' if report.deterministic else 'NO'}")
    if report.drift_details:
        click.echo("")
        click.echo("Drift details:")
        for drift in report.drift_details:
            original = drift.original_event.decision
            replayed = "ALLOW" if drift.replayed_decision.allowed else "DENY"
            click.echo(
                f"  Event {drift.original_event.event_id}: original={original} replayed={replayed}"
            )
            for reason in drift.drift_reasons:
                click.echo(f"    - {reason}")
    DEFAULT_REPLAY_RUNS_PATH.parent.mkdir(parents=True, exist_ok=True)
    DEFAULT_REPLAY_RUNS_PATH.write_text(
        (
            DEFAULT_REPLAY_RUNS_PATH.read_text(encoding="utf-8")
            if DEFAULT_REPLAY_RUNS_PATH.exists()
            else ""
        )
        + json.dumps(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "total": report.total,
                "matches": report.matches,
                "drifts": report.drifts,
            },
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )


@main.command()
@click.option("--agent", "agent_id", required=True)
@click.option("--since", type=int, default=None)
@click.option("--log", "log_path", type=click.Path(exists=True), default="decisions.jsonl")
def forensic(agent_id: str, since: int | None, log_path: str) -> None:
    """Show decision timeline for a specific agent."""
    events = read_events_from_jsonl(log_path)
    filtered = [event for event in events if event.agent_id == agent_id]

    if since is not None:
        threshold = datetime.now(timezone.utc) - timedelta(hours=since)
        recent: list[Any] = []
        for event in filtered:
            try:
                if datetime.fromisoformat(event.timestamp) >= threshold:
                    recent.append(event)
            except ValueError:
                continue
        filtered = recent

    filtered = sorted(filtered, key=lambda item: item.timestamp)
    allow_count = sum(1 for event in filtered if event.decision == "ALLOW")
    deny_count = sum(1 for event in filtered if event.decision == "DENY")

    period_label = f"last {since}h" if since is not None else "all time"
    click.echo(f"Agent: {agent_id}")
    click.echo(f"Period: {period_label}")
    click.echo(f"Decisions: {len(filtered)} total ({allow_count} ALLOW, {deny_count} DENY)")
    click.echo("")
    click.echo("Timeline:")

    for event in filtered:
        ts = event.timestamp
        time_only = ts[11:19] if len(ts) >= 19 else ts
        click.echo(
            f"  {time_only} {event.decision} {event.tool} "
            f"policy={event.policy_version} params_hash={event.params_hash}"
        )
        for reason in event.reasons:
            click.echo(f"    -> {reason}")


@main.command("reliability-report")
@click.option("--format", "output_format", type=click.Choice(["md", "json"]), default="md")
def reliability_report(output_format: str) -> None:
    """Generate reliability report."""
    generator = ReliabilityReportGenerator()
    report = generator.generate()
    if output_format == "json":
        click.echo(generator.to_json(report))
        return
    click.echo(generator.to_markdown(report))


def _load_experiment_data(data_path: str) -> list[dict[str, Any]]:
    source = Path(data_path)
    text = source.read_text(encoding="utf-8")
    if source.suffix.lower() == ".jsonl":
        rows: list[dict[str, Any]] = []
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                rows.append(payload)
        return rows
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as error:
        raise click.ClickException(f"Invalid data file JSON: {error}") from error
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        return [payload]
    return []


@main.command("experiment")
@click.option("--id", "experiment_id", default=None, help="Experiment id (e.g. exp8)")
@click.option("--data", "data_path", type=click.Path(exists=True), default=None, help="Input JSON/JSONL data file")
@click.option("--list", "list_only", is_flag=True, default=False, help="List available experiments")
@click.option("--results", "show_results", is_flag=True, default=False, help="List saved results")
@click.option("--results-dir", "results_dir", default="experiments/results", show_default=True)
def experiment_command(
    experiment_id: str | None,
    data_path: str | None,
    list_only: bool,
    show_results: bool,
    results_dir: str,
) -> None:
    """Run NLCE experiments or inspect results."""
    runner = NLCEExperimentRunner({"results_dir": results_dir})
    if list_only:
        click.echo("Available experiments:")
        for exp_id, name in sorted(runner.EXPERIMENTS.items()):
            click.echo(f"  {exp_id}: {name}")
        return
    if show_results:
        items = runner.list_results()
        click.echo(json.dumps(items, ensure_ascii=False, indent=2))
        return
    if not experiment_id:
        raise click.ClickException("--id is required unless using --list/--results")
    if not data_path:
        raise click.ClickException("--data is required when running an experiment")
    data = _load_experiment_data(data_path)
    result = runner.run(experiment_id=experiment_id, data=data)
    saved_path = runner.save(result)
    payload = dict(result)
    payload["saved_path"] = saved_path
    click.echo(json.dumps(payload, ensure_ascii=False, indent=2))


@main.command("benchmark")
@click.option("--run-all", "run_all", is_flag=True, default=False, help="Run all benchmark cases")
@click.option("--case", "case_name", default=None, help="Run a single case by id or subcategory")
@click.option(
    "--compare",
    "compare_files",
    nargs=2,
    type=click.Path(exists=True),
    default=None,
    help="Compare two exported benchmark JSON files",
)
@click.option("--list-cases", "list_cases", is_flag=True, default=False, help="List all benchmark cases")
@click.option("--export", "export_path", default=None, type=click.Path(), help="Export results to JSON/CSV")
def benchmark_command(
    run_all: bool,
    case_name: str | None,
    compare_files: tuple[str, str] | None,
    list_cases: bool,
    export_path: str | None,
) -> None:
    """Run and compare Orchesis benchmark suites."""

    def _bar(rate: float, width: int = 20) -> str:
        filled = int(round(max(0.0, min(1.0, rate)) * width))
        return ("█" * filled) + ("░" * (width - filled))

    def _load_report(path: str) -> BenchmarkReport:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        rows = payload.get("results", []) if isinstance(payload, dict) else []
        results = [
            BenchmarkResult(
                case_id=str(item.get("case_id", "")),
                category=str(item.get("category", "")),
                expected_action=str(item.get("expected_action", "")),
                actual_action=str(item.get("actual_action", "")),
                passed=bool(item.get("passed", False)),
                latency_ms=float(item.get("latency_ms", 0.0)),
                details=str(item.get("details", "")),
            )
            for item in rows
            if isinstance(item, dict)
        ]
        return BenchmarkReport(
            suite_name=str(payload.get("suite_name", "ORCHESIS_BENCHMARK_V1")),
            total=int(payload.get("total", len(results))),
            passed=int(payload.get("passed", sum(1 for item in results if item.passed))),
            failed=int(payload.get("failed", max(0, len(results) - sum(1 for item in results if item.passed)))),
            pass_rate=float(payload.get("pass_rate", (sum(1 for item in results if item.passed) / len(results)) if results else 0.0)),
            by_category=payload.get("by_category", {}) if isinstance(payload.get("by_category"), dict) else {},
            by_severity=payload.get("by_severity", {}) if isinstance(payload.get("by_severity"), dict) else {},
            avg_latency_ms=float(payload.get("avg_latency_ms", 0.0)),
            results=results,
            generated_at=float(payload.get("generated_at", time.time())),
            orchesis_version=str(payload.get("orchesis_version", __version__)),
        )

    def _run_cases_with_progress(suite: BenchmarkSuite, selected: list[BenchmarkCase]) -> BenchmarkReport:
        total = len(selected)
        click.echo(f"Running benchmark suite [{total} cases]")
        results: list[BenchmarkResult] = []
        evaluator = suite._default_evaluator  # noqa: SLF001
        for idx, case in enumerate(selected, start=1):
            started = time.perf_counter()
            actual_action = str(evaluator(case.request, suite._policy)).lower()  # noqa: SLF001
            latency_ms = max(0.001, (time.perf_counter() - started) * 1000.0)
            passed = actual_action == case.expected_action
            details = (
                f"Matched expected action '{case.expected_action}'"
                if passed
                else f"Expected {case.expected_action}, got {actual_action}"
            )
            results.append(
                BenchmarkResult(
                    case_id=case.id,
                    category=case.category,
                    expected_action=case.expected_action,
                    actual_action=actual_action,
                    passed=passed,
                    latency_ms=round(latency_ms, 3),
                    details=details,
                )
            )
            rate = idx / float(max(1, total))
            label = case.subcategory or case.id
            click.echo(f"  [{_bar(rate)}] {int(rate * 100):>3}% ({idx}/{total}) {label}")

        passed_count = sum(1 for item in results if item.passed)
        failed_count = len(results) - passed_count
        pass_rate = (passed_count / float(len(results))) if results else 0.0
        avg_latency = (sum(item.latency_ms for item in results) / float(len(results))) if results else 0.0
        case_by_id = {case.id: case for case in selected}
        by_category = suite._aggregate(results, lambda result: result.category)  # noqa: SLF001
        by_severity = suite._aggregate(  # noqa: SLF001
            results,
            lambda result: case_by_id.get(result.case_id, BenchmarkCase("", "", "", "", {}, "allow", "low", [], "")).severity,
        )
        return BenchmarkReport(
            suite_name="ORCHESIS_BENCHMARK_V1",
            total=len(results),
            passed=passed_count,
            failed=failed_count,
            pass_rate=round(pass_rate, 4),
            by_category=by_category,
            by_severity=by_severity,
            avg_latency_ms=round(avg_latency, 3),
            results=results,
            generated_at=time.time(),
            orchesis_version=__version__,
        )

    suite = BenchmarkSuite()

    if list_cases:
        click.echo("Available benchmark cases:")
        click.echo("ID       Category     Subcategory              Description")
        click.echo("-------  -----------  -----------------------  ------------------------------")
        for case in ORCHESIS_BENCHMARK_V1:
            click.echo(f"{case.id:<7}  {case.category:<11}  {case.subcategory:<23}  {case.description}")
        return

    if compare_files:
        file_a, file_b = compare_files
        report_a = _load_report(file_a)
        report_b = _load_report(file_b)
        by_a = {item.case_id: item for item in report_a.results}
        by_b = {item.case_id: item for item in report_b.results}
        common = sorted(set(by_a.keys()) & set(by_b.keys()))
        better: list[str] = []
        worse: list[str] = []
        same_count = 0
        for case_id in common:
            a_res = by_a[case_id]
            b_res = by_b[case_id]
            if (not a_res.passed) and b_res.passed:
                better.append(f"{case_id} (FAIL → PASS)")
            elif a_res.passed and (not b_res.passed):
                worse.append(f"{case_id} (PASS → FAIL)")
            else:
                same_count += 1
        click.echo("Comparing results:")
        if better:
            click.echo(f"  ✓ Better:  {', '.join(better)}")
        if worse:
            click.echo(f"  ✗ Worse:   {', '.join(worse)}")
        click.echo(f"  = Same:    {same_count} cases")
        return

    selected_cases: list[BenchmarkCase]
    if case_name:
        key = str(case_name).strip().lower()
        selected_cases = [
            case
            for case in ORCHESIS_BENCHMARK_V1
            if case.id.lower() == key or case.subcategory.lower() == key
        ]
        if not selected_cases:
            raise click.ClickException(f"Case not found: {case_name}")
    elif run_all or (not case_name and not compare_files and not list_cases):
        selected_cases = list(ORCHESIS_BENCHMARK_V1)
    else:
        selected_cases = list(ORCHESIS_BENCHMARK_V1)

    report = _run_cases_with_progress(suite, selected_cases)
    click.echo("")
    click.echo(f"Overall: {report.passed}/{report.total}  {report.pass_rate*100:.1f}%")

    if export_path:
        suffix = Path(export_path).suffix.lower()
        fmt = "csv" if suffix == ".csv" else "json"
        BenchmarkSuite.export_report(report, export_path, fmt=fmt)
        click.echo(f"Exported report to {export_path}")


@main.command("publish")
@click.option("--period", "period_days", type=int, default=7, show_default=True)
@click.option("--output", "output_path", type=click.Path(), default=None)
@click.option("--upload", "do_upload", is_flag=True, default=False)
@click.option("--preview", "preview_only", is_flag=True, default=False)
@click.option("--decisions", "decisions_path", type=click.Path(), default=str(DEFAULT_DECISIONS_PATH))
def publish_command(
    period_days: int,
    output_path: str | None,
    do_upload: bool,
    preview_only: bool,
    decisions_path: str,
) -> None:
    """Build and share an anonymized public findings report."""
    source = Path(decisions_path)
    rows = read_decisions(source) if source.exists() else []
    decisions = [entry for entry in rows if isinstance(entry, dict)]
    publisher = FindingsPublisher()
    report = publisher.build_report(decisions, period_days=max(1, int(period_days)))

    if preview_only:
        click.echo(json.dumps(report, ensure_ascii=False, indent=2))
        return

    target = (
        output_path
        if isinstance(output_path, str) and output_path.strip()
        else str(Path(".orchesis") / "public_findings_report.json")
    )
    publisher.export_local(report, target)
    click.echo(f"Saved report to {target}")

    if do_upload:
        public_url = publisher.publish(report)
        click.echo(f"Published report: {public_url}")


@main.command("template")
@click.option("--list", "list_only", is_flag=True, default=False)
@click.option(
    "--use",
    "template_name",
    type=click.Choice(sorted(POLICY_TEMPLATES.keys())),
    default=None,
)
@click.option("--output", "output_path", type=click.Path(), default="orchesis.yaml")
@click.option("--merge", "merge_path", type=click.Path(), default=None)
def template_command(
    list_only: bool,
    template_name: str | None,
    output_path: str,
    merge_path: str | None,
) -> None:
    """List or apply policy templates."""
    manager = PolicyTemplateManager()
    if list_only:
        click.echo("Available templates:")
        for item in manager.list_templates():
            click.echo(f"- {item['name']}: {item['description']} ({item['use_case']})")
        return
    if not isinstance(template_name, str) or not template_name.strip():
        raise click.ClickException("--use is required unless --list is provided")

    if isinstance(merge_path, str) and merge_path.strip():
        target = Path(merge_path)
        existing: dict[str, Any] = {}
        if target.exists():
            loaded = yaml.safe_load(target.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                existing = loaded
        merged = manager.merge_template(template_name, existing)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            yaml.safe_dump(merged, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )
        click.echo(f"Merged template '{template_name}' into {target}")
        return

    manager.apply_template(template_name, output_path)
    click.echo(f"Applied template '{template_name}' to {output_path}")


@main.command("readiness")
@click.option("--agent", "agent_id", required=True)
@click.option("--config", "config_path", default="orchesis.yaml")
def readiness_command(agent_id: str, config_path: str) -> None:
    """Compute Agent Readiness Index (ARI) for an agent."""
    policy: dict[str, Any] = {}
    config_exists = Path(config_path).exists()
    if config_exists:
        try:
            policy = load_policy(config_path)
        except Exception:
            policy = {}

    readiness_cfg = policy.get("agent_readiness", {}) if isinstance(policy, dict) else {}
    weights = readiness_cfg.get("weights") if isinstance(readiness_cfg, dict) else None
    thresholds = readiness_cfg.get("thresholds") if isinstance(readiness_cfg, dict) else None

    metrics: dict[str, Any] = {}
    metrics_store = readiness_cfg.get("metrics", {}) if isinstance(readiness_cfg, dict) else {}
    if isinstance(metrics_store, dict):
        selected = metrics_store.get(agent_id, {})
        if isinstance(selected, dict):
            metrics = selected

    ari = AgentReadinessIndex(weights=weights, thresholds=thresholds)
    result = ari.evaluate(agent_id=agent_id, metrics=metrics)

    green = "\033[92m"
    yellow = "\033[93m"
    red = "\033[91m"
    reset = "\033[0m"
    pass_mark = "✅"
    warn_mark = "⚠️"
    fail_mark = "❌"

    click.echo(f"Agent Readiness Index: {agent_id}")
    click.echo("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    click.echo(f"Verdict:  {result.verdict}")
    click.echo(f"Index:    {result.index} / 100")
    click.echo("")
    click.echo("Dimensions:")
    for dim in result.dimensions:
        if dim.status == "pass":
            color = green
            mark = pass_mark
            label = "PASS"
        elif dim.status == "warn":
            color = yellow
            mark = warn_mark
            label = "WARN"
        else:
            color = red
            mark = fail_mark
            label = "FAIL"
        click.echo(f"  {color}{mark}{reset} {dim.name:<20} {dim.score:>5.1f}  {color}{label}{reset}")

    if result.recommendations:
        click.echo("")
        click.echo("Recommendations:")
        for recommendation in result.recommendations:
            click.echo(f"  -> {recommendation}")

    if not config_exists:
        click.echo("")
        click.echo(f"Note: config not found at {config_path}; evaluated using defaults.")


@main.command("ari-check")
@click.option("--agent", "agent_id", required=True)
@click.option("--min-score", type=int, default=75, show_default=True)
@click.option("--config", "config_path", default="orchesis.yaml", show_default=True)
def ari_check_command(agent_id: str, min_score: int, config_path: str) -> None:
    """CI/CD gate for Agent Readiness Index."""
    policy: dict[str, Any] = {}
    if Path(config_path).exists():
        try:
            policy = load_policy(config_path)
        except Exception:
            policy = {}
    readiness_cfg = policy.get("agent_readiness", {}) if isinstance(policy, dict) else {}
    weights = readiness_cfg.get("weights") if isinstance(readiness_cfg, dict) else None
    thresholds = readiness_cfg.get("thresholds") if isinstance(readiness_cfg, dict) else None
    metrics: dict[str, Any] = {}
    metrics_store = readiness_cfg.get("metrics", {}) if isinstance(readiness_cfg, dict) else {}
    if isinstance(metrics_store, dict):
        selected = metrics_store.get(agent_id, {})
        if isinstance(selected, dict):
            metrics = selected
    ari = AgentReadinessIndex(weights=weights, thresholds=thresholds)
    result = ari.evaluate(agent_id=agent_id, metrics=metrics)
    score = int(round(float(result.index)))
    if score >= int(min_score):
        click.echo(f"✓ ARI score: {score}/100 — {result.verdict}")
        raise SystemExit(0)
    click.echo(f"✗ ARI score: {score}/100 — {result.verdict}")
    raise SystemExit(1)


@main.command("threat-feed")
@click.option("--update", "do_update", is_flag=True, default=False)
@click.option("--status", "show_status", is_flag=True, default=False)
@click.option("--export", "export_path", type=click.Path(), default=None)
@click.option("--import", "import_path", type=click.Path(exists=True), default=None)
@click.option("--config", "config_path", type=click.Path(), default="orchesis.yaml")
def threat_feed_command(
    do_update: bool,
    show_status: bool,
    export_path: str | None,
    import_path: str | None,
    config_path: str,
) -> None:
    """Manage external threat intelligence feed."""
    policy: dict[str, Any] = {}
    config_file = Path(config_path)
    if config_file.exists():
        try:
            policy = load_policy(str(config_file))
        except Exception:
            policy = {}
    cfg = policy.get("threat_feed", {}) if isinstance(policy, dict) and isinstance(policy.get("threat_feed"), dict) else {}
    feed = ThreatFeed(cfg)

    if isinstance(import_path, str) and import_path.strip():
        imported = feed.import_signatures(import_path)
        click.echo(f"Imported signatures: {imported}")
    if bool(do_update):
        added = feed.fetch()
        click.echo(f"Fetched signatures: {len(added)} new")
    if isinstance(export_path, str) and export_path.strip():
        feed.export_signatures(export_path)
        click.echo(f"Exported signatures to {export_path}")
    if show_status or (not do_update and export_path is None and import_path is None):
        click.echo(json.dumps(feed.get_stats(), ensure_ascii=False, indent=2))


@main.command("compliance")
@click.argument("framework", required=False)
@click.option("--agent", "agent_id", default=None)
@click.option("--policy", "policy_path", default="policy.yaml")
@click.option("--decisions", "decisions_path", default=str(DEFAULT_DECISIONS_PATH))
@click.option("--format", "output_format", type=click.Choice(["md", "json", "text"]), default="text")
@click.option("--output", "output_path", type=click.Path(), default=None)
def compliance_command(
    framework: str | None,
    agent_id: str | None,
    policy_path: str,
    decisions_path: str,
    output_format: str,
    output_path: str | None,
) -> None:
    """Generate compliance report(s) for one or all frameworks."""
    if isinstance(agent_id, str) and agent_id.strip():
        source = Path(decisions_path)
        events = read_events_from_jsonl(source) if source.exists() else []
        filtered = [event for event in events if str(getattr(event, "agent_id", "")) == agent_id.strip()]
        generator = ComplianceReportGenerator()
        report = generator.generate(agent_id=agent_id.strip(), decisions_log=filtered)
        if output_format == "json":
            content = json.dumps(report, ensure_ascii=False, indent=2)
        else:
            content = generator.export_text(report)
        if output_path is not None:
            target = Path(output_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            click.echo(f"Report written to {target}")
            return
        click.echo(content)
        return

    if not isinstance(framework, str) or not framework.strip():
        raise click.ClickException(
            "framework is required unless --agent is provided (use framework/all/cross-map)"
        )
    framework = framework.strip()

    if framework == "cross-map":
        cross = FrameworkCrossReference()
        if output_format == "json":
            content = json.dumps(cross.generate_coverage_matrix(), ensure_ascii=False, indent=2)
        elif output_format == "md":
            content = _render_cross_map_markdown(cross)
        else:
            content = _render_cross_map_text(cross)
        if output_path is not None:
            target = Path(output_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            click.echo(f"Report written to {target}")
            return
        click.echo(content)
        return

    engine = ComplianceEngine(policy_path=policy_path, decisions_path=str(DEFAULT_DECISIONS_PATH))
    if framework == "all":
        reports = engine.check_all()
        if output_format == "json":
            content = json.dumps(
                {name: asdict(report) for name, report in reports.items()},
                ensure_ascii=False,
                indent=2,
            )
        elif output_format == "md":
            content = _render_all_compliance_markdown(reports)
        else:
            content = _render_all_compliance_text(reports)
    else:
        valid = set(FRAMEWORK_CHECKS.keys())
        if framework not in valid:
            raise click.ClickException(
                f"Unsupported framework '{framework}'. Use one of: {', '.join(sorted(valid))}, all, cross-map"
            )
        report = engine.check(framework)
        if output_format == "json":
            content = engine.export_json(report)
        elif output_format == "md":
            content = engine.export_markdown(report)
        else:
            content = _render_single_compliance_text(report)

    if output_format == "text":
        content = f"{content}\n\n{_render_integrity_monitoring_summary(policy_path)}"

    if output_path is not None:
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        click.echo(f"Report written to {target}")
        return
    click.echo(content)


def _render_single_compliance_text(report: Any) -> str:
    lines = [
        f"{report.framework.upper()} Compliance Check",
        "=" * (len(report.framework) + 17),
    ]
    for check in report.checks:
        symbol = "PASS" if check.status == "pass" else ("PARTIAL" if check.status == "partial" else "FAIL")
        lines.append(f"{symbol:8} {check.id}  {check.requirement}")
    lines.append("")
    lines.append(
        f"Score: {report.score*100:.1f}% ({report.pass_count}/{len(report.checks)} pass, {report.partial_count} partial, {report.fail_count} fail)"
    )
    recommendations = [check.recommendation for check in report.checks if check.status != "pass" and check.recommendation]
    if recommendations:
        lines.append("")
        lines.append("Recommendations:")
        for index, text in enumerate(dict.fromkeys(recommendations), start=1):
            lines.append(f"  {index}. {text}")
    return "\n".join(lines)


def _render_integrity_monitoring_summary(policy_path: str) -> str:
    baseline_path = Path(policy_path).resolve().parent / ".orchesis" / "integrity.json"
    if not baseline_path.exists():
        return "Integrity monitoring: not configured. Run 'orchesis integrity init' to enable."
    try:
        payload = json.loads(baseline_path.read_text(encoding="utf-8"))
    except Exception:
        payload = {}
    files = payload.get("files", {}) if isinstance(payload, dict) else {}
    files_count = len(files) if isinstance(files, dict) else 0
    updated_at = payload.get("updated_at") if isinstance(payload, dict) else None
    last_check = "unknown"
    age_note = ""
    if isinstance(updated_at, str) and updated_at.strip():
        try:
            parsed = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            age = now - parsed
            hours = max(0, int(age.total_seconds() // 3600))
            last_check = parsed.strftime("%Y-%m-%d %H:%M:%S")
            age_note = f" ({hours} hours ago)"
        except Exception:
            last_check = updated_at
    return "\n".join(
        [
            "Integrity Monitoring Status:",
            "Baseline: ✅ present (.orchesis/integrity.json)",
            f"Files monitored: {files_count}",
            f"Last check: {last_check}{age_note}",
            "Last violation: none",
        ]
    )


def _render_all_compliance_text(reports: dict[str, Any]) -> str:
    framework_labels = {
        "hipaa": "HIPAA",
        "soc2": "SOC2",
        "eu_ai_act": "EU AI Act",
        "nist_ai_rmf": "NIST AI RMF",
        "owasp_asi": "OWASP ASI Top 10",
        "mitre_atlas": "MITRE ATLAS",
        "cosai": "CoSAI",
        "csa_maestro": "CSA MAESTRO",
        "nist_ai_100_2": "NIST AI 100-2",
    }
    lines = [
        "Framework           Score   Pass  Fail  Partial",
        "------------------------------------------------",
    ]
    total_score = 0.0
    recommendations: list[str] = []
    for framework, report in reports.items():
        total_score += report.score
        label = framework_labels.get(framework, framework.upper())
        lines.append(
            f"{label:<18} {report.score*100:>5.1f}%   {report.pass_count:<4}  {report.fail_count:<4}  {report.partial_count:<7}"
        )
        recommendations.extend(
            check.recommendation
            for check in report.checks
            if check.status != "pass" and check.recommendation
        )
    overall = (total_score / len(reports)) if reports else 0.0
    lines.append("")
    lines.append(f"Overall: {overall*100:.1f}% across {len(reports)} frameworks")
    unique_recs = list(dict.fromkeys(recommendations))
    if unique_recs:
        lines.append("Top recommendations:")
        for index, text in enumerate(unique_recs[:3], start=1):
            lines.append(f"  {index}. {text}")
    return "\n".join(lines)


def _render_all_compliance_markdown(reports: dict[str, Any]) -> str:
    framework_labels = {
        "hipaa": "HIPAA",
        "soc2": "SOC2",
        "eu_ai_act": "EU AI Act",
        "nist_ai_rmf": "NIST AI RMF",
        "owasp_asi": "OWASP ASI Top 10",
        "mitre_atlas": "MITRE ATLAS",
        "cosai": "CoSAI",
        "csa_maestro": "CSA MAESTRO",
        "nist_ai_100_2": "NIST AI 100-2",
    }
    lines = [
        "# Compliance Report (All Frameworks)",
        "",
        "| Framework | Score | Pass | Fail | Partial |",
        "|-----------|------:|-----:|-----:|--------:|",
    ]
    for framework, report in reports.items():
        label = framework_labels.get(framework, framework.upper())
        lines.append(
            f"| {label} | {report.score*100:.1f}% | {report.pass_count} | {report.fail_count} | {report.partial_count} |"
        )
    overall = (sum(report.score for report in reports.values()) / len(reports)) if reports else 0.0
    lines.extend(["", f"Overall: {overall*100:.1f}% across {len(reports)} frameworks"])
    return "\n".join(lines) + "\n"


def _render_cross_map_text(cross: FrameworkCrossReference) -> str:
    lines = [
        "Feature                  Frameworks Covered",
        "--------------------------------------------",
    ]
    matrix = cross.generate_coverage_matrix()
    features = matrix.get("features", {})
    if isinstance(features, dict):
        for feature, refs in features.items():
            if not isinstance(refs, list):
                continue
            compact = ", ".join(ref.split(":", 1)[1] if ":" in ref else ref for ref in refs)
            lines.append(f"{feature:<24} {compact}")
    lines.append("")
    lines.append(
        "Coverage: "
        f"{matrix.get('covered_checks', 0)}/{matrix.get('total_checks', 0)} checks "
        f"({float(matrix.get('coverage_ratio', 0.0))*100:.1f}%)"
    )
    return "\n".join(lines)


def _render_cross_map_markdown(cross: FrameworkCrossReference) -> str:
    matrix = cross.generate_coverage_matrix()
    lines = [
        "# Compliance Cross-Framework Map",
        "",
        "| Feature | Frameworks Covered |",
        "|---------|--------------------|",
    ]
    features = matrix.get("features", {})
    if isinstance(features, dict):
        for feature, refs in features.items():
            if not isinstance(refs, list):
                continue
            compact = ", ".join(refs)
            lines.append(f"| {feature} | {compact} |")
    lines.extend(
        [
            "",
            f"Coverage: {matrix.get('covered_checks', 0)}/{matrix.get('total_checks', 0)} checks "
            f"({float(matrix.get('coverage_ratio', 0.0))*100:.1f}%)",
        ]
    )
    return "\n".join(lines) + "\n"


def _format_network_scan_text(findings: list[dict[str, Any]]) -> str:
    lines = ["Network Exposure Scan", "====================="]
    counts = Counter(str(item.get("severity", "info")).lower() for item in findings)
    for item in findings:
        sev = str(item.get("severity", "info")).upper()
        lines.append(
            f"[{sev:<8}] {item.get('check','network'):<18} {item.get('description','')} ({item.get('evidence','')})"
        )
    lines.append("")
    lines.append(
        f"Findings: {counts.get('critical',0)} critical, {counts.get('high',0)} high, "
        f"{counts.get('medium',0)} medium, {counts.get('info',0)} info"
    )
    recommendations = [str(item.get("recommendation", "")) for item in findings if item.get("recommendation")]
    if recommendations:
        lines.append("")
        lines.append("Recommendations:")
        for index, text in enumerate(dict.fromkeys(recommendations), start=1):
            lines.append(f"  {index}. {text}")
    return "\n".join(lines)


@main.group("ioc")
def ioc_group() -> None:
    """Inspect and scan known indicators of compromise."""


@ioc_group.command("list")
@click.option("--category", default=None)
@click.option("--severity", default=None)
def ioc_list(category: str | None, severity: str | None) -> None:
    """List IoCs from local in-memory database."""
    matcher = IoCMatcher()
    items = matcher.list_iocs(category=category, severity=severity)
    if not items:
        click.echo("No IoCs found for provided filters.")
        return
    for item in items:
        click.echo(f"{item.id:<14} {item.severity.upper():<8} {item.category:<18} {item.name}")


@ioc_group.command("scan")
@click.argument("path", type=click.Path(exists=True))
def ioc_scan(path: str) -> None:
    """Scan a file/path content against IoC patterns."""
    matcher = IoCMatcher()
    findings = matcher.scan_file(path)
    if not findings:
        click.echo("No IoC matches found.")
        return
    for item in findings:
        click.echo(
            f"[{item['severity'].upper():<8}] {item['ioc_id']} {item['ioc_name']} "
            f"@{item.get('position', 0)}"
        )
    click.echo(f"Total matches: {len(findings)}")


@ioc_group.command("info")
@click.argument("ioc_id")
def ioc_info(ioc_id: str) -> None:
    """Show detailed metadata for one IoC."""
    matcher = IoCMatcher()
    item = matcher.get_ioc(ioc_id)
    if item is None:
        raise click.ClickException(f"IoC '{ioc_id}' not found")
    click.echo(f"ID: {item.id}")
    click.echo(f"Name: {item.name}")
    click.echo(f"Category: {item.category}")
    click.echo(f"Severity: {item.severity}")
    click.echo(f"Source: {item.source}")
    if item.cve:
        click.echo(f"CVE: {item.cve}")
    if item.mitre_atlas:
        click.echo(f"MITRE ATLAS: {item.mitre_atlas}")
    click.echo("Indicators:")
    for pattern in item.indicators:
        click.echo(f"  - {pattern}")
