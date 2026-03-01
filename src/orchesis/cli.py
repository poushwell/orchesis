"""CLI entrypoint for Orchesis."""

import asyncio
import json
import os
import time
import tracemalloc
from concurrent.futures import ThreadPoolExecutor
from collections import Counter
from dataclasses import asdict, replace
from datetime import datetime, timezone, timedelta
from pathlib import Path
from random import Random
from typing import Any

import click
import httpx
import uvicorn
import yaml
from yaml import YAMLError

from orchesis.audit import AuditEngine, AuditQuery
from orchesis.api import create_api_app
from orchesis.compliance import ComplianceEngine, FRAMEWORK_CHECKS
from orchesis.contrib.ioc_database import IoCMatcher
from orchesis.contrib.network_scanner import NetworkExposureScanner
from orchesis.config import (
    load_agent_registry,
    load_policy,
    validate_policy,
    validate_policy_warnings,
)
from orchesis.engine import evaluate
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
from orchesis.reliability import ReliabilityReportGenerator
from orchesis.scenarios import AdversarialScenarios
from orchesis.scanner import (
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
from orchesis.mcp_config import McpProxySettings
from orchesis.mcp_proxy import run_stdio_proxy
from orchesis.marketplace import PolicyMarketplace
from orchesis.proxy import OrchesisProxy, ProxyConfig
from orchesis.interceptors import McpStdioProxy
from orchesis.structured_log import StructuredLogger
from orchesis.sync import PolicySyncClient
from orchesis.templates import TEMPLATE_NAMES, load_template_text

DEFAULT_KEYS_DIR = Path(".orchesis") / "keys"
DEFAULT_PRIVATE_KEY_PATH = DEFAULT_KEYS_DIR / "private.pem"
DEFAULT_PUBLIC_KEY_PATH = DEFAULT_KEYS_DIR / "public.pem"
DEFAULT_STATE_PATH = Path(".orchesis") / "state.jsonl"
DEFAULT_DECISIONS_PATH = Path("decisions.jsonl")
DEFAULT_FUZZ_RUNS_PATH = Path(".orchesis") / "fuzz_runs.jsonl"
DEFAULT_MUTATION_RUNS_PATH = Path(".orchesis") / "mutation_runs.jsonl"
DEFAULT_REPLAY_RUNS_PATH = Path(".orchesis") / "replay_runs.jsonl"
OPERATIONS_LOG = StructuredLogger("cli")


@click.group()
def main() -> None:
    """Orchesis command line interface."""


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
@click.option("--policy", "policy_path", type=click.Path(), default="policy.yaml")
def doctor(policy_path: str) -> None:
    """Run environment and project diagnostics."""
    checks: list[tuple[str, bool, str]] = []
    import importlib.util
    import sys

    py_ok = (sys.version_info.major, sys.version_info.minor) >= (3, 11)
    checks.append(("python_version", py_ok, f"{sys.version_info.major}.{sys.version_info.minor}"))

    for module_name in ("yaml", "click", "fastapi", "httpx", "mcp"):
        checks.append(
            (
                f"module:{module_name}",
                importlib.util.find_spec(module_name) is not None,
                "importable",
            )
        )

    policy_file = Path(policy_path)
    if policy_file.exists():
        try:
            policy = load_policy(policy_file)
            errors = validate_policy(policy)
            checks.append(("policy_load", True, str(policy_file)))
            checks.append(
                (
                    "policy_validate",
                    len(errors) == 0,
                    "OK" if not errors else "; ".join(errors[:2]),
                )
            )
        except Exception as error:  # noqa: BLE001
            checks.append(("policy_load", False, str(error)))
            checks.append(("policy_validate", False, "invalid policy"))
    else:
        checks.append(("policy_load", False, f"missing: {policy_file}"))
        checks.append(("policy_validate", False, "policy file not found"))

    template_ok = all(
        (Path(__file__).resolve().parent / "templates" / f"{name}.yaml").exists()
        for name in TEMPLATE_NAMES
    )
    checks.append(("templates", template_ok, ", ".join(TEMPLATE_NAMES)))

    runtime_dir = Path(".orchesis")
    runtime_dir.mkdir(parents=True, exist_ok=True)
    writable_probe = runtime_dir / ".doctor_probe"
    try:
        writable_probe.write_text("ok", encoding="utf-8")
        writable_probe.unlink()
        checks.append(("runtime_writable", True, str(runtime_dir)))
    except OSError as error:
        checks.append(("runtime_writable", False, str(error)))

    click.echo("Doctor checks:")
    all_ok = True
    for name, ok, detail in checks:
        marker = "[OK]" if ok else "[FAIL]"
        click.echo(f"  {marker} {name}: {detail}")
        all_ok = all_ok and ok
    raise SystemExit(0 if all_ok else 1)


@main.command()
def init() -> None:
    """Initialize sample policy and request files."""
    policy_content = """rules:
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
    request_content = """{
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

    Path("policy.yaml").write_text(policy_content, encoding="utf-8")
    Path("request.json").write_text(request_content, encoding="utf-8")
    click.echo("Created policy.yaml and request.json. Edit them, then run: orchesis verify")


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
@click.option("--policy", "policy_path", type=click.Path(exists=True), required=True)
def validate(policy_path: str) -> None:
    """Validate policy file."""
    try:
        policy = load_policy(policy_path)
    except (ValueError, YAMLError, OSError) as error:
        raise click.ClickException(f"Failed to load policy: {error}") from error

    errors = validate_policy(policy)
    warnings = validate_policy_warnings(policy)
    for warning in warnings:
        click.echo(f"! warning: {warning}")
    if not errors:
        click.echo("OK")
        return

    for error in errors:
        click.echo(f"- {error}")
    raise SystemExit(1)


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
@click.option("--port", type=int, default=8080)
@click.option("--policy", "policy_path", type=click.Path(exists=True), default="policy.yaml")
@click.option(
    "--plugins",
    "plugin_modules",
    multiple=True,
    help="Plugin module path(s), e.g. orchesis.contrib.pii_detector",
)
def serve(port: int, policy_path: str, plugin_modules: tuple[str, ...]) -> None:
    """Run Orchesis control API server."""
    try:
        policy = load_policy(policy_path)
    except (ValueError, YAMLError, OSError) as error:
        raise click.ClickException(f"Failed to load policy: {error}") from error

    store = PolicyStore()
    version = store.load(policy_path)
    registry = load_agent_registry(policy)
    click.echo(f"Orchesis Control API running on http://0.0.0.0:{port}")
    click.echo(f"Policy: {policy_path} (version {version.version_id[:12]})")
    click.echo(
        f"Agents: {len(registry.agents)} registered, default tier: {registry.default_tier.name.lower()}"
    )
    click.echo("Endpoints: /api/v1/policy, /api/v1/agents, /api/v1/evaluate, /api/v1/status")
    OPERATIONS_LOG.info("starting api server", port=port, policy_path=policy_path)
    app = create_api_app(
        policy_path=policy_path,
        plugin_modules=_normalize_plugin_modules(plugin_modules),
    )
    uvicorn.run(app, host="0.0.0.0", port=port)


@main.command("proxy")
@click.option("--policy", "policy_path", type=click.Path(exists=True), required=True)
@click.option("--port", type=int, default=8100)
@click.option("--host", "listen_host", type=str, default="127.0.0.1")
@click.option("--upstream", "upstream_url", type=str, required=True)
@click.option(
    "--mode",
    "intercept_mode",
    type=click.Choice(["tool_call", "all", "passthrough"]),
    default="tool_call",
)
@click.option("--buffer-responses/--no-buffer-responses", default=True)
def proxy_command(
    policy_path: str,
    port: int,
    listen_host: str,
    upstream_url: str,
    intercept_mode: str,
    buffer_responses: bool,
) -> None:
    """Run transparent HTTP proxy interceptor."""
    policy = load_policy(policy_path)
    tracker = RateLimitTracker(persist_path=None)
    config = ProxyConfig(
        listen_host=listen_host,
        listen_port=max(1, int(port)),
        upstream_url=upstream_url,
        intercept_mode=intercept_mode,
        buffer_responses=bool(buffer_responses),
    )

    def _engine(request_payload: dict[str, Any]):
        return evaluate(request_payload, policy, state=tracker)

    proxy = OrchesisProxy(engine=_engine, config=config)
    click.echo("Orchesis Proxy starting...")
    click.echo(f"Policy: {policy_path}")
    click.echo(f"Mode: {intercept_mode}")
    click.echo(f"Listening: http://{listen_host}:{port}")
    click.echo(f"Upstream: {upstream_url}")
    click.echo("")
    click.echo("Press Ctrl+C to stop.")

    async def _run() -> None:
        await proxy.start()
        try:
            while True:
                await asyncio.sleep(1.0)
        finally:
            await proxy.stop()

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        click.echo("\nProxy stopped.")


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


@main.command("nodes")
@click.option("--api-url", default="http://localhost:8080")
@click.option("--api-token", default=None)
def nodes(api_url: str, api_token: str | None) -> None:
    """List connected enforcement nodes from control plane."""
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
def scan_command(
    path_arg: str | None,
    output_format: str,
    severity_threshold: str,
    scan_mcp_configs: bool,
    scan_network: bool,
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

    if output_format == "json":
        payload = [report_to_dict(item) for item in reports]
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
        click.echo("")
    if network_findings:
        click.echo(_format_network_scan_text(network_findings))
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
@click.option("--log", "log_path", type=click.Path(exists=True), required=True)
@click.option("--policy", "policy_path", type=click.Path(exists=True), required=True)
@click.option("--strict", is_flag=True, default=False)
def replay(log_path: str, policy_path: str, strict: bool) -> None:
    """Replay structured decision logs and check determinism."""
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


@main.command("compliance")
@click.argument("framework")
@click.option("--policy", "policy_path", default="policy.yaml")
@click.option("--format", "output_format", type=click.Choice(["md", "json", "text"]), default="text")
@click.option("--output", "output_path", type=click.Path(), default=None)
def compliance_command(framework: str, policy_path: str, output_format: str, output_path: str | None) -> None:
    """Generate compliance report(s) for one or all frameworks."""
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
                f"Unsupported framework '{framework}'. Use one of: {', '.join(sorted(valid))}, all"
            )
        report = engine.check(framework)
        if output_format == "json":
            content = engine.export_json(report)
        elif output_format == "md":
            content = engine.export_markdown(report)
        else:
            content = _render_single_compliance_text(report)

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


def _render_all_compliance_text(reports: dict[str, Any]) -> str:
    lines = [
        "Framework       Score   Pass  Fail  Partial",
        "-------------------------------------------",
    ]
    total_score = 0.0
    recommendations: list[str] = []
    for framework, report in reports.items():
        total_score += report.score
        lines.append(
            f"{framework.upper():<14} {report.score*100:>5.1f}%   {report.pass_count:<4}  {report.fail_count:<4}  {report.partial_count:<7}"
        )
        recommendations.extend(
            check.recommendation
            for check in report.checks
            if check.status != "pass" and check.recommendation
        )
    overall = (total_score / len(reports)) if reports else 0.0
    lines.append("")
    lines.append(f"Overall: {overall*100:.1f}%")
    unique_recs = list(dict.fromkeys(recommendations))
    if unique_recs:
        lines.append("Top recommendations:")
        for index, text in enumerate(unique_recs[:3], start=1):
            lines.append(f"  {index}. {text}")
    return "\n".join(lines)


def _render_all_compliance_markdown(reports: dict[str, Any]) -> str:
    lines = [
        "# Compliance Report (All Frameworks)",
        "",
        "| Framework | Score | Pass | Fail | Partial |",
        "|-----------|------:|-----:|-----:|--------:|",
    ]
    for framework, report in reports.items():
        lines.append(
            f"| {framework.upper()} | {report.score*100:.1f}% | {report.pass_count} | {report.fail_count} | {report.partial_count} |"
        )
    overall = (sum(report.score for report in reports.values()) / len(reports)) if reports else 0.0
    lines.extend(["", f"Overall: {overall*100:.1f}%"])
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
