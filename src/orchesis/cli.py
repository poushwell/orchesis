"""CLI entrypoint for Orchesis."""

import json
from collections import Counter
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import click
from yaml import YAMLError

from orchesis.config import (
    load_agent_registry,
    load_policy,
    validate_policy,
    validate_policy_warnings,
)
from orchesis.engine import evaluate
from orchesis.logger import read_decisions
from orchesis.policy_store import PolicyStore
from orchesis.replay import ReplayEngine, read_events_from_jsonl
from orchesis.signing import generate_keypair, sign_entry, verify_entry
from orchesis.state import RateLimitTracker
from orchesis.telemetry import InMemoryEmitter, JsonlEmitter

DEFAULT_KEYS_DIR = Path(".orchesis") / "keys"
DEFAULT_PRIVATE_KEY_PATH = DEFAULT_KEYS_DIR / "private.pem"
DEFAULT_PUBLIC_KEY_PATH = DEFAULT_KEYS_DIR / "public.pem"
DEFAULT_STATE_PATH = Path(".orchesis") / "state.jsonl"
DEFAULT_DECISIONS_PATH = Path("decisions.jsonl")


@click.group()
def main() -> None:
    """Orchesis command line interface."""


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
def verify(request_path: str, policy_path: str, should_sign: bool) -> None:
    """Verify a request against policy."""
    try:
        request = json.loads(Path(request_path).read_text(encoding="utf-8"))
        policy = load_policy(policy_path)
        has_identity_config = "agents" in policy or "default_trust_tier" in policy
        registry = load_agent_registry(policy) if has_identity_config else None
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
@click.option("--since", type=int, default=None)
@click.option("--limit", type=int, default=20)
@click.option("--verify", "verify_signatures", is_flag=True, default=False)
def audit(since: int | None, limit: int, verify_signatures: bool) -> None:
    """Audit decision log."""
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

        click.echo(f"{verified_count} verified, {tampered_count} tampered, {unsigned_count} unsigned")
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
