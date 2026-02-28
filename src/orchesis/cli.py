"""CLI entrypoint for Orchesis."""

import json
from collections import Counter
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import click
from yaml import YAMLError

from orchesis.config import load_policy, validate_policy
from orchesis.engine import evaluate
from orchesis.logger import read_decisions
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
    except (json.JSONDecodeError, OSError) as error:
        raise click.ClickException(f"Failed to load request: {error}") from error
    except (ValueError, YAMLError, OSError) as error:
        raise click.ClickException(f"Failed to load policy: {error}") from error

    if not isinstance(request, dict):
        raise click.ClickException("Request JSON must be an object.")

    state_tracker = RateLimitTracker(persist_path=DEFAULT_STATE_PATH)
    signature: str | None = None
    if should_sign:
        memory_emitter = InMemoryEmitter()
        decision = evaluate(request, policy, state=state_tracker, emitter=memory_emitter)
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
        )

    click.echo(json.dumps(asdict(decision), ensure_ascii=False, indent=2))
    raise SystemExit(0 if decision.allowed else 1)


@main.command()
@click.option("--policy", "policy_path", type=click.Path(exists=True), required=True)
def validate(policy_path: str) -> None:
    """Validate policy file."""
    try:
        policy = load_policy(policy_path)
    except (ValueError, YAMLError, OSError) as error:
        raise click.ClickException(f"Failed to load policy: {error}") from error

    errors = validate_policy(policy)
    if not errors:
        click.echo("OK")
        return

    for error in errors:
        click.echo(f"- {error}")
    raise SystemExit(1)


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
