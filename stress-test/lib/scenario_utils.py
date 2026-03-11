from __future__ import annotations

import json
import socket
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.request import urlopen

from orchesis.proxy import HTTPProxyConfig, LLMHTTPProxy

from .mock_upstream import MockUpstream


def pick_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for_port(host: str, port: int, timeout: float = 6.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def policy_text(
    *,
    strict: bool = False,
    low_budget: bool = False,
    heartbeat_limit: int = 5,
    enable_content_loop: bool = False,
    enable_spend_rate: bool = False,
) -> str:
    budget_daily = 0.10 if low_budget else 50.0
    blocked = '["/etc", "/root", "~/.ssh", "~/.aws", "/tmp/reload-target.txt"]' if strict else "[]"
    spend_60 = 0.05 if low_budget else 25.0
    spend_3600 = 2.0 if low_budget else 100.0
    return f"""
default_action: allow
rules:
  - name: default_deny
    denied_paths: {blocked}
budgets:
  daily: {budget_daily}
  spend_rate:
    enabled: {str(enable_spend_rate).lower()}
    windows:
      - seconds: 60
        max_spend: {spend_60}
      - seconds: 3600
        max_spend: {spend_3600}
    spike_multiplier: 6.0
    pause_seconds: 10
loop_detection:
  enabled: {str(enable_content_loop).lower()}
  content_loop:
    enabled: {str(enable_content_loop).lower()}
    window_seconds: 60
    max_identical: {heartbeat_limit}
    cooldown_seconds: 60
    hash_prefix_len: 256
threat_intel:
  enabled: true
  default_action: warn
  severity_actions:
    critical: block
    high: warn
    medium: log
semantic_cache:
  enabled: true
  max_entries: 500
  ttl_seconds: 300
behavioral_fingerprint:
  enabled: true
flow_xray:
  enabled: true
model_routing:
  enabled: true
  default: gpt-4o
  heartbeat_models:
    default: gpt-4o-mini
secrets:
  scan_outbound: true
"""


def start_stack(
    *,
    upstream_behavior: str = "normal",
    strict: bool = False,
    low_budget: bool = False,
    heartbeat_limit: int = 5,
    enable_content_loop: bool = False,
    enable_spend_rate: bool = False,
) -> dict[str, Any]:
    temp_dir = Path(tempfile.mkdtemp(prefix="orchesis-stress-"))
    policy_path = temp_dir / "policy.yaml"
    policy_path.write_text(
        policy_text(
            strict=strict,
            low_budget=low_budget,
            heartbeat_limit=heartbeat_limit,
            enable_content_loop=enable_content_loop,
            enable_spend_rate=enable_spend_rate,
        ),
        encoding="utf-8",
    )

    upstream = MockUpstream(behavior=upstream_behavior)
    upstream_port = upstream.start()
    proxy_port = pick_port()
    proxy = LLMHTTPProxy(
        policy_path=str(policy_path),
        config=HTTPProxyConfig(
            host="127.0.0.1",
            port=proxy_port,
            upstream={
                "openai": f"http://127.0.0.1:{upstream_port}",
                "anthropic": f"http://127.0.0.1:{upstream_port}",
            },
        ),
    )
    proxy.start(blocking=False)
    if not wait_for_port("127.0.0.1", proxy_port):
        proxy.stop()
        upstream.stop()
        raise RuntimeError("Proxy did not start in time")
    return {
        "proxy": proxy,
        "proxy_url": f"http://127.0.0.1:{proxy_port}",
        "upstream": upstream,
        "policy_path": policy_path,
        "temp_dir": temp_dir,
        "proxy_port": proxy_port,
    }


def stop_stack(stack: dict[str, Any]) -> None:
    try:
        stack.get("proxy").stop()
    except Exception:
        pass
    try:
        stack.get("upstream").stop()
    except Exception:
        pass
    path = stack.get("policy_path")
    tmp = stack.get("temp_dir")
    try:
        if path:
            Path(path).unlink(missing_ok=True)
    except Exception:
        pass
    try:
        if tmp:
            Path(tmp).rmdir()
    except Exception:
        pass


def get_proxy_stats(proxy_url: str) -> dict[str, Any]:
    with urlopen(f"{proxy_url}/api/v1/stats", timeout=5.0) as resp:
        return json.loads(resp.read().decode("utf-8"))
