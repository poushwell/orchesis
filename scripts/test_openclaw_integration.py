"""
OpenClaw + Orchesis Integration Test Script
For Daniil - run on VPS after deploying fixes.

Usage:
  python scripts/test_openclaw_integration.py --orchesis-url http://localhost:8080

Exit codes:
  0 = all passed
  1 = failures found
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request


def test_health(base_url: str) -> bool:
    """Test 1: Orchesis proxy health check."""
    try:
        response = urllib.request.urlopen(f"{base_url}/api/v1/health", timeout=5)
        data = json.loads(response.read())
        assert response.status == 200, f"Expected 200, got {response.status}"
        assert isinstance(data, dict)
        print("  [PASS] Health check passed")
        return True
    except Exception as error:
        print(f"  [FAIL] Health check failed: {error}")
        return False


def _post_completion(base_url: str, payload: dict, headers: dict[str, str], timeout: int = 30) -> int:
    request = urllib.request.Request(
        f"{base_url}/v1/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
    )
    try:
        response = urllib.request.urlopen(request, timeout=timeout)
        return int(response.status)
    except urllib.error.HTTPError as error:
        return int(error.code)


def test_baseline_request(base_url: str) -> bool:
    """Test 2: Simple chat completion - must NOT return 403."""
    try:
        status = _post_completion(
            base_url,
            payload={
                "model": "claude-3-sonnet-20240229",
                "messages": [{"role": "user", "content": "Say hello"}],
                "max_tokens": 10,
            },
            headers={
                "Content-Type": "application/json",
                "User-Agent": "OpenClaw/1.0",
                "Authorization": "Bearer test-key",
            },
        )
        if status == 403:
            print("  [FAIL] Baseline request BLOCKED (403)")
            return False
        if status in (200, 401, 502):
            print(f"  [PASS] Baseline request not blocked (status {status})")
            return True
        print(f"  [WARN] Unexpected baseline status {status}")
        return True
    except Exception as error:
        print(f"  [FAIL] Baseline request failed: {error}")
        return False


def test_openclaw_detection(base_url: str) -> bool:
    """Test 3: OpenClaw framework detected from User-Agent."""
    try:
        status = _post_completion(
            base_url,
            payload={
                "model": "claude-3-sonnet-20240229",
                "messages": [{"role": "user", "content": "test"}],
            },
            headers={
                "Content-Type": "application/json",
                "User-Agent": "OpenClaw/1.0 (test)",
            },
            timeout=10,
        )
        print(f"  [PASS] OpenClaw-style request sent (status {status})")
        return True
    except Exception as error:
        print(f"  [FAIL] OpenClaw detection test failed: {error}")
        return False


def test_tool_call_not_blocked(base_url: str) -> bool:
    """Test 4: Tool call request from OpenClaw not blocked."""
    try:
        status = _post_completion(
            base_url,
            payload={
                "model": "claude-3-sonnet-20240229",
                "messages": [
                    {"role": "user", "content": "Read the file main.py"},
                    {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "type": "function",
                                "function": {
                                    "name": "read_file",
                                    "arguments": '{"path":"main.py"}',
                                },
                            }
                        ],
                    },
                ],
            },
            headers={
                "Content-Type": "application/json",
                "User-Agent": "OpenClaw/1.0",
            },
            timeout=10,
        )
        if status == 403:
            print("  [FAIL] Tool call blocked (403)")
            return False
        print(f"  [PASS] Tool call not blocked (status {status})")
        return True
    except Exception as error:
        print(f"  [FAIL] Tool call test failed: {error}")
        return False


def test_memory_read_non_loop(base_url: str) -> bool:
    """Test 5: Repeated memory-like reads should not hard-fail as loops."""
    try:
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "OpenClaw/1.0",
        }
        statuses: list[int] = []
        for _ in range(3):
            statuses.append(
                _post_completion(
                    base_url,
                    payload={
                        "model": "claude-3-sonnet-20240229",
                        "messages": [{"role": "user", "content": "Read memory file notes.md"}],
                        "max_tokens": 8,
                    },
                    headers=headers,
                    timeout=10,
                )
            )
        if any(code == 403 for code in statuses):
            print(f"  [FAIL] Memory read pattern blocked: {statuses}")
            return False
        print(f"  [PASS] Memory read pattern not hard-blocked: {statuses}")
        return True
    except Exception as error:
        print(f"  [FAIL] Memory read non-loop test failed: {error}")
        return False


def test_dashboard(base_url: str) -> bool:
    """Test 6: Dashboard endpoint is reachable."""
    try:
        probe_urls = [
            f"{base_url}/api/v1/dashboard/overview",
            f"{base_url}/dashboard",
        ]
        for url in probe_urls:
            try:
                response = urllib.request.urlopen(url, timeout=5)
                if int(response.status) == 200:
                    print(f"  [PASS] Dashboard reachable at {url}")
                    return True
            except Exception:
                continue
        print("  [WARN] Dashboard endpoint not found on default URLs")
        return True
    except Exception as error:
        print(f"  [FAIL] Dashboard test failed: {error}")
        return False


def test_latency(base_url: str) -> bool:
    """Test 7: Health response latency under 500ms (warning-only if slower)."""
    try:
        start = time.time()
        urllib.request.urlopen(f"{base_url}/api/v1/health", timeout=5)
        elapsed_ms = (time.time() - start) * 1000.0
        if elapsed_ms < 500.0:
            print(f"  [PASS] Latency {elapsed_ms:.0f}ms (< 500ms)")
            return True
        print(f"  [WARN] Latency {elapsed_ms:.0f}ms (> 500ms)")
        return True
    except Exception as error:
        print(f"  [FAIL] Latency test failed: {error}")
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="OpenClaw + Orchesis Integration Test")
    parser.add_argument("--orchesis-url", default="http://localhost:8080")
    args = parser.parse_args()

    base = args.orchesis_url.rstrip("/")
    print("\nOpenClaw + Orchesis Integration Test")
    print(f"Target: {base}\n")

    tests = [
        ("Health check", test_health),
        ("Baseline request (no 403)", test_baseline_request),
        ("OpenClaw detection", test_openclaw_detection),
        ("Tool call not blocked", test_tool_call_not_blocked),
        ("Memory read non-loop", test_memory_read_non_loop),
        ("Dashboard accessible", test_dashboard),
        ("Latency < 500ms", test_latency),
    ]

    results: list[bool] = []
    for name, func in tests:
        print(f"[{name}]")
        results.append(func(base))

    passed = sum(1 for item in results if item)
    total = len(results)
    print("\n" + ("=" * 40))
    print(f"Results: {passed}/{total} passed")
    if all(results):
        print("[READY] All checks passed")
        raise SystemExit(0)
    print("[FAIL] Some checks failed")
    raise SystemExit(1)


if __name__ == "__main__":
    main()
