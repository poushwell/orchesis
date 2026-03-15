#!/usr/bin/env python3
"""
MVE #1: Context Deduplication Experiment
Tests whether Orchesis proxy reduces token usage across repeated sessions.

Usage:
    # Run both paths:
    OPENAI_API_KEY=sk-... python experiments/mve_context_dedup.py

    # Run only baseline (no Orchesis needed):
    OPENAI_API_KEY=sk-... python experiments/mve_context_dedup.py --baseline-only
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import date, datetime
from pathlib import Path
from typing import Any


TASK_TEXT = "Explain bubble sort algorithm and write a Python implementation"
MODEL = "gpt-4o-mini"
ITERATIONS = 10
TEMPERATURE = 0
OPENAI_BASE_URL = "https://api.openai.com/v1"
PROXY_BASE_URL = "http://127.0.0.1:8080/v1"


def _cost_usd(prompt_tokens: int, completion_tokens: int) -> float:
    return prompt_tokens * 0.00000015 + completion_tokens * 0.0000006


def _post_json(url: str, payload: dict[str, Any], headers: dict[str, str], timeout: float = 30.0) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", "application/json")
    for key, value in headers.items():
        request.add_header(key, value)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def _run_single_completion(base_url: str, api_key: str, messages: list[dict[str, str]]) -> tuple[int, int, int, str]:
    endpoint = f"{base_url.rstrip('/')}/chat/completions"
    payload = {
        "model": MODEL,
        "temperature": TEMPERATURE,
        "messages": messages,
    }
    headers = {"Authorization": f"Bearer {api_key}"}
    data = _post_json(endpoint, payload, headers=headers)
    usage = data.get("usage", {}) if isinstance(data, dict) else {}
    prompt_tokens = int(usage.get("prompt_tokens", 0))
    completion_tokens = int(usage.get("completion_tokens", 0))
    total_tokens = int(usage.get("total_tokens", prompt_tokens + completion_tokens))
    choices = data.get("choices", []) if isinstance(data, dict) else []
    message = choices[0].get("message", {}) if choices else {}
    content = str(message.get("content", ""))
    return prompt_tokens, completion_tokens, total_tokens, content


def _run_path(path_name: str, base_url: str, iterations: int, api_key: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    conversation_history: list[dict[str, str]] = []
    cumulative_tokens = 0
    cumulative_cost = 0.0

    for idx in range(1, iterations + 1):
        print(f"Path {path_name} iteration {idx}/{iterations}...")
        messages = list(conversation_history)
        messages.append({"role": "user", "content": TASK_TEXT})
        prompt_tokens = completion_tokens = total_tokens = 0
        content = ""
        last_error: str | None = None

        for _attempt in range(2):
            try:
                prompt_tokens, completion_tokens, total_tokens, content = _run_single_completion(
                    base_url=base_url,
                    api_key=api_key,
                    messages=messages,
                )
                last_error = None
                break
            except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, ValueError) as err:
                last_error = str(err)
                continue

        if last_error is not None:
            print(f"  warning: path {path_name} iteration {idx} failed after retry: {last_error}")
            continue

        cost = _cost_usd(prompt_tokens, completion_tokens)
        cumulative_tokens += total_tokens
        cumulative_cost += cost
        record = {
            "iteration": idx,
            "path": path_name,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
            "cost_usd": round(cost, 8),
            "cumulative_tokens": cumulative_tokens,
            "cumulative_cost": round(cumulative_cost, 8),
        }
        records.append(record)
        print(record)

        conversation_history.append({"role": "user", "content": TASK_TEXT})
        conversation_history.append({"role": "assistant", "content": content})

    return records


def _proxy_available(api_key: str) -> bool:
    try:
        _run_single_completion(
            base_url=PROXY_BASE_URL,
            api_key=api_key,
            messages=[{"role": "user", "content": "ping"}],
        )
        return True
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, ValueError):
        return False


def _print_summary(path_a: list[dict[str, Any]], path_b: list[dict[str, Any]]) -> dict[str, Any]:
    by_iter_a = {item["iteration"]: item for item in path_a}
    by_iter_b = {item["iteration"]: item for item in path_b}

    print("\nIteration | Tokens A | Tokens B | Savings %")
    for idx in range(1, ITERATIONS + 1):
        ta = int(by_iter_a.get(idx, {}).get("total_tokens", 0))
        tb = by_iter_b.get(idx, {}).get("total_tokens")
        if tb is None:
            print(f"{idx:<9} | {ta:<8} | {'-':<8} | {'-':>8}")
            continue
        savings = ((ta - int(tb)) / ta * 100.0) if ta > 0 else 0.0
        print(f"{idx:<9} | {ta:<8} | {int(tb):<8} | {savings:>7.2f}%")

    total_tokens_a = sum(int(item.get("total_tokens", 0)) for item in path_a)
    total_tokens_b = sum(int(item.get("total_tokens", 0)) for item in path_b)
    total_cost_a = sum(float(item.get("cost_usd", 0.0)) for item in path_a)
    total_cost_b = sum(float(item.get("cost_usd", 0.0)) for item in path_b)
    savings_tokens = total_tokens_a - total_tokens_b
    savings_usd = total_cost_a - total_cost_b
    savings_pct = (savings_tokens / total_tokens_a * 100.0) if total_tokens_a > 0 else 0.0
    proxy_duplications_detected = sum(
        1
        for idx in range(1, ITERATIONS + 1)
        if idx in by_iter_a and idx in by_iter_b and int(by_iter_b[idx]["prompt_tokens"]) < int(by_iter_a[idx]["prompt_tokens"])
    )

    print("\nTotal tokens A:   ", total_tokens_a)
    print("Total tokens B:   ", total_tokens_b)
    print("Savings tokens:   ", savings_tokens)
    print(f"Savings USD:       ${savings_usd:.6f}")
    print(f"Savings %:         {savings_pct:.2f}%")

    return {
        "total_tokens_a": total_tokens_a,
        "total_tokens_b": total_tokens_b,
        "savings_tokens": savings_tokens,
        "savings_usd": round(savings_usd, 8),
        "savings_pct": round(savings_pct, 4),
        "proxy_duplications_detected": proxy_duplications_detected,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="MVE #1: Context Deduplication Experiment")
    parser.add_argument("--baseline-only", action="store_true", help="Run baseline only and skip proxy path")
    args = parser.parse_args()

    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        print("OPENAI_API_KEY is not set.")
        print("Set it and rerun, for example:")
        print("  set OPENAI_API_KEY=sk-...            (Windows)")
        print("  export OPENAI_API_KEY=sk-...         (macOS/Linux)")
        return 0

    results_dir = Path("experiments") / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    print("Running Path A (baseline)...")
    path_a = _run_path(path_name="A", base_url=OPENAI_BASE_URL, iterations=ITERATIONS, api_key=api_key)

    path_b: list[dict[str, Any]] = []
    if args.baseline_only:
        print("Skipping Path B (--baseline-only).")
    else:
        if _proxy_available(api_key):
            print("Running Path B (proxy)...")
            path_b = _run_path(path_name="B", base_url=PROXY_BASE_URL, iterations=ITERATIONS, api_key=api_key)
        else:
            print("Warning: Orchesis proxy is not reachable at http://127.0.0.1:8080. Skipping Path B.")

    summary = _print_summary(path_a, path_b)
    today = date.today()
    payload = {
        "experiment": "mve_001_context_dedup",
        "date": today.isoformat(),
        "model": MODEL,
        "task": "bubble sort explanation",
        "iterations": ITERATIONS,
        "path_a": path_a,
        "path_b": path_b,
        "summary": summary,
        "generated_at": datetime.utcnow().isoformat() + "Z",
    }
    output_path = results_dir / f"mve_001_{today.strftime('%Y%m%d')}.json"
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"Saved results: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
