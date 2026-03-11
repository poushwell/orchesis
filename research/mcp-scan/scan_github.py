#!/usr/bin/env python3
"""
Scan GitHub for public MCP server configs.

Usage:
    python research/mcp-scan/scan_github.py
    python research/mcp-scan/scan_github.py --max-configs 500
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from dataclasses import asdict
from pathlib import Path

from lib.config_parser import MCPServerEntry, parse_config
from lib.github_client import GitHubCodeSearchClient
from lib.security_checks import run_all_checks


def _repo_hash(repo_full_name: str) -> str:
    return hashlib.sha256(repo_full_name.encode("utf-8")).hexdigest()[:16]


def _safe_path(path: str) -> str:
    return path.replace("\\", "/").strip()


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan GitHub MCP config files.")
    parser.add_argument("--max-configs", type=int, default=0, help="Limit number of configs for testing.")
    args = parser.parse_args()

    root = Path(__file__).resolve().parent
    data_dir = root / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    out_path = data_dir / "configs.jsonl"

    client = GitHubCodeSearchClient()
    results = client.search_mcp_configs()
    if args.max_configs and args.max_configs > 0:
        results = results[: args.max_configs]

    total = 0
    parsed_ok = 0
    with out_path.open("w", encoding="utf-8") as handle:
        for row in results:
            repo = str(row.get("repo", ""))
            path = _safe_path(str(row.get("path", "")))
            raw_url = str(row.get("raw_url", ""))
            config_type = str(row.get("config_type", "generic"))
            repo_id = _repo_hash(repo)

            content = client.fetch_raw_content(raw_url)
            if content is None:
                payload = {
                    "repo_hash": repo_id,
                    "path": path,
                    "config_type": config_type,
                    "servers": [],
                    "findings": [],
                    "parse_error": "fetch_failed",
                }
                handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
                total += 1
                time.sleep(0.5)
                continue

            servers = parse_config(content, config_type=config_type)
            normalized: list[MCPServerEntry] = []
            for server in servers:
                server.source_repo = repo_id
                server.source_path = path
                server.config_type = config_type
                normalized.append(server)

            findings = run_all_checks(normalized)
            payload = {
                "repo_hash": repo_id,
                "path": path,
                "config_type": config_type,
                "servers": [asdict(item) for item in normalized],
                "findings": [item.to_dict() for item in findings],
                "parse_error": "",
            }
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
            total += 1
            if normalized:
                parsed_ok += 1
            time.sleep(0.5)

    print(f"Saved {total} config records to {out_path}")
    print(f"Configs with parsed servers: {parsed_ok}")


if __name__ == "__main__":
    main()
