"""GitHub Code Search API client for finding MCP configs.

Uses GitHub REST API v3 code search.
Requires GITHUB_TOKEN env var for best limits.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


class GitHubCodeSearchClient:
    def __init__(self, token: str | None = None) -> None:
        self._token = token or os.getenv("GITHUB_TOKEN", "")
        self._api_base = "https://api.github.com"
        self._last_rate_headers: dict[str, str] = {}

    def search_code(self, query: str, per_page: int = 100, max_pages: int = 10) -> list[dict[str, str]]:
        per_page = max(1, min(100, int(per_page)))
        max_pages = max(1, int(max_pages))
        out: list[dict[str, str]] = []
        seen: set[str] = set()

        for page in range(1, max_pages + 1):
            self._respect_rate_limit()
            params = urlencode({"q": query, "per_page": per_page, "page": page})
            url = f"{self._api_base}/search/code?{params}"
            payload = self._json_request(url)
            if not isinstance(payload, dict):
                break
            items = payload.get("items", [])
            if not isinstance(items, list) or not items:
                break

            for item in items:
                if not isinstance(item, dict):
                    continue
                repo = item.get("repository", {})
                full_name = str(repo.get("full_name", "")) if isinstance(repo, dict) else ""
                path = str(item.get("path", ""))
                sha = str(item.get("sha", ""))
                html_url = str(item.get("html_url", ""))
                api_url = str(item.get("url", ""))
                if not full_name or not path or not sha:
                    continue
                key = f"{full_name}:{path}"
                if key in seen:
                    continue
                seen.add(key)
                out.append(
                    {
                        "repo": full_name,
                        "path": path,
                        "url": api_url,
                        "html_url": html_url,
                        "sha": sha,
                        "raw_url": f"https://raw.githubusercontent.com/{full_name}/{sha}/{path}",
                    }
                )

            if len(items) < per_page:
                break
            time.sleep(2.0)
        return out

    def fetch_raw_content(self, raw_url: str) -> str | None:
        try:
            req = Request(raw_url, headers={"User-Agent": "orchesis-mcp-scan/1.0"})
            with urlopen(req, timeout=20) as resp:
                data = resp.read()
            return data.decode("utf-8", errors="replace")
        except (HTTPError, URLError, OSError):
            return None

    def search_mcp_configs(self) -> list[dict[str, str]]:
        queries: list[tuple[str, str]] = [
            ("filename:claude_desktop_config.json language:JSON", "claude_desktop"),
            ("filename:claude_desktop_config.json size:>100", "claude_desktop"),
            ("filename:claude_desktop_config.json created:>2025-01-01", "claude_desktop"),
            ("filename:mcp.json path:.cursor language:JSON", "cursor"),
            ('filename:mcp.json "mcpServers" language:JSON', "generic"),
            ("filename:.mcp.json language:JSON", "generic"),
            ('"mcpServers" extension:json', "generic"),
            ('"mcp-servers" extension:json', "generic"),
        ]
        out: list[dict[str, str]] = []
        seen: set[str] = set()
        for query, config_type in queries:
            rows = self.search_code(query=query, per_page=100, max_pages=10)
            for row in rows:
                key = f"{row.get('repo','')}:{row.get('path','')}"
                if key in seen:
                    continue
                seen.add(key)
                row["config_type"] = config_type
                out.append(row)
        return out

    def _json_request(self, url: str) -> Any:
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "orchesis-mcp-scan/1.0"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        req = Request(url, headers=headers)
        try:
            with urlopen(req, timeout=30) as resp:
                self._last_rate_headers = {k: str(v) for k, v in resp.headers.items()}
                body = resp.read().decode("utf-8", errors="replace")
            return json.loads(body)
        except (HTTPError, URLError, OSError, json.JSONDecodeError):
            return {}

    def _respect_rate_limit(self) -> None:
        remaining = self._last_rate_headers.get("X-RateLimit-Remaining", "")
        reset = self._last_rate_headers.get("X-RateLimit-Reset", "")
        try:
            rem = int(remaining)
        except Exception:
            rem = 999
        if rem > 0:
            return
        try:
            reset_at = int(reset)
        except Exception:
            reset_at = int(time.time()) + 30
        sleep_seconds = max(1, min(120, reset_at - int(time.time()) + 1))
        time.sleep(float(sleep_seconds))
