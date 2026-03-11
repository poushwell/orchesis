"""GitHub Code Search API client for finding MCP configs.

Uses GitHub REST API v3 code search.
Requires GITHUB_TOKEN env var for best limits.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any
from http.client import InvalidURL
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen


class GitHubCodeSearchClient:
    def __init__(self, token: str | None = None, verbose: bool = False) -> None:
        self._token = token or os.getenv("GITHUB_TOKEN", "")
        self._api_base = "https://api.github.com"
        self._last_rate_headers: dict[str, str] = {}
        self._verbose = bool(verbose)

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
                default_branch = str(repo.get("default_branch", "main")) if isinstance(repo, dict) else "main"
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
                        "default_branch": default_branch,
                        "path": path,
                        "url": api_url,
                        "html_url": html_url,
                        "sha": sha,
                        # Use branch-based raw URL; blob sha from search results is not always valid for raw endpoint.
                        "raw_url": f"https://raw.githubusercontent.com/{full_name}/{default_branch}/{path}",
                    }
                )

            if len(items) < per_page:
                break
            time.sleep(2.0)
        return out

    def fetch_raw_content(
        self, raw_url: str, *, repo: str = "", path: str = "", branch: str = ""
    ) -> str | None:
        try:
            raw_url = raw_url.replace(" ", "%20")
            headers = {"User-Agent": "orchesis-mcp-scan/1.0"}
            if self._token:
                headers["Authorization"] = f"Bearer {self._token}"

            effective_raw_url = raw_url
            if repo and path:
                safe_branch = branch or "main"
                encoded_path = quote(path, safe="/")
                effective_raw_url = f"https://raw.githubusercontent.com/{repo}/{safe_branch}/{encoded_path}"

            if self._verbose:
                print(f"[fetch] url={effective_raw_url}")
            try:
                req = Request(effective_raw_url, headers=headers)
                with urlopen(req, timeout=20) as resp:
                    status = int(getattr(resp, "status", 0))
                    data = resp.read()
                text = data.decode("utf-8", errors="replace")
                if self._verbose:
                    print(f"[fetch] status={status} preview={text[:200]!r}")
                if status == 200 and text:
                    return text
            except HTTPError as exc:
                try:
                    preview = exc.read().decode("utf-8", errors="replace")[:200]
                except Exception:
                    preview = ""
                if self._verbose:
                    print(f"[fetch] raw failed status={int(exc.code)} preview={preview!r}")
            except (URLError, OSError, ValueError, InvalidURL) as exc:
                if self._verbose:
                    print(f"[fetch] raw failed error={exc}")

            # Fallback: GitHub Contents API with raw accept header.
            if repo and path:
                safe_branch = branch or "main"
                encoded_path = quote(path, safe="/")
                contents_url = f"{self._api_base}/repos/{repo}/contents/{encoded_path}?ref={quote(safe_branch, safe='')}"
                contents_url = contents_url.replace(" ", "%20")
                if self._verbose:
                    print(f"[fetch] fallback={contents_url}")
                fallback_headers = {
                    "Accept": "application/vnd.github.raw",
                    "User-Agent": "orchesis-mcp-scan/1.0",
                }
                if self._token:
                    fallback_headers["Authorization"] = f"Bearer {self._token}"
                try:
                    req2 = Request(contents_url, headers=fallback_headers)
                    with urlopen(req2, timeout=20) as resp2:
                        status2 = int(getattr(resp2, "status", 0))
                        data2 = resp2.read()
                    text2 = data2.decode("utf-8", errors="replace")
                    if self._verbose:
                        print(f"[fetch] fallback status={status2} preview={text2[:200]!r}")
                    if status2 == 200 and text2:
                        return text2
                except HTTPError as exc:
                    try:
                        preview2 = exc.read().decode("utf-8", errors="replace")[:200]
                    except Exception:
                        preview2 = ""
                    if self._verbose:
                        print(f"[fetch] fallback failed status={int(exc.code)} preview={preview2!r}")
                except (URLError, OSError, ValueError, InvalidURL) as exc:
                    if self._verbose:
                        print(f"[fetch] fallback failed error={exc}")
            return None
        except Exception as exc:  # noqa: BLE001
            if self._verbose:
                print(f"[fetch] unexpected error={exc}")
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
