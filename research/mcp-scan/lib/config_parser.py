"""Parse MCP config formats into normalized server entries."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass
class MCPServerEntry:
    name: str
    command: str
    args: list[str]
    env: dict[str, str]
    url: str
    source_repo: str
    source_path: str
    config_type: str


def parse_config(content: str, config_type: str = "auto") -> list[MCPServerEntry]:
    try:
        loaded = json.loads(content)
    except Exception:
        return []
    if not isinstance(loaded, dict):
        return []

    inferred = _infer_type(loaded) if config_type == "auto" else config_type
    out: list[MCPServerEntry] = []

    if isinstance(loaded.get("mcpServers"), dict):
        servers = loaded["mcpServers"]
        for name, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            out.append(
                MCPServerEntry(
                    name=str(name),
                    command=str(cfg.get("command", "")),
                    args=_list_str(cfg.get("args")),
                    env=_dict_str(cfg.get("env")),
                    url=str(cfg.get("url", cfg.get("endpoint", ""))),
                    source_repo="",
                    source_path="",
                    config_type=inferred if inferred != "auto" else "claude_desktop",
                )
            )

    if isinstance(loaded.get("mcp-servers"), dict):
        servers_alt = loaded.get("mcp-servers")
        for name, cfg in servers_alt.items():
            if not isinstance(cfg, dict):
                continue
            out.append(
                MCPServerEntry(
                    name=str(name),
                    command=str(cfg.get("command", "")),
                    args=_list_str(cfg.get("args")),
                    env=_dict_str(cfg.get("env")),
                    url=str(cfg.get("url", cfg.get("endpoint", ""))),
                    source_repo="",
                    source_path="",
                    config_type="generic",
                )
            )

    if isinstance(loaded.get("servers"), list):
        for idx, item in enumerate(loaded["servers"]):
            if not isinstance(item, dict):
                continue
            out.append(
                MCPServerEntry(
                    name=str(item.get("name", f"server_{idx}")),
                    command=str(item.get("command", "")),
                    args=_list_str(item.get("args")),
                    env=_dict_str(item.get("env")),
                    url=str(item.get("url", item.get("endpoint", ""))),
                    source_repo="",
                    source_path="",
                    config_type="generic",
                )
            )
    return out


def _infer_type(loaded: dict[str, Any]) -> str:
    if isinstance(loaded.get("mcpServers"), dict):
        return "claude_desktop"
    if isinstance(loaded.get("mcp-servers"), dict) or isinstance(loaded.get("servers"), list):
        return "generic"
    return "generic"


def _list_str(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _dict_str(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    out: dict[str, str] = {}
    for key, item in value.items():
        out[str(key)] = str(item)
    return out
