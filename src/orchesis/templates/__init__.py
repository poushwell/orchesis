"""Built-in Orchesis policy templates."""

from __future__ import annotations

from pathlib import Path

TEMPLATE_NAMES = ("minimal", "strict", "mcp_development", "multi_agent")


def template_dir() -> Path:
    return Path(__file__).resolve().parent


def template_path(name: str) -> Path:
    return template_dir() / f"{name}.yaml"


def load_template_text(name: str) -> str:
    if name not in TEMPLATE_NAMES:
        raise ValueError(f"Unknown template: {name}")
    return template_path(name).read_text(encoding="utf-8")
