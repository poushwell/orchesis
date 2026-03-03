"""Discover and run all horror story scenarios."""

from __future__ import annotations

import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
RESULTS_DIR = ROOT / "results"


def _load_module(path: Path):
    module_name = "horror_story_" + "_".join(path.with_suffix("").parts[-3:])
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _discover_story_files() -> list[Path]:
    files: list[Path] = []
    for category in sorted(ROOT.iterdir()):
        if not category.is_dir() or category.name in {"results", "__pycache__"}:
            continue
        for candidate in sorted(category.glob("[0-9][0-9]_*.py")):
            files.append(candidate)
    return files


def _render_markdown(stories: list[dict[str, Any]]) -> str:
    lines = [
        "# Horror Stories Report",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
        "| Story | Category | Without Orchesis | With Orchesis |",
        "|---|---|---|---|",
    ]
    for story in stories:
        wout = "[VULNERABLE]" if story["without_orchesis"].get("vulnerable", False) else "[SAFE]"
        if story["with_orchesis"].get("partial", False):
            w = "[PARTIAL]"
        else:
            w = "[BLOCKED]" if story["with_orchesis"].get("blocked", False) else "[VULNERABLE]"
        lines.append(f"| {story['title']} | {story['category']} | {wout} | {w} |")
    lines.append("")
    for story in stories:
        lines.append(f"## {story['story_id']} - {story['title']}")
        lines.append("")
        lines.append(story["description"])
        lines.append("")
        lines.append(f"- **Attack narrative:** {story['attack_narrative']}")
        lines.append(f"- **Policy that blocks:** {story['policy_that_blocks']}")
        lines.append(f"- **Real-world impact:** {story['real_world_impact']}")
        if story.get("mitre_atlas_id"):
            lines.append(f"- **MITRE ATLAS:** {story['mitre_atlas_id']}")
        if story.get("owasp_asi_id"):
            lines.append(f"- **OWASP ASI:** {story['owasp_asi_id']}")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    story_files = _discover_story_files()
    stories: list[dict[str, Any]] = []
    for file_path in story_files:
        module = _load_module(file_path)
        if module is None or not hasattr(module, "get_story"):
            continue
        story = module.get_story()
        stories.append(story.to_dict() if hasattr(story, "to_dict") else dict(story))

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    data_path = RESULTS_DIR / "stories_data.json"
    md_path = RESULTS_DIR / "stories_report.md"
    data_path.write_text(json.dumps(stories, indent=2, ensure_ascii=False), encoding="utf-8")
    md_path.write_text(_render_markdown(stories), encoding="utf-8")

    total = len(stories)
    without_vuln = sum(1 for item in stories if item["without_orchesis"].get("vulnerable", False))
    with_blocked = sum(1 for item in stories if item["with_orchesis"].get("blocked", False))
    with_partial = sum(1 for item in stories if item["with_orchesis"].get("partial", False))
    with_succeeded = total - with_blocked - with_partial

    print("=== Horror Stories Results ===")
    print(f"{total} stories executed")
    print(f"WITHOUT Orchesis: {without_vuln}/{total} attacks succeeded [VULNERABLE]")
    print(
        "WITH Orchesis:    "
        f"{with_succeeded}/{total} attacks succeeded "
        f"({with_blocked} BLOCKED, {with_partial} PARTIAL)"
    )
    by_category: dict[str, list[dict[str, Any]]] = {}
    for item in stories:
        by_category.setdefault(item["category"], []).append(item)
    print("Categories:")
    for category in sorted(by_category.keys()):
        entries = by_category[category]
        blocked = sum(1 for item in entries if item["with_orchesis"].get("blocked", False))
        partial = sum(1 for item in entries if item["with_orchesis"].get("partial", False))
        print(f"{category}: {blocked}/{len(entries)} blocked, {partial} partial")
    print(f"Report: {md_path}")
    print(f"Data:   {data_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

