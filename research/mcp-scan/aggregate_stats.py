#!/usr/bin/env python3
"""Generate article-ready statistics and ASCII charts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _bar(percent: float, width: int = 30) -> str:
    percent = max(0.0, min(100.0, percent))
    fill = int((percent / 100.0) * width)
    return "[" + ("#" * fill).ljust(width, "-") + f"] {percent:.1f}%"


def _load(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return raw if isinstance(raw, dict) else {}


def main() -> None:
    root = Path(__file__).resolve().parent
    analysis_path = root / "results" / "analysis.json"
    out_path = root / "results" / "article_stats.md"
    data = _load(analysis_path)

    total = int(data.get("total_configs_scanned", 0))
    repos = int(data.get("unique_repositories", 0))
    with_findings = int(data.get("configs_with_findings", 0))
    with_critical = int(data.get("configs_with_critical", 0))
    top_packages = data.get("top_packages", [])

    pct_findings = (with_findings / total * 100.0) if total else 0.0
    pct_critical = (with_critical / total * 100.0) if total else 0.0
    unique_packages = len(top_packages) if isinstance(top_packages, list) else 0

    check_rows = data.get("findings_by_check_id", [])
    mcp001 = next((row for row in check_rows if row.get("check_id") == "MCP-001"), None)
    mcp004 = next((row for row in check_rows if row.get("check_id") == "MCP-004"), None)
    mcp008 = next((row for row in check_rows if row.get("check_id") == "MCP-008"), None)

    mcp001_pct = float(mcp001.get("percent_of_configs", 0.0)) if isinstance(mcp001, dict) else 0.0
    mcp004_pct = float(mcp004.get("percent_of_configs", 0.0)) if isinstance(mcp004, dict) else 0.0
    mcp008_pct = float(mcp008.get("percent_of_configs", 0.0)) if isinstance(mcp008, dict) else 0.0

    severity_map = {str(row.get("severity", "")).lower(): int(row.get("count", 0)) for row in data.get("findings_by_severity", []) if isinstance(row, dict)}
    total_findings = int(data.get("total_findings", 0))

    lines: list[str] = []
    lines.append("# MCP Config Scan Results - Article Statistics")
    lines.append("")
    lines.append("## Headline Numbers")
    lines.append(f"- **{total} configs** scanned from **{repos} unique repositories**")
    lines.append(f"- **{pct_findings:.1f}%** contain at least one security finding")
    lines.append(f"- **{pct_critical:.1f}%** contain at least one CRITICAL finding")
    lines.append(f"- **{unique_packages}** unique MCP server packages observed (Top-10 window)")
    lines.append("")
    lines.append("## Key Findings")
    lines.append(f"1. **{mcp001_pct:.1f}% of configs contain hardcoded API keys** (MCP-001)")
    lines.append(f"   {_bar(mcp001_pct)}")
    lines.append(f"2. **{mcp004_pct:.1f}% grant shell access** (MCP-004)")
    lines.append(f"   {_bar(mcp004_pct)}")
    lines.append(f"3. **{mcp008_pct:.1f}% have no version pinning** (MCP-008)")
    lines.append(f"   {_bar(mcp008_pct)}")
    lines.append("")
    lines.append("## Severity Distribution")
    for key in ("critical", "high", "medium", "low", "info"):
        count = severity_map.get(key, 0)
        pct = (count / total_findings * 100.0) if total_findings else 0.0
        lines.append(f"{key.capitalize():8}: {count} ({pct:.1f}%)")
    lines.append("")
    lines.append("## Top 10 MCP Packages")
    if isinstance(top_packages, list):
        for idx, item in enumerate(top_packages[:10], start=1):
            if not isinstance(item, dict):
                continue
            lines.append(f"{idx}. {item.get('name', '')} ({item.get('count', 0)} configs)")
    lines.append("")
    lines.append("## Privacy")
    lines.append("- Repository identifiers are hashed in stored data.")
    lines.append("- No owner names or repository URLs are included in article outputs.")
    lines.append("- Secrets are redacted to pattern-only forms (for example, `sk-proj-****`).")
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
