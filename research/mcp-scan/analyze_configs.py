#!/usr/bin/env python3
"""Analyze downloaded MCP configs and produce security report."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if isinstance(obj, dict):
            out.append(obj)
    return out


def _top_package(server: dict[str, Any]) -> str:
    args = server.get("args", [])
    if not isinstance(args, list):
        return ""
    for arg in args:
        if isinstance(arg, str) and arg and not arg.startswith("-"):
            return arg
    return ""


def main() -> None:
    root = Path(__file__).resolve().parent
    data_path = root / "data" / "configs.jsonl"
    results_dir = root / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    analysis_json = results_dir / "analysis.json"
    analysis_md = results_dir / "analysis.md"

    rows = _load_jsonl(data_path)
    total_configs = len(rows)
    unique_repos = len({str(r.get("repo_hash", "")) for r in rows if str(r.get("repo_hash", ""))})
    total_servers = 0
    configs_with_findings = 0
    check_counter: Counter[str] = Counter()
    severity_counter: Counter[str] = Counter()
    category_counter: Counter[str] = Counter()
    command_counter: Counter[str] = Counter()
    package_counter: Counter[str] = Counter()
    danger_counter: Counter[str] = Counter()
    total_findings = 0

    for row in rows:
        servers = row.get("servers", [])
        findings = row.get("findings", [])
        if isinstance(servers, list):
            total_servers += len(servers)
            for srv in servers:
                if not isinstance(srv, dict):
                    continue
                command = str(srv.get("command", "")).strip().lower()
                if command:
                    command_counter[command] += 1
                pkg = _top_package(srv)
                if pkg:
                    package_counter[pkg] += 1
        if isinstance(findings, list):
            if len(findings) > 0:
                configs_with_findings += 1
            total_findings += len(findings)
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                cid = str(finding.get("check_id", ""))
                sev = str(finding.get("severity", "")).lower()
                cat = str(finding.get("category", "")).lower()
                title = str(finding.get("title", ""))
                if cid:
                    check_counter[cid] += 1
                if sev:
                    severity_counter[sev] += 1
                if cat:
                    category_counter[cat] += 1
                if title:
                    danger_counter[title] += 1

    clean_configs = total_configs - configs_with_findings
    avg_findings = (total_findings / total_configs) if total_configs else 0.0
    critical_count = severity_counter.get("critical", 0)
    with_critical = 0
    for row in rows:
        findings = row.get("findings", [])
        if not isinstance(findings, list):
            continue
        if any(str(item.get("severity", "")).lower() == "critical" for item in findings if isinstance(item, dict)):
            with_critical += 1

    check_stats = [
        {
            "check_id": k,
            "count": v,
            "percent_of_configs": round((v / total_configs) * 100.0, 2) if total_configs else 0.0,
        }
        for k, v in check_counter.most_common()
    ]
    severity_stats = [
        {
            "severity": k,
            "count": v,
            "percent_of_findings": round((v / total_findings) * 100.0, 2) if total_findings else 0.0,
        }
        for k, v in severity_counter.most_common()
    ]
    category_stats = [
        {
            "category": k,
            "count": v,
            "percent_of_findings": round((v / total_findings) * 100.0, 2) if total_findings else 0.0,
        }
        for k, v in category_counter.most_common()
    ]

    analysis: dict[str, Any] = {
        "total_configs_scanned": total_configs,
        "unique_repositories": unique_repos,
        "total_mcp_servers": total_servers,
        "total_findings": total_findings,
        "configs_with_findings": configs_with_findings,
        "configs_without_findings": clean_configs,
        "configs_with_critical": with_critical,
        "average_findings_per_config": round(avg_findings, 4),
        "findings_by_check_id": check_stats,
        "findings_by_severity": severity_stats,
        "findings_by_category": category_stats,
        "top_packages": [{"name": k, "count": v} for k, v in package_counter.most_common(10)],
        "top_commands": [{"name": k, "count": v} for k, v in command_counter.most_common(10)],
        "most_dangerous_patterns": [{"title": k, "count": v} for k, v in danger_counter.most_common(10)],
    }
    analysis_json.write_text(json.dumps(analysis, ensure_ascii=False, indent=2), encoding="utf-8")

    lines: list[str] = []
    lines.append("# MCP Config Security Analysis")
    lines.append("")
    lines.append(f"- Total configs scanned: **{total_configs}**")
    lines.append(f"- Unique repositories (anonymized): **{unique_repos}**")
    lines.append(f"- Total MCP servers found: **{total_servers}**")
    lines.append(f"- Configs with findings: **{configs_with_findings}**")
    lines.append(f"- Configs with critical findings: **{with_critical}**")
    lines.append(f"- Average findings per config: **{avg_findings:.2f}**")
    lines.append("")
    lines.append("## Findings by Check ID")
    for item in check_stats[:20]:
        lines.append(f"- {item['check_id']}: {item['count']} ({item['percent_of_configs']}%)")
    lines.append("")
    lines.append("## Severity Distribution")
    for item in severity_stats:
        lines.append(f"- {item['severity']}: {item['count']} ({item['percent_of_findings']}%)")
    lines.append("")
    lines.append("## Top 10 MCP Packages")
    for item in analysis["top_packages"]:
        lines.append(f"- {item['name']}: {item['count']}")
    lines.append("")
    lines.append("## Top 10 Commands")
    for item in analysis["top_commands"]:
        lines.append(f"- {item['name']}: {item['count']}")
    lines.append("")
    lines.append("## Most Dangerous Patterns (Anonymized)")
    for item in analysis["most_dangerous_patterns"]:
        lines.append(f"- {item['title']}: {item['count']}")
    lines.append("")
    analysis_md.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {analysis_json}")
    print(f"Wrote {analysis_md}")


if __name__ == "__main__":
    main()
