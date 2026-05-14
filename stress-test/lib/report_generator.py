from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class ReportGenerator:
    """Generate markdown/json artifacts for stress test run."""

    def __init__(self, results: dict[str, Any]) -> None:
        self._results = results

    def generate_markdown(self) -> str:
        meta = self._results.get("meta", {})
        scenarios: list[dict[str, Any]] = self._results.get("scenarios", [])
        lines: list[str] = []
        lines.append("# Orchesis Stress Test Report")
        lines.append("")
        lines.append(f"**Date:** {meta.get('date', datetime.now(timezone.utc).date().isoformat())}")
        lines.append(f"**Version:** {meta.get('version', 'unknown')}")
        lines.append(f"**Platform:** {meta.get('platform', 'unknown')}")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append("| Scenario | Result | Key Metric |")
        lines.append("|----------|--------|------------|")
        for item in scenarios:
            icon = "✅ PASS" if item.get("passed", False) else "❌ FAIL"
            lines.append(
                f"| {item.get('name', item.get('id', 'unknown'))} | {icon} | {item.get('key_metric', '-') } |"
            )
        lines.append("")
        lines.append("## Detailed Results")
        lines.append("")
        for item in scenarios:
            lines.append(f"### {item.get('id', 'scenario')} — {item.get('name', '')}")
            lines.append("")
            lines.append(f"- Result: {'PASS' if item.get('passed') else 'FAIL'}")
            lines.append(f"- Key metric: {item.get('key_metric', '-')}")
            details = item.get("details", {})
            for key, value in details.items():
                lines.append(f"- {key}: {value}")
            lat = item.get("latencies_ms", [])
            if isinstance(lat, list) and lat:
                lines.append("")
                lines.append("Latency chart:")
                lines.append("")
                lines.extend(self._ascii_histogram(lat, bins=8, width=30))
            lines.append("")
        return "\n".join(lines).strip() + "\n"

    def generate_json(self) -> str:
        return json.dumps(self._results, ensure_ascii=False, indent=2)

    def save(self, path: str = "stress-test/results/report.md") -> tuple[str, str]:
        md_path = Path(path)
        md_path.parent.mkdir(parents=True, exist_ok=True)
        md = self.generate_markdown()
        md_path.write_text(md, encoding="utf-8")

        json_path = md_path.with_suffix(".json")
        json_path.write_text(self.generate_json(), encoding="utf-8")
        return str(md_path), str(json_path)

    @staticmethod
    def _ascii_histogram(values: list[float], bins: int = 8, width: int = 30) -> list[str]:
        if not values:
            return ["(no data)"]
        low = min(values)
        high = max(values)
        if high <= low:
            return [f"[{low:.2f} .. {high:.2f}] {'#' * max(1, width // 2)} ({len(values)})"]
        step = (high - low) / float(max(1, bins))
        counts = [0 for _ in range(bins)]
        for val in values:
            idx = int((val - low) / step)
            if idx >= bins:
                idx = bins - 1
            counts[idx] += 1
        peak = max(counts) if counts else 1
        out: list[str] = []
        for i, count in enumerate(counts):
            left = low + (i * step)
            right = left + step
            bar_len = int((count / max(1, peak)) * width)
            out.append(f"{left:7.2f}-{right:7.2f} | {'#' * max(1, bar_len)} ({count})")
        return out
