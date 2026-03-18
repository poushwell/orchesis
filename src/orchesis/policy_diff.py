"""Policy diff helper for Orchesis policy versions."""

from __future__ import annotations

from typing import Any

import yaml


class PolicyDiff:
    """Compare two orchesis.yaml policy versions."""

    def _flatten(self, value: Any, prefix: str = "") -> dict[str, Any]:
        out: dict[str, Any] = {}
        if isinstance(value, dict):
            for key, item in value.items():
                name = f"{prefix}.{key}" if prefix else str(key)
                out.update(self._flatten(item, name))
            return out
        out[prefix] = value
        return out

    def compare(self, policy_a: dict, policy_b: dict) -> dict:
        flat_a = self._flatten(policy_a or {})
        flat_b = self._flatten(policy_b or {})

        keys_a = set(flat_a.keys())
        keys_b = set(flat_b.keys())

        added = {key: flat_b[key] for key in sorted(keys_b - keys_a)}
        removed = {key: flat_a[key] for key in sorted(keys_a - keys_b)}

        changed: dict[str, dict[str, Any]] = {}
        unchanged: list[str] = []
        breaking_changes: list[str] = []

        for key in sorted(keys_a & keys_b):
            old_val = flat_a[key]
            new_val = flat_b[key]
            if old_val == new_val:
                unchanged.append(key)
                continue
            changed[key] = {"old": old_val, "new": new_val}
            if self.is_breaking(key, old_val, new_val):
                breaking_changes.append(key)

        total_changes = len(added) + len(removed) + len(changed)
        if len(breaking_changes) >= 2:
            risk_level = "high"
        elif len(breaking_changes) == 1 or total_changes >= 6:
            risk_level = "medium"
        else:
            risk_level = "low"

        return {
            "added": added,
            "removed": removed,
            "changed": changed,
            "unchanged": unchanged,
            "summary": {
                "total_changes": total_changes,
                "breaking_changes": breaking_changes,
                "risk_level": risk_level,
            },
        }

    def is_breaking(self, key: str, old_val: Any, new_val: Any) -> bool:
        """Returns True if change reduces security."""
        lowered = key.lower()

        if lowered in {"threat_intel.enabled", "adaptive_detection.enabled", "loop_detection.enabled"}:
            return bool(old_val) and (not bool(new_val))

        if any(token in lowered for token in ["max_requests", "rate_limit", "max_per_minute"]):
            if isinstance(old_val, int | float) and isinstance(new_val, int | float):
                return float(new_val) < float(old_val)

        if lowered.endswith(".default_action"):
            return str(new_val).lower() == "allow" and str(old_val).lower() != "allow"

        return False

    def format_text(self, diff: dict) -> str:
        """Human-readable diff output."""
        lines: list[str] = []
        summary = diff.get("summary", {}) if isinstance(diff, dict) else {}
        total = int(summary.get("total_changes", 0) or 0)
        risk = str(summary.get("risk_level", "low"))
        breaking = list(summary.get("breaking_changes", []) or [])

        lines.append("Policy Diff")
        lines.append("-----------")
        lines.append(f"Total changes: {total}")
        lines.append(f"Risk level: {risk}")
        if breaking:
            lines.append("Breaking changes:")
            for key in breaking:
                lines.append(f"  - {key}")

        for section in ("added", "removed"):
            payload = diff.get(section, {}) if isinstance(diff, dict) else {}
            if isinstance(payload, dict) and payload:
                lines.append("")
                lines.append(section.capitalize() + ":")
                for key, value in payload.items():
                    lines.append(f"  + {key}: {value}" if section == "added" else f"  - {key}: {value}")

        changed = diff.get("changed", {}) if isinstance(diff, dict) else {}
        if isinstance(changed, dict) and changed:
            lines.append("")
            lines.append("Changed:")
            for key, values in changed.items():
                if isinstance(values, dict):
                    lines.append(f"  ~ {key}: {values.get('old')} -> {values.get('new')}")

        return "\n".join(lines)

    def format_yaml(self, diff: dict) -> str:
        """YAML-format diff."""
        return yaml.safe_dump(diff, sort_keys=False, allow_unicode=True)
