"""Pre-built policy templates for common Orchesis use cases."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import yaml


POLICY_TEMPLATES = {
    "strict_security": {
        "description": "Maximum security — blocks aggressive threats",
        "use_case": "Production AI agents with sensitive data",
        "config": {
            "threat_intel": {"enabled": True},
            "loop_detection": {"enabled": True, "block_threshold": 3},
            "semantic_cache": {"enabled": True},
            "recording": {"enabled": True},
            "budgets": {"daily": 10.0, "on_hard_limit": "block"},
        },
    },
    "developer_mode": {
        "description": "Relaxed for development — logs everything",
        "use_case": "Local development and testing",
        "config": {
            "threat_intel": {"enabled": True},
            "loop_detection": {"enabled": True, "block_threshold": 12},
            "semantic_cache": {"enabled": False},
            "recording": {"enabled": True, "store_prompt_body": True},
            "budgets": {"daily": 100.0, "on_hard_limit": "warn"},
        },
    },
    "cost_optimizer": {
        "description": "Maximum token savings",
        "use_case": "High-volume production with cost pressure",
        "config": {
            "threat_intel": {"enabled": True},
            "loop_detection": {"enabled": True, "block_threshold": 5},
            "semantic_cache": {"enabled": True, "similarity_threshold": 0.82},
            "context_budget": {"enabled": True},
            "recording": {"enabled": True},
            "budgets": {"daily": 5.0, "on_hard_limit": "block"},
        },
    },
    "compliance_ready": {
        "description": "EU AI Act Article 12 compliant",
        "use_case": "Enterprise compliance requirements",
        "config": {
            "threat_intel": {"enabled": True},
            "loop_detection": {"enabled": True, "block_threshold": 4},
            "recording": {"enabled": True, "retention_days": 90},
            "audit": {"enabled": True},
            "semantic_cache": {"enabled": True},
            "budgets": {"daily": 20.0, "on_hard_limit": "warn"},
        },
    },
    "minimal": {
        "description": "Bare minimum — just proxy",
        "use_case": "Testing Orchesis integration",
        "config": {
            "threat_intel": {"enabled": False},
            "loop_detection": {"enabled": False},
            "semantic_cache": {"enabled": False},
            "recording": {"enabled": False},
            "budgets": {"daily": 0.0, "on_hard_limit": "warn"},
        },
    },
}


class PolicyTemplateManager:
    def list_templates(self) -> list[dict]:
        """List all templates with descriptions."""
        return [
            {
                "name": name,
                "description": item["description"],
                "use_case": item["use_case"],
            }
            for name, item in sorted(POLICY_TEMPLATES.items())
        ]

    def get_template(self, name: str) -> dict:
        """Get template config by name."""
        if name not in POLICY_TEMPLATES:
            raise KeyError(f"unknown template: {name}")
        return copy.deepcopy(POLICY_TEMPLATES[name])

    def apply_template(self, name: str, output_path: str) -> None:
        """Write template to orchesis.yaml."""
        template = self.get_template(name)
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            yaml.safe_dump(template["config"], sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )

    def merge_template(self, name: str, existing: dict) -> dict:
        """Merge template with existing policy."""
        base = self.get_template(name)["config"]
        existing_dict = existing if isinstance(existing, dict) else {}
        return self._merge_keep_existing(base, existing_dict)

    def _merge_keep_existing(self, defaults: dict[str, Any], current: dict[str, Any]) -> dict:
        merged: dict[str, Any] = copy.deepcopy(defaults)
        for key, value in current.items():
            if (
                key in merged
                and isinstance(merged[key], dict)
                and isinstance(value, dict)
            ):
                merged[key] = self._merge_keep_existing(merged[key], value)
            else:
                merged[key] = copy.deepcopy(value)
        return merged
