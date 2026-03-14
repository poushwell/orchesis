"""Interactive quickstart wizard for Orchesis."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any


class QuickstartWizard:
    """One-command setup for Orchesis."""

    PRESETS: dict[str, dict[str, Any]] = {
        "openclaw": {
            "description": "Optimized for OpenClaw (Claude Code)",
            "upstream": "https://api.anthropic.com",
            "features": ["security", "cost", "context_optimizer", "loop_detection"],
        },
        "openai": {
            "description": "For OpenAI API agents",
            "upstream": "https://api.openai.com",
            "features": ["security", "cost", "semantic_cache"],
        },
        "generic": {
            "description": "Works with any LLM provider",
            "upstream": "https://api.openai.com",
            "features": ["security", "cost"],
        },
        "minimal": {
            "description": "Just proxy + dashboard, no detection",
            "upstream": "https://api.openai.com",
            "features": ["dashboard"],
        },
    }

    def run(
        self,
        non_interactive: bool = False,
        preset: str | None = None,
        budget: float = 10.0,
        output_path: str | Path = "orchesis.yaml",
    ) -> Path:
        """Run quickstart wizard and return generated config path."""
        chosen = str(preset or "").strip().lower()
        if chosen and chosen not in self.PRESETS:
            chosen = "generic"
        if not chosen:
            env = self._detect_environment()
            if env.get("has_claude_dir"):
                chosen = "openclaw"
            elif env.get("has_openai_key"):
                chosen = "openai"
            elif env.get("has_anthropic_key"):
                chosen = "openclaw"
            else:
                chosen = "generic"

        selected_budget = float(max(0.0, budget))
        selected_features = list(self.PRESETS[chosen]["features"])
        if not non_interactive:
            chosen = self._ask_provider(default=chosen)
            selected_budget = self._ask_budget(default=selected_budget)
            selected_features = self._ask_features(default=selected_features)

        config_text = self._generate_config(chosen, selected_budget, selected_features)
        config_path = Path(output_path).expanduser().resolve()
        self._write_config(config_text, config_path)
        self._print_next_steps(config_path, chosen)
        return config_path

    def _detect_environment(self) -> dict[str, bool]:
        """Auto-detect installed agents and API keys."""
        return {
            "has_claude_dir": (Path.home() / ".claude").exists(),
            "has_openai_key": bool(os.environ.get("OPENAI_API_KEY")),
            "has_anthropic_key": bool(os.environ.get("ANTHROPIC_API_KEY")),
        }

    def _ask_provider(self, default: str = "generic") -> str:
        choices = ", ".join(self.PRESETS.keys())
        response = input(f"Preset [{choices}] (default: {default}): ").strip().lower()
        if response in self.PRESETS:
            return response
        return default

    def _ask_budget(self, default: float = 10.0) -> float:
        response = input(f"Daily budget USD (default: {default:.2f}): ").strip()
        if not response:
            return default
        try:
            return max(0.0, float(response))
        except Exception:
            return default

    def _ask_features(self, default: list[str]) -> list[str]:
        response = input(
            "Enable features (comma-separated, Enter for preset defaults): "
        ).strip()
        if not response:
            return list(default)
        features = [item.strip() for item in response.split(",") if item.strip()]
        return features or list(default)

    def _generate_config(self, preset: str, budget: float, features: list[str]) -> str:
        spec = self.PRESETS.get(preset, self.PRESETS["generic"])
        upstream = str(spec["upstream"])
        enabled = set(features)

        lines = [
            "rules: []",
            "proxy:",
            '  host: "0.0.0.0"',
            "  port: 8080",
            "  timeout: 300",
            "upstream:",
            f'  url: "{upstream}"',
            "dashboard:",
            "  enabled: true",
            "budgets:",
            f"  daily: {float(max(0.0, budget)):.2f}",
            "recording:",
            "  enabled: false",
        ]
        if "security" in enabled:
            lines.extend(["threat_intel:", "  enabled: true"])
        if "cost" in enabled:
            lines.extend(["cost_optimizer:", "  enabled: true"])
        if "context_optimizer" in enabled:
            lines.extend(
                [
                    "context_optimizer:",
                    "  enabled: true",
                    "  dedup_system_prompt: true",
                    "  remove_stale_messages: true",
                    "  dedup_tool_definitions: true",
                    "  remove_ack_messages: true",
                    "  merge_consecutive: true",
                ]
            )
        if "loop_detection" in enabled:
            lines.extend(["loop_detection:", "  enabled: true"])
        if "semantic_cache" in enabled:
            lines.extend(["semantic_cache:", "  enabled: true"])
        if preset == "minimal":
            lines = [
                "rules: []",
                "proxy:",
                '  host: "0.0.0.0"',
                "  port: 8080",
                "upstream:",
                f'  url: "{upstream}"',
                "dashboard:",
                "  enabled: true",
            ]
        return "\n".join(lines) + "\n"

    @staticmethod
    def _write_config(config_str: str, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(config_str, encoding="utf-8")

    @staticmethod
    def _print_next_steps(config_path: Path, preset: str) -> None:
        print(f"[OK] Config written to {config_path}")
        print("")
        print("Next steps:")
        print(f"  1. Start proxy:  orchesis proxy --config {config_path}")
        print("  2. Point your agent to: http://localhost:8080")
        print("  3. Open dashboard: http://localhost:8080/dashboard")
        print("")
        if preset == "openclaw":
            print("Optional for Claude Code:")
            print("  orchesis hooks install")
            print("")
        print("Or try demo mode first:")
        print("  orchesis demo")

