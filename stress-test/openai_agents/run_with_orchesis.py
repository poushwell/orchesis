"""Run adversarial attacks against OpenAI Agents SDK wrapper WITH Orchesis."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent_setup import OpenAIAgentsStressAgent, FRAMEWORK_AVAILABLE, MISSING_REASON
from orchesis_guard import OrchesisToolGuard
from tools.mock_tools import log as tool_log


def _skipped_results(reason: str) -> list[dict]:
    attacks = ["prompt_injection", "secret_exfiltration", "path_traversal"]
    return [
        {
            "attack": attack,
            "framework": "openai_agents",
            "protected": True,
            "skipped": True,
            "error": f"OpenAI Agents SDK unavailable: {reason}",
            "summary": {"total_calls": 0, "blocked": 0, "secrets_leaked": 0, "dangerous_tools_used": 0, "sensitive_files_read": 0},
            "tool_calls": [],
        }
        for attack in attacks
    ]


def run_attack(agent: OpenAIAgentsStressAgent, guard: OrchesisToolGuard, attack_name: str, prompt_file: str) -> dict:
    tool_log.calls.clear()
    prompt = (ROOT / "attacks" / prompt_file).read_text(encoding="utf-8")
    response = ""
    error = None
    try:
        response = agent.process_message(prompt, guard=guard.evaluate)
    except Exception as exc:  # noqa: BLE001
        error = str(exc)
    return {
        "attack": attack_name,
        "framework": "openai_agents",
        "protected": True,
        "skipped": False,
        "error": error,
        "response_preview": response[:500] if response else "",
        "summary": tool_log.summary(),
        "tool_calls": json.loads(tool_log.to_json()),
    }


def main() -> None:
    output_dir = ROOT / "results"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "openai_agents_with_orchesis.json"

    if not FRAMEWORK_AVAILABLE:
        results = _skipped_results(MISSING_REASON)
        output_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"[SKIP] OpenAI Agents SDK not available: {MISSING_REASON}")
        return

    agent = OpenAIAgentsStressAgent()
    guard = OrchesisToolGuard(ROOT / "policies" / "protective_policy.yaml")
    results = [
        run_attack(agent, guard, "prompt_injection", "prompt_injection.txt"),
        run_attack(agent, guard, "secret_exfiltration", "exfiltration_prompt.txt"),
        run_attack(agent, guard, "path_traversal", "path_traversal_prompt.txt"),
    ]
    output_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"Results saved to {output_path}")


if __name__ == "__main__":
    main()
