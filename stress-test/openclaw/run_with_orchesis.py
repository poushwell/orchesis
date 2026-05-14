"""Run adversarial attacks against simulated OpenClaw agent WITH Orchesis protection."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent_setup import MockOpenClawAgent
from orchesis_guard import OrchesisToolGuard
from tools.mock_tools import log as tool_log


def run_attack(agent, guard: OrchesisToolGuard, attack_name: str, prompt_file: str):
    """Run a single protected attack and record results."""
    tool_log.calls.clear()
    prompt = (ROOT / "attacks" / prompt_file).read_text(encoding="utf-8")

    print(f"\n{'='*60}")
    print(f"ATTACK: {attack_name}")
    print("MODE: WITH Orchesis")
    print(f"{'='*60}")

    response = ""
    error = None
    try:
        response = agent.process_message(prompt, guard=guard.evaluate)
        print(f"Agent response: {response[:300]}...")
    except Exception as exc:  # noqa: BLE001
        error = str(exc)
        print(f"Error: {error}")

    summary = tool_log.summary()
    print("\nResults:")
    print(f"  Tool calls made: {summary['total_calls']}")
    print(f"  Blocked calls: {summary['blocked']}")
    print(f"  Dangerous tools used: {summary['dangerous_tools_used']}")
    print(f"  Secrets leaked: {summary['secrets_leaked']}")
    print(f"  Sensitive files read: {summary['sensitive_files_read']}")

    return {
        "attack": attack_name,
        "framework": "openclaw",
        "protected": True,
        "skipped": False,
        "error": error,
        "response_preview": response[:500] if response else "",
        "summary": summary,
        "tool_calls": json.loads(tool_log.to_json()),
    }


def main():
    agent = MockOpenClawAgent()
    guard = OrchesisToolGuard(ROOT / "policies" / "protective_policy.yaml")
    results = []

    results.append(run_attack(agent, guard, "prompt_injection", "prompt_injection.txt"))
    results.append(run_attack(agent, guard, "secret_exfiltration", "exfiltration_prompt.txt"))
    results.append(run_attack(agent, guard, "path_traversal", "path_traversal_prompt.txt"))

    output_dir = ROOT / "results"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "openclaw_with_orchesis.json"
    output_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nResults saved to {output_path}")


if __name__ == "__main__":
    main()
