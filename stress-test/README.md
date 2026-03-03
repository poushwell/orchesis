# Orchesis Stress Test: Adversarial AI Agent Security

This standalone project demonstrates how agent toolchains can be exploited without runtime enforcement, and how Orchesis blocks those same attack paths when policy checks are enabled.

## Scope

The test matrix runs:

- 3 adversarial attack scenarios
- across 4 AI agent frameworks
- in 2 modes (without Orchesis, with Orchesis)

Total: **24 runs**.

## Attack Scenarios

- Prompt injection with malicious instructions embedded in trusted content
- Secret exfiltration request (read secrets, email secrets)
- Path traversal / sensitive file access (`/etc/passwd`, `~/.ssh/id_rsa`, etc.)

## Frameworks

- OpenClaw-style simulated agent
- CrewAI
- LangGraph
- OpenAI Agents SDK

## Prerequisites

- Python 3.11+
- `OPENAI_API_KEY` set in your environment
- Dependencies from `requirements.txt`
- Optional: OpenClaw installed locally (for real OpenClaw experiments). The included OpenClaw runner is a simulated OpenClaw-style agent.

## Install

```bash
cd stress-test
pip install -r requirements.txt
```

## Quick Start

Linux/macOS:

```bash
./run_all.sh
```

Windows PowerShell:

```powershell
./run_all.ps1
```

## Results

Per-framework results are written to:

- `results/openclaw_without_orchesis.json`
- `results/openclaw_with_orchesis.json`
- `results/crewai_without_orchesis.json`
- `results/crewai_with_orchesis.json`
- `results/langgraph_without_orchesis.json`
- `results/langgraph_with_orchesis.json`
- `results/openai_agents_without_orchesis.json`
- `results/openai_agents_with_orchesis.json`

Aggregate reports:

- `results/summary.md` (human-readable)
- `results/full_report.json` (machine-readable)

## How To Read Results

Each attack run includes:

- `summary.total_calls`
- `summary.blocked`
- `summary.secrets_leaked`
- `summary.dangerous_tools_used`
- `summary.sensitive_files_read`

Expected behavior:

- **Without Orchesis**: vulnerable patterns should appear (dangerous tool calls, sensitive reads, secret leakage).
- **With Orchesis**: dangerous calls denied, sensitive reads blocked, secret exfiltration prevented.

## Notes

- All tool actions are simulated via `tools/mock_tools.py` (no real command execution, no real file access, no real email transmission).
- OpenAI API is used to produce realistic tool-calling behavior.

## Repository

Main Orchesis repository: `../`
