# Horror Stories: Real AI Agent Attacks

This package contains realistic adversarial scenarios that show how an agent can behave dangerously without runtime controls, and how policy enforcement blocks those same paths.

## What this is

- 27 practical "horror story" scenarios
- Each story runs in two modes:
  - without Orchesis (`[VULNERABLE]`)
  - with Orchesis (`[BLOCKED]` or `[PARTIAL]`)
- All attacks use simulated tools only. Nothing dangerous is executed.

## Run

```bash
cd stress-test/horror_stories
python run_all_stories.py
```

Outputs:

- `results/stories_report.md`
- `results/stories_data.json`

## Categories

- Prompt Injection
- Data Exfiltration
- Tool Abuse
- Supply Chain
- Evasion
- Financial

## How stories work

Each module exposes `get_story()`. It executes the same attack function in both modes and returns a structured `StoryResult` with:

- narrative and impact
- blocking policy section
- MITRE ATLAS / OWASP ASI references when available
- per-mode tool-call evidence

## Security references

- MITRE ATLAS: https://atlas.mitre.org/
- OWASP Agentic Security Initiative (ASI): https://owasp.org/www-project-top-10-for-large-language-model-applications/

## Important

- These are simulation scenarios for validation and training.
- They demonstrate failure patterns that are realistic in production AI systems.
- Partial outcomes are explicitly marked for known hard cases (paraphrase and ultra-slow exfiltration).

