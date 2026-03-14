# Privacy & Data Handling

## Overview

Orchesis is a **self-hosted** proxy. It runs on YOUR infrastructure, under YOUR control. The Orchesis project developers **never** receive, collect, or have access to any data processed by your Orchesis instance.

## What Orchesis Processes Locally

When running on your infrastructure, Orchesis may process:

- **HTTP requests/responses** between your AI agents and LLM providers
- **API keys** (passed through to upstream, filtered from logs by default)
- **Prompt content** (analyzed by detection pipeline, never stored unless recording is enabled)
- **Response content** (analyzed for anomalies, never stored unless recording is enabled)
- **Session metadata** (timestamps, model names, token counts, costs)
- **Agent identifiers** (user-agent strings, behavioral fingerprints)

## What Orchesis Does NOT Do

- ❌ Does not send any data to Orchesis developers or any third party
- ❌ Does not include telemetry or usage analytics
- ❌ Does not phone home, check for updates via network, or beacon
- ❌ Does not store API keys (passes through, filters from logs)
- ❌ Does not require an account, registration, or license key
- ❌ Does not use cookies or browser tracking in the dashboard

## Data Storage

By default, Orchesis stores **nothing persistently**. All data is in-memory and lost when the proxy stops.

Optional features that store data locally (on YOUR disk):

| Feature | What is stored | Location | Enabled by default |
|---------|---------------|----------|-------------------|
| Session Recording | Full request/response pairs | Configurable path | **No** |
| JSONL Audit Log | Event summaries (no full content) | Configurable path | **No** |
| Hooks Log | Tool call summaries | ~/.orchesis/hooks.log | **No** |

## Your Responsibilities

If you use Orchesis to process data:

- **You are the data controller** for any personal data processed through the proxy
- If processing data of EU residents, GDPR applies to YOU (not to Orchesis developers)
- If processing data of California residents, CCPA applies to YOU
- Orchesis provides tools to help you comply:
  - `recording: disabled` (default) — no persistent storage
  - Session deletion API — remove recorded sessions
  - Secrets filter — prevents API keys from appearing in logs
  - Dashboard runs locally — no external access unless you configure it

## Deleting Data

- Stop the proxy → all in-memory data is gone
- Delete recording files → session data is gone
- Delete hooks.log → hook audit data is gone
- Delete ~/.orchesis/ → all local config and logs are gone

## Contact

Questions about privacy or data handling: security@orchesis.io

