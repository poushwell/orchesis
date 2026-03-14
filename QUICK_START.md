# Quick Start Guide

## Use Case 1: I use OpenClaw and want security

1. Install Orchesis:
   ```bash
   pip install orchesis
   ```
2. Start proxy with OpenClaw preset:
   ```bash
   orchesis proxy --config config/orchesis_openclaw.yaml
   ```
3. In OpenClaw config, set model base URL to:
   ```text
   http://localhost:8080
   ```
4. Open dashboard:
   ```text
   http://localhost:8080/dashboard
   ```
5. Verify blocked threats and approval queue in real time.

## Use Case 2: I use CrewAI/LangChain and want cost optimization

1. Install and run proxy:
   ```bash
   pip install orchesis
   orchesis proxy --config config/orchesis_example.yaml
   ```
2. Point your framework LLM endpoint to `http://localhost:8080`.
3. Keep provider API keys unchanged; Orchesis passes them upstream.
4. Validate cost optimizations in dashboard:
   - context savings
   - cache hit rate
   - cost velocity and 24h projection

## Use Case 3: I just want to see the dashboard

1. Start demo mode:
   ```bash
   orchesis demo --port 8080
   ```
2. Open:
   ```text
   http://localhost:8080/dashboard
   ```
3. Explore sample data:
   - compliance overview
   - approvals workflow
   - flow x-ray

## Use Case 4: I want to audit my OpenClaw deployment

1. Run audit command:
   ```bash
   orchesis audit-openclaw --config /path/to/openclaw.json --format text
   ```
2. Export machine-readable results:
   ```bash
   orchesis audit-openclaw --config /path/to/openclaw.json --format json
   ```
3. Use markdown output for reports:
   ```bash
   orchesis audit-openclaw --config /path/to/openclaw.json --format markdown
   ```

