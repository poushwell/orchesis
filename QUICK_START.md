# Quick start

## Install

Base package is **stdlib-only** (`dependencies = []` in `pyproject.toml`). Optional extras:

```bash
pip install orchesis
pip install orchesis[yaml]    # YAML policies (PyYAML)
pip install orchesis[server]  # FastAPI + Uvicorn for `orchesis serve`
pip install orchesis[all]   # yaml + httpx + fastapi + uvicorn
pip install orchesis[dev]   # pytest, ruff, etc. (contributors)
```

Requires **Python 3.10+**.

## Configure

Create a policy file (e.g. `policy.yaml`). Minimal example:

```yaml
proxy:
  host: "127.0.0.1"
  port: 8080
  upstream:
    openai: "https://api.openai.com"
    anthropic: "https://api.anthropic.com"

budgets:
  daily: 50.0
```

YAML needs `pip install orchesis[yaml]` or `[all]`. See [docs/CONFIG.md](docs/CONFIG.md) for all sections.

## Run the LLM proxy

```bash
orchesis proxy --config policy.yaml
# or if the file is named policy.yaml / orchesis.yaml in the cwd:
orchesis proxy
```

Equivalent module form:

```bash
python -m orchesis proxy --config policy.yaml
```

Default listen port is **8100** when not set in policy; set `proxy.port` (or `--port`) to match your agent (e.g. **8080**).

## Run the API server (`serve`)

`orchesis serve` starts the FastAPI-style stack when `orchesis[server]` / `[all]` is installed. With only default options it may use the newer `orchesis.serve` path; legacy Uvicorn mode uses `policy.yaml` by default.

```bash
orchesis serve --policy policy.yaml
python -m orchesis serve --policy policy.yaml
```

## Verify

```bash
orchesis verify
python -m orchesis verify
```

## Scan MCP configs

```bash
orchesis scan --mcp
npx orchesis-scan
```

## Dashboard

With the proxy running:

```text
http://127.0.0.1:<proxy-port>/dashboard
```

CLI helper (opens browser; ensure a server is listening on the URL):

```bash
orchesis dashboard
orchesis dashboard --proxy-dashboard   # opens http://127.0.0.1:8080/dashboard
```

See [docs/DASHBOARD.md](docs/DASHBOARD.md).

## Point your agent at the proxy

Change the OpenAI-compatible base URL to your proxy origin, including the `/v1` path if the client expects it, for example:

```python
from openai import OpenAI

client = OpenAI(base_url="http://127.0.0.1:8080/v1", api_key=os.environ["OPENAI_API_KEY"])
```

## Troubleshooting

| Issue | What to check |
|-------|----------------|
| **Address already in use** | Another process on `proxy.port`; change `proxy.port` or stop the other service. |
| **Missing policy / parse error** | Path to YAML/JSON; install `orchesis[yaml]` for `.yaml` / `.yml`. |
| **Python version** | Use Python **3.10+** (`requires-python` in `pyproject.toml`). |
| **Import errors on `serve`** | Install `orchesis[server]` or `orchesis[all]`. |

---

## More recipes

### OpenClaw-oriented flow

1. `pip install orchesis[yaml]`
2. `orchesis proxy --config config/orchesis_openclaw.yaml` (adjust path to your repo)
3. Set the agent model base URL to `http://localhost:8080` (or your `proxy.host` / `proxy.port`).
4. Open `http://localhost:8080/dashboard` when `proxy.port` is 8080.

### CrewAI / LangChain

1. `orchesis proxy --config config/orchesis_example.yaml`
2. Point the framework LLM base URL to the same host/port as the proxy.
3. Provider API keys still go to the client; the proxy forwards to configured upstreams.

### Demo mode

```bash
orchesis demo --port 8080
```

Then open `http://localhost:8080/dashboard`.

### OpenClaw audit CLI

```bash
orchesis audit-openclaw --config /path/to/openclaw.json --format text
orchesis audit-openclaw --config /path/to/openclaw.json --format json
orchesis audit-openclaw --config /path/to/openclaw.json --format markdown
```

---

## Further reading

- [docs/CONFIG.md](docs/CONFIG.md) — policy reference  
- [docs/PIPELINE.md](docs/PIPELINE.md) — proxy phases  
- [docs/DASHBOARD.md](docs/DASHBOARD.md) — dashboard behavior  
- [CONTRIBUTING.md](CONTRIBUTING.md) — development  
