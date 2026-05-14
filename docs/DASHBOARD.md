# Dashboard

There are **two** dashboard implementations in the tree; which one you get at `/dashboard` depends on whether a **built Vite bundle** is present.

## How to open the UI

1. **Embedded in the LLM proxy (recommended)**  
   Run `orchesis proxy` (with a policy file, e.g. `--config policy.yaml`). Open:

   `http://<proxy-host>:<proxy-port>/dashboard`

   The proxy serves this path from `get_dashboard_html()` in `src/orchesis/dashboard.py` (`proxy.py` routes `/dashboard` and `/dashboard/`).

2. **`orchesis dashboard` CLI**  
   Prints a URL and opens the browser. Default target is `http://127.0.0.1:8081/` unless `ORCHESIS_DASHBOARD_URL` is set. Use `--proxy-dashboard` to open `http://127.0.0.1:8080/dashboard` instead.  
   **Note:** The CLI does not start an HTTP server by itself; something must be listening on the URL you open, or use the proxy URL above.

---

## Built dashboard (Vite) — 8 tabs

When `dashboard/dist/index.html` exists (dev tree) or packaged assets exist under `src/orchesis/dashboard_dist/`, `get_dashboard_html()` inlines that build. Tab names are defined in `dashboard/src/components/TabBar.jsx`:

| Tab | Role (high level) |
|-----|-------------------|
| **Shield** | Status hero, threat summary, cost timeline / spark metrics (see `App.jsx`). |
| **Agents** | Table of detected agents (from `/api/dashboard/agents`). |
| **Sessions** | Session-oriented view (fetches `/api/sessions`). |
| **Flow X-Ray** | Flow / efficiency visualizations driven from polled data. |
| **Experiments** | Experiment-related metrics when present. |
| **Threats** | Threat log / stats (`/api/threats`, `/api/threats/stats`). |
| **Cache** | Cache-related stats from aggregated payload. |
| **Compliance** | Compliance summary (`/api/compliance/summary`). |

### Polling intervals (built UI)

From `dashboard/src/hooks/useApi.js`:

| Tab | Interval |
|-----|----------|
| **Shield** | **2500** ms |
| **Threats** | **2000** ms |
| All other tabs | **5000** ms |

The hook loads data in parallel from:

- `/api/dashboard/overview`
- `/stats`
- `/api/dashboard/agents`
- `/api/sessions`
- `/api/threats`
- `/api/threats/stats`
- `/api/compliance/summary`

These routes are implemented on the proxy HTTP handler in `proxy.py` (see grep for `/api/dashboard/overview`, `/api/threats`, etc.).

### Keyboard shortcuts

There are **no** documented tab-switch shortcuts in the React app. `dashboard/src/easter-eggs.js` registers a `keydown` listener for easter-egg behavior only.

---

## Fallback dashboard (tests / no dist) — 4 sections

If no dist bundle is found, or during pytest (`PYTEST_CURRENT_TEST` set), `get_dashboard_html()` falls back to `render_dashboard()` in `dashboard.py`, which uses `dashboard_components.py`:

| Section ID | Title |
|------------|--------|
| `overview` | Overview |
| `security` | Security |
| `ecosystem` | Ecosystem |
| `fleet` | Fleet |

### Modular JS refresh

`render_js()` in `dashboard_components.py` sets **`DASHBOARD_REFRESH_MS = 5000`** and polls **`/api/v1/dashboard/data`**.

The stdlib proxy in `proxy.py` exposes **`/api/dashboard/overview`** and **`/api/dashboard/agents`**, not `/api/v1/dashboard/data`. So the fallback page’s fetch URL **does not match** the proxy routes as of this codebase.

<!-- TODO: verify — align `render_js()` fetch URL with proxy routes or add `/api/v1/dashboard/data` if product intends a unified JSON aggregate endpoint. -->

---

## Summary

| Surface | Tabs / sections | Primary data endpoints |
|---------|------------------|-------------------------|
| Vite build | 8 (`TabBar.jsx`) | `/api/dashboard/*`, `/stats`, `/api/sessions`, `/api/threats*`, `/api/compliance/summary` |
| Component fallback | 4 (`dashboard_components.py`) | Intended poll: `/api/v1/dashboard/data` (see TODO above) |
