"""Example FastAPI middleware that enforces Orchesis checks."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from orchesis.client import OrchesisClient

app = FastAPI()
orchesis = OrchesisClient("http://localhost:8080", api_token="orch_sk_example")


@app.middleware("http")
async def orchesis_middleware(request: Request, call_next):
    if request.url.path.startswith("/tool/") and request.method.upper() == "POST":
        body = await request.json()
        tool = body.get("tool")
        params = body.get("params", {})
        if isinstance(tool, str):
            result = orchesis.evaluate(tool=tool, params=params, agent_id="fastapi_agent")
            if not result.allowed:
                return JSONResponse(
                    status_code=403,
                    content={"error": "denied", "reasons": result.reasons, "tool": tool},
                )
    return await call_next(request)


@app.post("/tool/execute")
async def execute_tool(payload: dict):
    return {"ok": True, "payload": payload}
