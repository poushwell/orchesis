"""Demo backend service for proxy integration tests."""

from typing import Any

from fastapi import FastAPI

app = FastAPI(title="Orchesis Demo Backend")


@app.get("/data")
def get_data() -> dict[str, list[str]]:
    """Return static demo data list."""
    return {"items": ["report.csv", "data.json"]}


@app.post("/execute")
def execute_action(payload: dict[str, Any]) -> dict[str, str]:
    """Accept action payload and return completion status."""
    _ = payload
    return {"status": "done"}


@app.delete("/files/{path:path}")
def delete_file(path: str) -> dict[str, bool]:
    """Simulate file delete endpoint."""
    _ = path
    return {"deleted": True}
