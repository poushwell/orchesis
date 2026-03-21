"""Run local Orchesis proxy demo with backend and sample requests."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import httpx
import uvicorn

from orchesis.config import load_policy
from orchesis.demo_backend import app as backend_app
from orchesis.proxy import create_proxy_app


def _start_server(app: object, host: str, port: int) -> tuple[uvicorn.Server, threading.Thread]:
    config = uvicorn.Config(app=app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    return server, thread


def _print_response(label: str, response: httpx.Response) -> None:
    print(f"{label} -> status={response.status_code}")
    try:
        parsed = response.json()
        print(json.dumps(parsed, ensure_ascii=False, indent=2))
    except ValueError:
        print(response.text)
    print("-" * 50)


def main() -> None:
    policy_path = Path(__file__).resolve().parent / "examples" / "policy.yaml"
    policy = load_policy(policy_path)

    proxy_app = create_proxy_app(policy=policy, backend_url="http://127.0.0.1:8081")

    backend_server, backend_thread = _start_server(backend_app, host="127.0.0.1", port=8081)
    proxy_server, proxy_thread = _start_server(proxy_app, host="127.0.0.1", port=8080)

    try:
        time.sleep(1)

        with httpx.Client(timeout=5.0) as client:
            get_resp = client.get("http://127.0.0.1:8080/data")
            _print_response("GET /data (expect ALLOW)", get_resp)

            delete_resp = client.delete("http://127.0.0.1:8080/files/etc/passwd")
            _print_response("DELETE /files/etc/passwd (expect DENY 403)", delete_resp)

            post_resp = client.post(
                "http://127.0.0.1:8080/execute",
                json={"action": "DROP TABLE", "query": "DROP TABLE users"},
            )
            _print_response("POST /execute DROP (expect DENY 403)", post_resp)
    finally:
        proxy_server.should_exit = True
        backend_server.should_exit = True
        proxy_thread.join(timeout=5)
        backend_thread.join(timeout=5)


if __name__ == "__main__":
    main()
