from __future__ import annotations

import json
import random
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class MockUpstream:
    """
    Configurable mock LLM upstream for stress scenarios.

    behavior:
      - normal
      - slow
      - errors
      - timeout
      - mixed
      - degrading
    """

    def __init__(self, port: int = 0, behavior: str = "normal") -> None:
        self._port = int(port)
        self._behavior = str(behavior or "normal")
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._started_at = time.monotonic()
        self._rng = random.Random(42)
        self._stats: dict[str, Any] = {
            "requests": 0,
            "errors": 0,
            "timeouts": 0,
            "latency_ms_total": 0.0,
            "by_status": {},
        }

    def start(self) -> int:
        owner = self

        class _Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                if self.path.rstrip("/") != "/v1/chat/completions":
                    self.send_error(404)
                    return

                started = time.perf_counter()
                status, body = owner._build_response(self)
                elapsed_ms = max(0.0, (time.perf_counter() - started) * 1000.0)
                owner._record(status, elapsed_ms)

                if status is None:
                    # Simulated timeout: do not respond.
                    return

                payload = json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
                _ = (format, args)

        self._server = ThreadingHTTPServer(("127.0.0.1", self._port), _Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self._started_at = time.monotonic()
        return int(self._server.server_address[1])

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    def set_behavior(self, behavior: str) -> None:
        self._behavior = str(behavior or "normal")
        self._started_at = time.monotonic()

    def stats(self) -> dict[str, Any]:
        with self._lock:
            req = int(self._stats["requests"])
            avg = (self._stats["latency_ms_total"] / req) if req else 0.0
            return {
                "requests": req,
                "errors": int(self._stats["errors"]),
                "timeouts": int(self._stats["timeouts"]),
                "avg_latency_ms": round(avg, 3),
                "by_status": dict(self._stats["by_status"]),
                "behavior": self._behavior,
            }

    def _record(self, status: int | None, latency_ms: float) -> None:
        with self._lock:
            self._stats["requests"] += 1
            self._stats["latency_ms_total"] += latency_ms
            if status is None:
                self._stats["timeouts"] += 1
                return
            key = str(status)
            by_status = self._stats["by_status"]
            by_status[key] = int(by_status.get(key, 0)) + 1
            if status >= 500:
                self._stats["errors"] += 1

    def _build_response(self, handler: BaseHTTPRequestHandler) -> tuple[int | None, dict[str, Any]]:
        length = int(handler.headers.get("Content-Length", "0") or 0)
        body = handler.rfile.read(max(0, length))
        try:
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            payload = {}
        model = str(payload.get("model", "gpt-4o-mini"))
        text = self._extract_text(payload)
        mode = self._resolve_behavior_mode()

        if mode == "timeout":
            time.sleep(30.0)
            return None, {}
        if mode == "slow":
            time.sleep(self._rng.uniform(2.0, 6.0))
        elif mode == "normal":
            time.sleep(self._rng.uniform(0.05, 0.20))
        elif mode == "errors":
            if self._rng.random() < 0.8:
                return 503, {"error": {"type": "upstream_unavailable", "message": "mock 503"}}
            time.sleep(self._rng.uniform(0.05, 0.20))

        if "large_response" in text:
            completion_tokens = 100_000
            content = "L" * 4096
        elif "expensive" in text:
            completion_tokens = 5_000
            content = "Expensive response."
        else:
            completion_tokens = 220
            content = "Mock upstream response."

        return 200, {
            "id": "chatcmpl-mock",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": 120,
                "completion_tokens": completion_tokens,
                "total_tokens": 120 + completion_tokens,
            },
        }

    def _resolve_behavior_mode(self) -> str:
        if self._behavior == "mixed":
            roll = self._rng.random()
            if roll < 0.80:
                return "normal"
            if roll < 0.90:
                return "slow"
            if roll < 0.95:
                return "errors"
            return "timeout"

        if self._behavior == "degrading":
            elapsed = time.monotonic() - self._started_at
            if elapsed < 60:
                return "normal"
            if elapsed < 120:
                return "slow"
            if elapsed < 180:
                return "errors"
            return "timeout"

        return self._behavior

    @staticmethod
    def _extract_text(payload: dict[str, Any]) -> str:
        parts: list[str] = []
        for item in payload.get("messages", []) if isinstance(payload.get("messages"), list) else []:
            if isinstance(item, dict) and isinstance(item.get("content"), str):
                parts.append(item["content"])
        return "\n".join(parts).lower()
