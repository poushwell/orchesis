"""Session replay engine for what-if analysis."""

from __future__ import annotations

from dataclasses import dataclass
import json
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request as UrlRequest, urlopen

from orchesis.cost_tracker import MODEL_COSTS
from orchesis.engine import evaluate
from orchesis.recorder import SessionRecord
from orchesis.state import RateLimitTracker


@dataclass
class ReplayConfig:
    model_override: str | None = None
    policy_path: str | None = None
    dry_run: bool = False
    max_requests: int | None = None
    delay_between_requests: float = 0.0


@dataclass
class ReplayResult:
    request_id: str
    original_model: str
    replay_model: str
    original_status: int
    replay_status: int
    original_cost: float
    replay_cost: float
    original_latency_ms: float
    replay_latency_ms: float
    original_error: str | None
    replay_error: str | None
    policy_blocked: bool
    policy_block_reason: str | None


@dataclass
class ReplayReportSummary:
    total_requests: int
    original_cost: float
    replay_cost: float
    cost_delta: float
    cost_savings_pct: float
    original_errors: int
    replay_errors: int
    policy_blocks: int
    original_avg_latency_ms: float
    replay_avg_latency_ms: float
    models_compared: dict[str, str]


@dataclass
class ReplayReport:
    session_id: str
    config: ReplayConfig
    results: list[ReplayResult]
    summary: ReplayReportSummary


class SessionReplayer:
    def __init__(self, upstream_base: str = "http://127.0.0.1:8100") -> None:
        self._upstream_base = upstream_base.rstrip("/")

    @staticmethod
    def _estimate_model_cost(model: str, prompt_tokens: int, completion_tokens: int = 0) -> float:
        rates = MODEL_COSTS.get(model, MODEL_COSTS["default"])
        return (prompt_tokens / 1000.0 * rates["input"]) + (completion_tokens / 1000.0 * rates["output"])

    def estimate_cost(self, session: list[SessionRecord], model: str) -> float:
        total = 0.0
        for item in session:
            messages = item.request.get("messages", []) if isinstance(item.request, dict) else []
            prompt_tokens = len(json.dumps(messages, ensure_ascii=False, sort_keys=True)) // 4
            completion_tokens = 0
            if isinstance(item.response, dict):
                usage = item.response.get("usage")
                if isinstance(usage, dict):
                    completion_tokens = int(usage.get("completion_tokens") or usage.get("output_tokens") or 0)
            total += self._estimate_model_cost(model, prompt_tokens, completion_tokens)
        return round(total, 8)

    def _send_replay(self, body: dict[str, Any], path: str = "/v1/chat/completions") -> tuple[int, dict[str, Any] | None, str | None, float]:
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        req = UrlRequest(
            f"{self._upstream_base}{path}",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        started = time.perf_counter()
        try:
            with urlopen(req, timeout=30) as resp:
                raw = resp.read()
                latency = (time.perf_counter() - started) * 1000.0
                decoded = json.loads(raw.decode("utf-8"))
                return int(resp.status), decoded if isinstance(decoded, dict) else None, None, latency
        except HTTPError as error:
            latency = (time.perf_counter() - started) * 1000.0
            body_raw = error.read()
            decoded = None
            try:
                parsed = json.loads(body_raw.decode("utf-8"))
                if isinstance(parsed, dict):
                    decoded = parsed
            except Exception:
                decoded = None
            return int(error.code), decoded, str(error), latency
        except URLError as error:
            latency = (time.perf_counter() - started) * 1000.0
            return 502, None, str(error), latency

    def replay(
        self,
        session: list[SessionRecord],
        config: ReplayConfig,
        policy: dict[str, Any] | None = None,
    ) -> ReplayReport:
        results: list[ReplayResult] = []
        state = RateLimitTracker(persist_path=None)
        sliced = session[: int(config.max_requests)] if isinstance(config.max_requests, int) else list(session)
        for item in sliced:
            original_model = item.model
            replay_model = config.model_override or original_model
            request_payload = dict(item.request) if isinstance(item.request, dict) else {}
            request_payload["model"] = replay_model
            policy_blocked = False
            policy_block_reason = None

            messages = request_payload.get("messages", [])
            prompt_tokens = len(json.dumps(messages, ensure_ascii=False, sort_keys=True)) // 4
            replay_cost = self._estimate_model_cost(replay_model, prompt_tokens, 0)
            replay_status = 0
            replay_error = None
            replay_latency_ms = 0.0

            if isinstance(policy, dict):
                eval_req = {
                    "tool": str(request_payload.get("tool") or "llm_request"),
                    "params": request_payload,
                    "context": {"path": "/replay"},
                    "cost": replay_cost,
                }
                decision = evaluate(eval_req, policy, state=state)
                if not decision.allowed:
                    policy_blocked = True
                    policy_block_reason = decision.reasons[0] if decision.reasons else "blocked_by_policy"

            if config.dry_run:
                replay_status = 429 if policy_blocked else item.status_code
            else:
                replay_status, replay_resp, replay_error, replay_latency_ms = self._send_replay(request_payload)
                if isinstance(replay_resp, dict):
                    usage = replay_resp.get("usage")
                    if isinstance(usage, dict):
                        completion_tokens = int(usage.get("completion_tokens") or usage.get("output_tokens") or 0)
                        replay_cost = self._estimate_model_cost(replay_model, prompt_tokens, completion_tokens)

            results.append(
                ReplayResult(
                    request_id=item.request_id,
                    original_model=original_model,
                    replay_model=replay_model,
                    original_status=item.status_code,
                    replay_status=replay_status,
                    original_cost=float(item.cost),
                    replay_cost=float(replay_cost),
                    original_latency_ms=float(item.latency_ms),
                    replay_latency_ms=float(replay_latency_ms),
                    original_error=item.error,
                    replay_error=replay_error,
                    policy_blocked=policy_blocked,
                    policy_block_reason=policy_block_reason,
                )
            )
            if config.delay_between_requests > 0:
                time.sleep(float(config.delay_between_requests))

        original_cost = sum(item.original_cost for item in results)
        replay_cost_total = sum(item.replay_cost for item in results)
        delta = replay_cost_total - original_cost
        savings_pct = ((original_cost - replay_cost_total) / original_cost * 100.0) if original_cost > 0 else 0.0
        models_compared = {item.original_model: item.replay_model for item in results}
        summary = ReplayReportSummary(
            total_requests=len(results),
            original_cost=round(original_cost, 8),
            replay_cost=round(replay_cost_total, 8),
            cost_delta=round(delta, 8),
            cost_savings_pct=round(savings_pct, 4),
            original_errors=sum(1 for item in results if item.original_error or item.original_status >= 400),
            replay_errors=sum(1 for item in results if item.replay_error or item.replay_status >= 400),
            policy_blocks=sum(1 for item in results if item.policy_blocked),
            original_avg_latency_ms=round(
                sum(item.original_latency_ms for item in results) / max(1, len(results)), 6
            ),
            replay_avg_latency_ms=round(
                sum(item.replay_latency_ms for item in results) / max(1, len(results)), 6
            ),
            models_compared=models_compared,
        )
        session_id = session[0].session_id if session else "unknown"
        return ReplayReport(session_id=session_id, config=config, results=results, summary=summary)
