"""Thompson Sampling-based model router."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
import math
import os
import random
import threading
import time
from typing import Any, Optional


@dataclass
class ModelStats:
    """Statistics for a single model."""

    model: str
    successes: int = 0
    failures: int = 0
    total_tokens: int = 0
    total_cost_usd: float = 0.0
    total_latency_ms: float = 0.0
    avg_latency_ms: float = 0.0
    avg_tokens: float = 0.0
    avg_cost_usd: float = 0.0
    quality_scores: list[float] = field(default_factory=list)
    last_used: float = 0.0


@dataclass
class RoutingDecision:
    """Result of model selection."""

    selected_model: str
    reason: str
    sampled_scores: dict[str, float]
    confidence: float
    expected_cost: float
    expected_latency_ms: float


class ThompsonRouter:
    """Thompson Sampling-based intelligent model router."""

    _DEFAULT_MODELS = [
        {
            "name": "gpt-4o",
            "cost_per_1k_input": 0.0025,
            "cost_per_1k_output": 0.01,
            "max_context": 128000,
            "tier": "premium",
        },
        {
            "name": "gpt-4o-mini",
            "cost_per_1k_input": 0.00015,
            "cost_per_1k_output": 0.0006,
            "max_context": 128000,
            "tier": "economy",
        },
    ]

    def __init__(self, config: Optional[dict] = None):
        cfg = config if isinstance(config, dict) else {}
        self.enabled = bool(cfg.get("enabled", True))
        models = cfg.get("models")
        self._models = models if isinstance(models, list) and models else list(self._DEFAULT_MODELS)
        self.objective = str(cfg.get("objective", "balanced") or "balanced").strip().lower()
        if self.objective not in {"cost", "quality", "speed", "balanced"}:
            self.objective = "balanced"
        self.min_exploration_rate = max(0.0, min(1.0, float(cfg.get("min_exploration_rate", 0.05))))
        self.initial_exploration_rate = max(0.0, min(1.0, float(cfg.get("initial_exploration_rate", 0.3))))
        self.exploration_decay = max(0.8, min(1.0, float(cfg.get("exploration_decay", 0.99))))
        classify_by = cfg.get("classify_by")
        self.classify_by = classify_by if isinstance(classify_by, list) and classify_by else [
            "estimated_tokens",
            "has_tools",
            "agent_id",
        ]
        self.save_interval_seconds = max(1, int(cfg.get("save_interval_seconds", 300)))
        self.save_path = str(cfg.get("save_path", ".orchesis/thompson_stats.json"))
        self._lock = threading.Lock()
        self._rng = random.Random(cfg.get("seed"))
        self._stats: dict[str, dict[str, ModelStats]] = {}
        self._recent_latency_by_model: dict[str, list[float]] = {}
        self._recent_cost_by_model: dict[str, list[float]] = {}
        self._category_selections: dict[str, int] = {}
        self._total_selections = 0
        self._stop_event = threading.Event()
        self.load()
        self._save_thread = threading.Thread(target=self._auto_save_worker, daemon=True)
        self._save_thread.start()

    @staticmethod
    def _estimate_tokens(request_data: dict[str, Any]) -> int:
        messages = request_data.get("messages")
        if not isinstance(messages, list):
            return 0
        chars = 0
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            content = msg.get("content")
            if isinstance(content, str):
                chars += len(content)
        return max(0, int(chars / 4))

    def classify_request(self, request_data: dict, agent_id: str | None = None) -> str:
        req = request_data if isinstance(request_data, dict) else {}
        parts: list[str] = []
        if "estimated_tokens" in self.classify_by:
            token_est = self._estimate_tokens(req)
            if token_est < 1000:
                parts.append("short")
            elif token_est <= 10000:
                parts.append("medium")
            else:
                parts.append("long")
        if "has_tools" in self.classify_by:
            tools = req.get("tools")
            has_tools = bool(isinstance(tools, list) and len(tools) > 0)
            if not has_tools:
                messages = req.get("messages")
                if isinstance(messages, list):
                    has_tools = any(
                        isinstance(m, dict) and isinstance(m.get("tool_calls"), list) and len(m.get("tool_calls", [])) > 0
                        for m in messages
                    )
            parts.append("tools" if has_tools else "chat")
        if "agent_id" in self.classify_by and agent_id:
            digest = hashlib.sha256(str(agent_id).encode("utf-8")).hexdigest()[:6]
            parts.append(f"agent_{digest}")
        return "_".join(parts) if parts else "default"

    def _model_names(self) -> list[str]:
        out: list[str] = []
        for item in self._models:
            if isinstance(item, dict):
                name = str(item.get("name", "") or "")
                if name:
                    out.append(name)
        return out

    def _model_cfg(self, model: str) -> dict[str, Any]:
        for item in self._models:
            if isinstance(item, dict) and str(item.get("name", "")) == model:
                return item
        return {"name": model, "cost_per_1k_input": 0.001, "cost_per_1k_output": 0.002}

    def _stats_for(self, category: str, model: str) -> ModelStats:
        by_model = self._stats.setdefault(category, {})
        if model not in by_model:
            by_model[model] = ModelStats(model=model)
        return by_model[model]

    @staticmethod
    def _median(values: list[float]) -> float:
        if not values:
            return 0.0
        sorted_vals = sorted(float(v) for v in values)
        n = len(sorted_vals)
        mid = n // 2
        if n % 2:
            return float(sorted_vals[mid])
        return float((sorted_vals[mid - 1] + sorted_vals[mid]) / 2.0)

    def _normalize_cost_latency(self, model_stats: ModelStats) -> tuple[float, float]:
        all_costs: list[float] = []
        all_latencies: list[float] = []
        for per_category in self._stats.values():
            for item in per_category.values():
                all_costs.append(float(item.avg_cost_usd))
                all_latencies.append(float(item.avg_latency_ms))
        max_cost = max(all_costs) if all_costs else 1.0
        max_latency = max(all_latencies) if all_latencies else 1.0
        norm_cost = 0.0 if max_cost <= 0 else min(1.0, max(0.0, float(model_stats.avg_cost_usd) / max_cost))
        norm_latency = (
            0.0 if max_latency <= 0 else min(1.0, max(0.0, float(model_stats.avg_latency_ms) / max_latency))
        )
        return norm_cost, norm_latency

    def _apply_objective(self, thompson_sample: float, model_stats: ModelStats, objective: str) -> float:
        norm_cost, norm_latency = self._normalize_cost_latency(model_stats)
        if objective == "quality":
            return float(thompson_sample)
        if objective == "cost":
            return float(thompson_sample) * (1.0 - norm_cost)
        if objective == "speed":
            return float(thompson_sample) * (1.0 - norm_latency)
        return float(thompson_sample) * 0.4 + (1.0 - norm_cost) * 0.3 + (1.0 - norm_latency) * 0.3

    def _gamma_sample(self, shape: float) -> float:
        k = float(max(shape, 1e-9))
        if k < 1.0:
            u = max(1e-12, self._rng.random())
            return self._gamma_sample(k + 1.0) * (u ** (1.0 / k))
        d = k - (1.0 / 3.0)
        c = 1.0 / math.sqrt(9.0 * d)
        while True:
            u1 = max(1e-12, self._rng.random())
            u2 = max(1e-12, self._rng.random())
            x = math.sqrt(-2.0 * math.log(u1)) * math.cos(2.0 * math.pi * u2)
            v = (1.0 + c * x) ** 3
            if v <= 0:
                continue
            u = max(1e-12, self._rng.random())
            if math.log(u) < (0.5 * x * x + d - d * v + d * math.log(v)):
                return d * v

    def sample_beta(self, alpha: float, beta: float) -> float:
        x = self._gamma_sample(max(alpha, 1e-9))
        y = self._gamma_sample(max(beta, 1e-9))
        den = x + y
        if den <= 0:
            return 0.5
        return max(0.0, min(1.0, x / den))

    def select_model(
        self,
        request_data: dict,
        agent_id: str | None = None,
        excluded_models: list | None = None,
    ) -> RoutingDecision:
        category = self.classify_request(request_data, agent_id=agent_id)
        excluded = set(str(x) for x in (excluded_models or []))
        with self._lock:
            candidates = [m for m in self._model_names() if m not in excluded]
            if not candidates:
                fallback = self._model_names()[0] if self._model_names() else "gpt-4o-mini"
                return RoutingDecision(
                    selected_model=fallback,
                    reason="fallback",
                    sampled_scores={},
                    confidence=0.0,
                    expected_cost=0.0,
                    expected_latency_ms=0.0,
                )
            sampled: dict[str, float] = {}
            raw_samples: dict[str, float] = {}
            for model in candidates:
                stats = self._stats_for(category, model)
                alpha = float(stats.successes + 1)
                beta = float(stats.failures + 1)
                sample = self.sample_beta(alpha, beta)
                raw_samples[model] = sample
                sampled[model] = self._apply_objective(sample, stats, self.objective)
            selected_model = max(sampled.items(), key=lambda item: item[1])[0]
            reason = "thompson_sample"
            self._total_selections += 1
            self._category_selections[category] = int(self._category_selections.get(category, 0)) + 1
            exploration_rate = max(
                self.min_exploration_rate,
                self.initial_exploration_rate * (self.exploration_decay ** self._total_selections),
            )
            if len(candidates) > 1 and self._rng.random() < exploration_rate:
                selected_model = self._rng.choice(candidates)
                reason = "forced_exploration"
            ordered = sorted(sampled.values(), reverse=True)
            confidence = 0.5
            if len(ordered) >= 2:
                confidence = max(0.0, min(1.0, ordered[0] - ordered[1] + 0.5))
            elif ordered:
                confidence = max(0.0, min(1.0, ordered[0]))
            sel_stats = self._stats_for(category, selected_model)
            expected_latency = float(sel_stats.avg_latency_ms)
            expected_cost = float(sel_stats.avg_cost_usd)
            if expected_cost <= 0.0:
                cfg = self._model_cfg(selected_model)
                expected_cost = float(cfg.get("cost_per_1k_input", 0.0))
            return RoutingDecision(
                selected_model=selected_model,
                reason=reason,
                sampled_scores={k: round(v, 6) for k, v in sampled.items()},
                confidence=round(confidence, 6),
                expected_cost=round(expected_cost, 8),
                expected_latency_ms=round(expected_latency, 3),
            )

    def record_outcome(self, model: str, category: str, outcome: dict) -> None:
        safe_model = str(model or "")
        safe_category = str(category or "default")
        if not safe_model:
            return
        o = outcome if isinstance(outcome, dict) else {}
        success = bool(o.get("success", False))
        latency = float(o.get("latency_ms", 0.0) or 0.0)
        in_tokens = int(o.get("input_tokens", 0) or 0)
        out_tokens = int(o.get("output_tokens", 0) or 0)
        cost = float(o.get("cost_usd", 0.0) or 0.0)
        quality = float(o.get("quality_score", 1.0 if success else 0.0))
        with self._lock:
            stats = self._stats_for(safe_category, safe_model)
            if success:
                stats.successes += 1
            else:
                stats.failures += 1
            stats.total_tokens += max(0, in_tokens + out_tokens)
            stats.total_cost_usd += max(0.0, cost)
            stats.total_latency_ms += max(0.0, latency)
            total = max(1, stats.successes + stats.failures)
            stats.avg_latency_ms = stats.total_latency_ms / float(total)
            stats.avg_tokens = float(stats.total_tokens) / float(total)
            stats.avg_cost_usd = float(stats.total_cost_usd) / float(total)
            stats.quality_scores.append(max(0.0, min(1.0, quality)))
            if len(stats.quality_scores) > 200:
                stats.quality_scores = stats.quality_scores[-200:]
            stats.last_used = time.time()
            lat_hist = self._recent_latency_by_model.setdefault(safe_model, [])
            cost_hist = self._recent_cost_by_model.setdefault(safe_model, [])
            lat_hist.append(max(0.0, latency))
            cost_hist.append(max(0.0, cost))
            if len(lat_hist) > 200:
                self._recent_latency_by_model[safe_model] = lat_hist[-200:]
            if len(cost_hist) > 200:
                self._recent_cost_by_model[safe_model] = cost_hist[-200:]

    def compute_quality_score(self, outcome: dict, detection_result: Any = None) -> float:
        o = outcome if isinstance(outcome, dict) else {}
        model = str(o.get("model", "") or "")
        success = bool(o.get("success", False))
        score = 1.0 if success else 0.0
        latency = float(o.get("latency_ms", 0.0) or 0.0)
        cost = float(o.get("cost_usd", 0.0) or 0.0)
        with self._lock:
            if model and model in self._recent_latency_by_model:
                lat_med = self._median(self._recent_latency_by_model[model])
            else:
                lat_med = self._median([x for v in self._recent_latency_by_model.values() for x in v])
            if model and model in self._recent_cost_by_model:
                cost_med = self._median(self._recent_cost_by_model[model])
            else:
                cost_med = self._median([x for v in self._recent_cost_by_model.values() for x in v])
        if success:
            if lat_med > 0 and latency < lat_med:
                score += 0.2
            if cost_med > 0 and cost < cost_med:
                score += 0.2
            if not bool(o.get("loop_detected", False)):
                score += 0.1
            if not bool(o.get("injection_detected", False)):
                score += 0.1
        err = str(o.get("error_type", "") or "").lower()
        if err == "rate_limit":
            score -= 0.3
        if err == "context_length":
            score -= 0.5
        if detection_result is not None:
            try:
                risk = str(getattr(detection_result, "risk_level", "low"))
                if risk in {"high", "critical"}:
                    score -= 0.2
            except Exception:
                pass
        return max(0.0, min(1.0, round(score, 6)))

    def save(self) -> None:
        payload = {
            "stats": {
                category: {model: asdict(stats) for model, stats in per_model.items()}
                for category, per_model in self._stats.items()
            },
            "recent_latency_by_model": self._recent_latency_by_model,
            "recent_cost_by_model": self._recent_cost_by_model,
            "category_selections": self._category_selections,
            "total_selections": self._total_selections,
            "saved_at": time.time(),
        }
        parent = os.path.dirname(self.save_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        tmp = f"{self.save_path}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.save_path)

    def load(self) -> None:
        try:
            with open(self.save_path, "r", encoding="utf-8") as f:
                payload = json.load(f)
            if not isinstance(payload, dict):
                return
            loaded_stats = payload.get("stats", {})
            if isinstance(loaded_stats, dict):
                for category, per_model in loaded_stats.items():
                    if not isinstance(per_model, dict):
                        continue
                    cat_key = str(category)
                    self._stats.setdefault(cat_key, {})
                    for model, raw_stats in per_model.items():
                        if not isinstance(raw_stats, dict):
                            continue
                        try:
                            self._stats[cat_key][str(model)] = ModelStats(**raw_stats)
                        except Exception:
                            continue
            rec_lat = payload.get("recent_latency_by_model", {})
            rec_cost = payload.get("recent_cost_by_model", {})
            if isinstance(rec_lat, dict):
                self._recent_latency_by_model = {
                    str(k): [float(x) for x in v if isinstance(x, int | float)]
                    for k, v in rec_lat.items()
                    if isinstance(v, list)
                }
            if isinstance(rec_cost, dict):
                self._recent_cost_by_model = {
                    str(k): [float(x) for x in v if isinstance(x, int | float)]
                    for k, v in rec_cost.items()
                    if isinstance(v, list)
                }
            cat_sel = payload.get("category_selections", {})
            if isinstance(cat_sel, dict):
                self._category_selections = {str(k): int(v) for k, v in cat_sel.items() if isinstance(v, int | float)}
            self._total_selections = int(payload.get("total_selections", 0) or 0)
        except Exception:
            self._stats = {}
            self._recent_latency_by_model = {}
            self._recent_cost_by_model = {}
            self._category_selections = {}
            self._total_selections = 0

    def _auto_save_worker(self) -> None:
        while not self._stop_event.wait(self.save_interval_seconds):
            try:
                with self._lock:
                    self.save()
            except Exception:
                continue

    def get_model_stats(self) -> dict:
        with self._lock:
            all_models = self._model_names()
            output: dict[str, Any] = {}
            for model in all_models:
                model_categories: dict[str, Any] = {}
                succ = 0
                fail = 0
                total_cost = 0.0
                total_latency = 0.0
                total_requests = 0
                for category, per_model in self._stats.items():
                    item = per_model.get(model)
                    if item is None:
                        continue
                    reqs = item.successes + item.failures
                    total_requests += reqs
                    succ += item.successes
                    fail += item.failures
                    total_cost += item.total_cost_usd
                    total_latency += item.total_latency_ms
                    model_categories[category] = {
                        "requests": reqs,
                        "success_rate": round((item.successes / reqs), 4) if reqs > 0 else 0.0,
                        "avg_latency_ms": round(item.avg_latency_ms, 3),
                        "avg_cost_usd": round(item.avg_cost_usd, 8),
                        "alpha": item.successes + 1,
                        "beta": item.failures + 1,
                    }
                success_rate = (succ / float(total_requests)) if total_requests else 0.0
                output[model] = {
                    "total_requests": total_requests,
                    "success_rate": round(success_rate, 4),
                    "avg_latency_ms": round((total_latency / float(total_requests)), 3) if total_requests else 0.0,
                    "avg_cost_usd": round((total_cost / float(total_requests)), 8) if total_requests else 0.0,
                    "thompson_alpha": succ + 1,
                    "thompson_beta": fail + 1,
                    "categories": model_categories,
                }
            output["_meta"] = {
                "total_selections": int(self._total_selections),
                "category_selections": dict(self._category_selections),
                "objective": self.objective,
            }
            return output

    def get_routing_report(self) -> str:
        stats = self.get_model_stats()
        lines = ["Thompson Router Report", f"Objective: {self.objective}", ""]
        categories: set[str] = set()
        for model_data in stats.values():
            if isinstance(model_data, dict):
                categories.update(model_data.get("categories", {}).keys())
        for category in sorted(categories):
            best_model = ""
            best_score = -1.0
            for model in self._model_names():
                model_data = stats.get(model, {})
                cat = model_data.get("categories", {}).get(category, {})
                reqs = int(cat.get("requests", 0) or 0)
                if reqs <= 0:
                    continue
                sr = float(cat.get("success_rate", 0.0))
                score = sr
                if score > best_score:
                    best_score = score
                    best_model = model
            if best_model:
                lines.append(f"- {category}: best={best_model} success_rate={best_score:.3f}")
        if len(lines) <= 3:
            lines.append("- Not enough data yet.")
        return "\n".join(lines)

    def get_recommendation(self) -> dict:
        stats = self.get_model_stats()
        recs: list[str] = []
        model_names = [m for m in self._model_names() if m in stats]
        for i, left in enumerate(model_names):
            for right in model_names[i + 1 :]:
                ls = stats.get(left, {})
                rs = stats.get(right, {})
                if int(ls.get("total_requests", 0)) < 20 or int(rs.get("total_requests", 0)) < 20:
                    continue
                l_sr = float(ls.get("success_rate", 0.0))
                r_sr = float(rs.get("success_rate", 0.0))
                l_cost = float(ls.get("avg_cost_usd", 0.0))
                r_cost = float(rs.get("avg_cost_usd", 0.0))
                if l_cost > 0 and r_cost > 0:
                    if l_sr >= r_sr * 0.95 and l_cost < r_cost * 0.5:
                        recs.append(
                            f"Prefer {left} over {right}: similar quality ({l_sr:.2f}/{r_sr:.2f}) at lower cost."
                        )
                    if r_sr >= l_sr * 1.1 and r_cost <= l_cost * 1.5:
                        recs.append(
                            f"Prefer {right} for quality-sensitive traffic: materially higher success."
                        )
        return {
            "objective": self.objective,
            "recommendations": recs[:10],
            "has_enough_data": bool(recs),
        }

    def reset(self, model: str | None = None, category: str | None = None) -> None:
        with self._lock:
            if model is None and category is None:
                self._stats = {}
                self._recent_latency_by_model = {}
                self._recent_cost_by_model = {}
                self._category_selections = {}
                self._total_selections = 0
                return
            if category is not None:
                cat = str(category)
                if cat in self._stats:
                    if model is None:
                        self._stats.pop(cat, None)
                    else:
                        self._stats[cat].pop(str(model), None)
                        if not self._stats[cat]:
                            self._stats.pop(cat, None)
                return
            if model is not None:
                m = str(model)
                for cat in list(self._stats.keys()):
                    self._stats[cat].pop(m, None)
                    if not self._stats[cat]:
                        self._stats.pop(cat, None)
                self._recent_latency_by_model.pop(m, None)
                self._recent_cost_by_model.pop(m, None)

    def stop(self) -> None:
        self._stop_event.set()
        try:
            with self._lock:
                self.save()
        except Exception:
            pass

