"""Adaptive Detection Engine v2."""

from __future__ import annotations

import math
import re
from collections import defaultdict
from typing import Any

from orchesis.entropy_detector import shannon_entropy
from orchesis.ngram_profiler import NgramProfiler
from orchesis.structural_patterns import StructuralPatternDetector


class DetectionResult:
    def __init__(self) -> None:
        self.triggered = False
        self.layers_hit: list[str] = []
        self.confidence: float = 0.0
        self.reasons: list[str] = []


class AdaptiveDetectionV2:
    """5-layer detection: regex -> structural -> entropy -> n-gram -> session_risk."""

    LAYERS = ["regex", "structural", "entropy", "ngram", "session_risk"]

    def __init__(self, config: dict | None = None):
        cfg = config or {}
        self.fpr_target = float(cfg.get("fpr_target", 0.05))
        self.regex_threshold = float(cfg.get("regex_threshold", 0.5))
        self.structural_threshold = float(cfg.get("structural_threshold", 0.6))
        self.entropy_threshold = float(cfg.get("entropy_threshold", 3.9))
        self.ngram_threshold = float(cfg.get("ngram_threshold", 0.45))
        self.session_risk_threshold = float(cfg.get("session_risk_threshold", 60.0))
        self.min_confidence = float(cfg.get("confidence_threshold", 0.62))
        self._layer_stats: dict[str, dict[str, float | int]] = {
            layer: {"runs": 0, "hits": 0, "false_positives": 0, "false_negatives": 0, "fpr_estimate": 0.0}
            for layer in self.LAYERS
        }
        self._patterns = [
            re.compile(pattern, flags=re.IGNORECASE)
            for pattern in [
                r"ignore\s+all\s+previous\s+instructions",
                r"system\s+prompt",
                r"developer\s+message",
                r"bypass\s+(?:policy|guardrails?)",
                r"BEGIN[\s_]*PROMPT[\s_]*INJECTION",
                r"(?:base64|hex)[\s:_-]*(?:payload|blob)",
            ]
        ]
        self._structural = StructuralPatternDetector({"history_size": 60, "min_occurrences": 2})
        self._ngram = NgramProfiler({"baseline_messages": 5, "window_size": 8, "drift_threshold": 0.3})
        self._weights = {
            "regex": 0.30,
            "structural": 0.20,
            "entropy": 0.18,
            "ngram": 0.17,
            "session_risk": 0.15,
        }

    @staticmethod
    def _char_entropy(text: str) -> float:
        if not text:
            return 0.0
        counts: dict[str, int] = {}
        for ch in text:
            counts[ch] = counts.get(ch, 0) + 1
        total = float(len(text))
        value = 0.0
        for count in counts.values():
            p = count / total
            if p > 0:
                value -= p * math.log2(p)
        return value

    def _update_layer_stats(self, layer: str, hit: bool) -> None:
        stats = self._layer_stats[layer]
        stats["runs"] = int(stats["runs"]) + 1
        if hit:
            stats["hits"] = int(stats["hits"]) + 1
        runs = max(1, int(stats["runs"]))
        fps = int(stats["false_positives"])
        stats["fpr_estimate"] = max(0.0, min(1.0, fps / float(runs)))

    @staticmethod
    def _extract_text(text: str, context: dict[str, Any]) -> str:
        parts = [text or ""]
        for item in context.get("messages", []):
            if isinstance(item, dict):
                parts.append(str(item.get("content", "") or ""))
            elif isinstance(item, str):
                parts.append(item)
        tools = context.get("tools", [])
        if isinstance(tools, list):
            parts.extend(str(t) for t in tools)
        return "\n".join(parts).strip()

    def detect(self, text: str, context: dict | None = None) -> DetectionResult:
        """Run all 5 layers, return combined result."""
        ctx = dict(context or {})
        agent_id = str(ctx.get("agent_id", "__default__"))
        full_text = self._extract_text(str(text or ""), ctx)
        result = DetectionResult()
        layer_scores: dict[str, float] = defaultdict(float)

        regex_hits = sum(1 for pat in self._patterns if pat.search(full_text))
        regex_score = min(1.0, regex_hits / 1.5)
        regex_hit = regex_score >= self.regex_threshold
        self._update_layer_stats("regex", regex_hit)
        if regex_hit:
            result.layers_hit.append("regex")
            result.reasons.append("regex:prompt_injection_pattern")
        layer_scores["regex"] = regex_score

        structural_input = {
            "messages": ctx.get("messages", []),
            "tools": ctx.get("tools", []),
            "model": str(ctx.get("model", "")),
            "tokens": int(ctx.get("tokens", max(0, len(full_text.split())))),
        }
        structural_hit, structural_matches = self._structural.check(agent_id, structural_input)
        structural_score = 0.0
        if structural_matches:
            structural_score = min(
                1.0,
                max(float(match.confidence) for match in structural_matches if hasattr(match, "confidence")),
            )
        self._update_layer_stats("structural", structural_hit or structural_score >= self.structural_threshold)
        if structural_hit or structural_score >= self.structural_threshold:
            result.layers_hit.append("structural")
            result.reasons.append("structural:pattern_anomaly")
        layer_scores["structural"] = structural_score

        entropy_value = max(shannon_entropy(full_text), self._char_entropy(full_text))
        entropy_score = max(0.0, min(1.0, (entropy_value - 2.5) / max(1e-6, (self.entropy_threshold - 2.5))))
        entropy_hit = entropy_value >= self.entropy_threshold
        self._update_layer_stats("entropy", entropy_hit)
        if entropy_hit:
            result.layers_hit.append("entropy")
            result.reasons.append(f"entropy:high({entropy_value:.2f})")
        layer_scores["entropy"] = entropy_score

        ngram_hit, drift = self._ngram.check(agent_id, full_text)
        drift_score = float(getattr(drift, "drift_score", 0.0))
        details = getattr(drift, "details", {}) if hasattr(drift, "details") else {}
        new_vocab_ratio = float(details.get("new_vocab_ratio", 0.0)) if isinstance(details, dict) else 0.0
        drift_type = str(getattr(drift, "drift_type", "normal"))
        tokens = re.findall(r"[A-Za-z0-9_-]+", full_text)
        long_token_ratio = (
            sum(1 for tok in tokens if len(tok) >= 20) / float(max(1, len(tokens)))
            if tokens
            else 0.0
        )
        repeated_bigram_ratio = 0.0
        if len(tokens) >= 2:
            bigram_counts: dict[tuple[str, str], int] = {}
            total_bigrams = max(1, len(tokens) - 1)
            for index in range(total_bigrams):
                pair = (tokens[index], tokens[index + 1])
                bigram_counts[pair] = bigram_counts.get(pair, 0) + 1
            max_bigram = max(bigram_counts.values()) if bigram_counts else 0
            repeated_bigram_ratio = max_bigram / float(total_bigrams)
        ngram_score = max(
            0.0,
            min(1.0, max(drift_score, new_vocab_ratio, long_token_ratio, repeated_bigram_ratio)),
        )
        ngram_layer_hit = (
            bool(ngram_hit)
            or ngram_score >= self.ngram_threshold
            or (drift_type != "normal" and float(getattr(drift, "confidence", 0.0)) >= 0.3)
        )
        self._update_layer_stats("ngram", ngram_layer_hit)
        if ngram_layer_hit:
            result.layers_hit.append("ngram")
            result.reasons.append(f"ngram:{drift_type}")
        layer_scores["ngram"] = ngram_score

        session_risk_raw = ctx.get("session_risk_score", 0.0)
        session_risk = float(session_risk_raw) if isinstance(session_risk_raw, int | float) else 0.0
        session_score = max(0.0, min(1.0, session_risk / 100.0))
        session_hit = session_risk >= self.session_risk_threshold or str(ctx.get("session_risk_level", "")).lower() in {
            "warn",
            "block",
        }
        self._update_layer_stats("session_risk", session_hit)
        if session_hit:
            result.layers_hit.append("session_risk")
            result.reasons.append(f"session_risk:{session_risk:.1f}")
        layer_scores["session_risk"] = session_score

        confidence = 0.0
        for layer in self.LAYERS:
            confidence += self._weights[layer] * layer_scores.get(layer, 0.0)
        if len(result.layers_hit) >= 2:
            confidence += 0.08
        result.confidence = round(max(0.0, min(1.0, confidence)), 4)
        result.triggered = result.confidence >= self.min_confidence or len(result.layers_hit) >= 3
        return result

    def calibrate(self, feedback: list[dict]) -> None:
        """Self-Play Regression: adjust thresholds based on FP/FN feedback."""
        if not isinstance(feedback, list):
            return
        fp = 0
        fn = 0
        layer_fp: dict[str, int] = defaultdict(int)
        layer_fn: dict[str, int] = defaultdict(int)
        for item in feedback:
            if not isinstance(item, dict):
                continue
            label = str(item.get("label", "")).strip().lower()
            predicted = bool(item.get("predicted", False))
            layers = item.get("layers_hit", [])
            if not isinstance(layers, list):
                layers = []
            if label in {"fp", "false_positive"}:
                fp += 1
                for layer in layers:
                    if layer in self._layer_stats:
                        layer_fp[layer] += 1
            if label in {"fn", "false_negative"}:
                fn += 1
                for layer in layers:
                    if layer in self._layer_stats:
                        layer_fn[layer] += 1
            if label == "clean" and predicted:
                fp += 1
            if label == "threat" and (not predicted):
                fn += 1
        total = max(1, fp + fn + len(feedback))
        observed_fpr = fp / float(total)
        if observed_fpr > self.fpr_target:
            self.min_confidence = min(0.95, self.min_confidence + 0.03)
            self.regex_threshold = min(0.95, self.regex_threshold + 0.02)
            self.entropy_threshold = min(6.0, self.entropy_threshold + 0.08)
            self.ngram_threshold = min(0.9, self.ngram_threshold + 0.03)
        elif fn > fp:
            self.min_confidence = max(0.45, self.min_confidence - 0.03)
            self.regex_threshold = max(0.45, self.regex_threshold - 0.02)
            self.entropy_threshold = max(3.0, self.entropy_threshold - 0.08)
            self.ngram_threshold = max(0.25, self.ngram_threshold - 0.03)
        for layer in self.LAYERS:
            stats = self._layer_stats[layer]
            stats["false_positives"] = int(stats["false_positives"]) + int(layer_fp.get(layer, 0))
            stats["false_negatives"] = int(stats["false_negatives"]) + int(layer_fn.get(layer, 0))
            runs = max(1, int(stats["runs"]))
            fps = int(stats["false_positives"])
            stats["fpr_estimate"] = max(0.0, min(1.0, fps / float(runs)))

    def get_layer_stats(self) -> dict:
        """Per-layer hit rates, FPR estimates."""
        out: dict[str, Any] = {
            "fpr_target": self.fpr_target,
            "confidence_threshold": round(self.min_confidence, 4),
            "thresholds": {
                "regex": round(self.regex_threshold, 4),
                "structural": round(self.structural_threshold, 4),
                "entropy": round(self.entropy_threshold, 4),
                "ngram": round(self.ngram_threshold, 4),
                "session_risk": round(self.session_risk_threshold, 4),
            },
            "layers": {},
        }
        for layer, stats in self._layer_stats.items():
            runs = max(1, int(stats["runs"]))
            hits = int(stats["hits"])
            fpr = float(stats["fpr_estimate"])
            out["layers"][layer] = {
                "runs": int(stats["runs"]),
                "hits": hits,
                "hit_rate": round(hits / float(runs), 6),
                "false_positives": int(stats["false_positives"]),
                "false_negatives": int(stats["false_negatives"]),
                "fpr_estimate": round(fpr, 6),
            }
        return out
