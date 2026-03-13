"""Entropy-based anomaly detection for AI agent traffic."""

from __future__ import annotations

import math
import re
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass
from typing import Optional

from orchesis.input_guard import sanitize_text


def _tokenize(text: str) -> list[str]:
    safe = sanitize_text(text)
    if safe is None:
        return []
    words = re.findall(r"\w+", safe.lower(), flags=re.UNICODE)
    if len(words) > 1:
        return words
    if len(words) == 1 and len(words[0]) >= 12:
        # Fallback for payload-like single-token strings.
        return [ch for ch in words[0]]
    return words


def _shannon(values: list[str]) -> float:
    if len(values) <= 1:
        return 0.0
    freq = Counter(values)
    total = float(len(values))
    entropy = 0.0
    for count in freq.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def shannon_entropy(text: str) -> float:
    """Shannon entropy for text token distribution."""

    return _shannon(_tokenize(text))


def length_entropy(lengths: list[int]) -> float:
    """Entropy of message length buckets."""

    if len(lengths) <= 1:
        return 0.0
    buckets: list[str] = []
    for value in lengths:
        v = max(0, int(value))
        if v <= 10:
            buckets.append("0-10")
        elif v <= 50:
            buckets.append("11-50")
        elif v <= 200:
            buckets.append("51-200")
        elif v <= 500:
            buckets.append("201-500")
        elif v <= 1000:
            buckets.append("501-1000")
        else:
            buckets.append("1001+")
    return _shannon(buckets)


def tool_entropy(tool_names: list[str]) -> float:
    """Entropy of tool-call distribution."""

    cleaned = [str(name).strip().lower() for name in tool_names if str(name).strip()]
    return _shannon(cleaned)


def timing_entropy(intervals: list[float]) -> float:
    """Entropy of inter-request timing buckets."""

    if len(intervals) <= 1:
        return 0.0
    buckets: list[str] = []
    for value in intervals:
        v = max(0.0, float(value))
        if v <= 1.0:
            buckets.append("0-1s")
        elif v <= 5.0:
            buckets.append("1-5s")
        elif v <= 30.0:
            buckets.append("5-30s")
        elif v <= 60.0:
            buckets.append("30-60s")
        else:
            buckets.append("60s+")
    return _shannon(buckets)


def vocab_richness(text: str) -> float:
    """Type-token ratio: unique tokens / total tokens."""

    tokens = _tokenize(text)
    if not tokens:
        return 0.0
    return len(set(tokens)) / float(len(tokens))


def ngram_repetition(text: str, n: int = 3) -> float:
    """Fraction of n-grams that appear more than once."""

    size = max(1, int(n))
    tokens = _tokenize(text)
    if len(tokens) < size:
        return 0.0
    grams = [tuple(tokens[i : i + size]) for i in range(len(tokens) - size + 1)]
    if not grams:
        return 0.0
    freq = Counter(grams)
    repeated = sum(1 for count in freq.values() if count >= 2)
    return repeated / float(len(freq))


@dataclass
class EntropyProfile:
    """Rolling entropy profile for a stream of events."""

    token_entropy: float = 0.0
    message_length_entropy: float = 0.0
    tool_call_entropy: float = 0.0
    timing_entropy: float = 0.0
    vocab_richness: float = 0.0
    repetition_score: float = 0.0
    anomaly_score: float = 0.0
    is_anomalous: bool = False


class EntropyBaseline:
    """Maintains rolling baseline of entropy values for an agent/session."""

    def __init__(
        self,
        window_size: int = 50,
        sensitivity: float = 2.0,
        metric_names: tuple[str, ...] | None = None,
        weights: dict[str, float] | None = None,
    ):
        self.window_size = max(5, int(window_size))
        self.sensitivity = max(0.5, float(sensitivity))
        self.metric_names = metric_names or (
            "token_entropy",
            "message_length_entropy",
            "tool_call_entropy",
            "timing_entropy",
            "vocab_richness",
            "repetition_score",
        )
        self._weights = weights or {
            "token_entropy": 0.25,
            "timing_entropy": 0.20,
            "tool_call_entropy": 0.20,
            "repetition_score": 0.15,
            "message_length_entropy": 0.10,
            "vocab_richness": 0.10,
        }
        self._history: dict[str, deque[float]] = {
            name: deque(maxlen=self.window_size) for name in self.metric_names
        }
        self._observation_count = 0

    @property
    def observation_count(self) -> int:
        return self._observation_count

    def update(self, profile: EntropyProfile) -> None:
        self._observation_count += 1
        for name in self.metric_names:
            self._history[name].append(float(getattr(profile, name, 0.0)))

    def _metric_stats(self, metric_name: str) -> tuple[float, float]:
        values = list(self._history[metric_name])
        if not values:
            return 0.0, 0.0
        mean = sum(values) / float(len(values))
        variance = sum((value - mean) ** 2 for value in values) / float(len(values))
        return mean, math.sqrt(variance)

    @staticmethod
    def _sigmoid(value: float) -> float:
        if value > 30:
            return 1.0
        if value < -30:
            return 0.0
        return 1.0 / (1.0 + math.exp(-value))

    def is_anomalous(self, profile: EntropyProfile) -> tuple[bool, float, dict]:
        if self._observation_count < 2:
            return False, 0.0, {"observation_count": self._observation_count}

        std_floor = {
            "token_entropy": 0.15,
            "message_length_entropy": 0.10,
            "tool_call_entropy": 0.10,
            "timing_entropy": 0.10,
            "vocab_richness": 0.05,
            "repetition_score": 0.05,
        }
        details: dict[str, dict[str, float] | int] = {"observation_count": self._observation_count}
        weighted_sum = 0.0
        max_deviation = 0.0
        for name in self.metric_names:
            current = float(getattr(profile, name, 0.0))
            mean, std = self._metric_stats(name)
            denom = max(std, std_floor.get(name, 0.05))
            deviation = abs(current - mean) / denom if denom > 0 else 0.0
            max_deviation = max(max_deviation, deviation)
            weight = float(self._weights.get(name, 0.0))
            weighted_sum += weight * self._sigmoid(deviation - self.sensitivity)
            details[name] = {
                "current": round(current, 6),
                "mean": round(mean, 6),
                "std": round(std, 6),
                "z": round(deviation, 6),
            }

        score = min(100.0, max(0.0, weighted_sum * 100.0))
        anomalous = bool(score >= 60.0 and max_deviation >= self.sensitivity)
        return anomalous, round(score, 2), details

    def as_dict(self) -> dict:
        summary: dict[str, dict[str, float] | int] = {"observation_count": self._observation_count}
        for name in self.metric_names:
            mean, std = self._metric_stats(name)
            summary[name] = {"mean": round(mean, 6), "std": round(std, 6), "n": len(self._history[name])}
        return summary


class EntropyDetector:
    """Main entropy-based anomaly detector."""

    def __init__(self, config: Optional[dict] = None):
        cfg = config or {}
        self.window_size = max(5, int(cfg.get("window_size", 50)))
        self.sensitivity = max(0.5, float(cfg.get("sensitivity", 2.0)))
        self.min_observations = max(1, int(cfg.get("min_observations", 10)))
        self.enable_token_entropy = bool(cfg.get("enable_token_entropy", True))
        self.enable_timing_entropy = bool(cfg.get("enable_timing_entropy", True))
        self.enable_tool_entropy = bool(cfg.get("enable_tool_entropy", True))
        self.enable_repetition = bool(cfg.get("enable_repetition", True))
        self.ngram_size = max(1, int(cfg.get("ngram_size", 3)))
        self._lock = threading.Lock()
        self._baselines: dict[str, EntropyBaseline] = {}
        self._timing_windows: dict[str, deque[float]] = {}
        self._last_timestamp: dict[str, float] = {}

    def analyze_message(self, content: str, role: str = "user") -> EntropyProfile:
        _ = role
        safe = sanitize_text(content)
        if safe is None:
            safe = ""
        profile = EntropyProfile()
        if self.enable_token_entropy:
            profile.token_entropy = shannon_entropy(safe)
        profile.message_length_entropy = length_entropy([len(_tokenize(safe))])
        profile.tool_call_entropy = 0.0
        if self.enable_timing_entropy:
            profile.timing_entropy = 0.0
        profile.vocab_richness = vocab_richness(safe)
        if self.enable_repetition:
            profile.repetition_score = ngram_repetition(safe, self.ngram_size)
        return profile

    def analyze_request(self, request_data: dict) -> EntropyProfile:
        messages = request_data.get("messages")
        if not isinstance(messages, list):
            messages = []
        tools = request_data.get("tools")
        if not isinstance(tools, list):
            tools = []
        intervals = request_data.get("intervals")
        if not isinstance(intervals, list):
            intervals = []

        contents: list[str] = []
        lengths: list[int] = []
        for item in messages:
            if isinstance(item, dict):
                safe = sanitize_text(item.get("content", ""))
                content = safe if safe is not None else ""
            else:
                safe = sanitize_text(item)
                content = safe if safe is not None else ""
            contents.append(content)
            lengths.append(len(_tokenize(content)))
        all_text = " ".join(contents).strip()

        profile = EntropyProfile()
        if self.enable_token_entropy:
            profile.token_entropy = shannon_entropy(all_text)
        profile.message_length_entropy = length_entropy(lengths)
        if self.enable_tool_entropy:
            profile.tool_call_entropy = tool_entropy([str(x) for x in tools])
        if self.enable_timing_entropy:
            profile.timing_entropy = timing_entropy([float(x) for x in intervals if isinstance(x, (int, float))])
        profile.vocab_richness = vocab_richness(all_text)
        if self.enable_repetition:
            profile.repetition_score = ngram_repetition(all_text, self.ngram_size)
        return profile

    def _metric_names(self) -> tuple[str, ...]:
        names = ["message_length_entropy", "vocab_richness"]
        if self.enable_token_entropy:
            names.append("token_entropy")
        if self.enable_tool_entropy:
            names.append("tool_call_entropy")
        if self.enable_timing_entropy:
            names.append("timing_entropy")
        if self.enable_repetition:
            names.append("repetition_score")
        return tuple(names)

    def _get_or_create_baseline(self, agent_id: str) -> EntropyBaseline:
        baseline = self._baselines.get(agent_id)
        if baseline is None:
            baseline = EntropyBaseline(
                window_size=self.window_size,
                sensitivity=self.sensitivity,
                metric_names=self._metric_names(),
            )
            self._baselines[agent_id] = baseline
        return baseline

    def check(self, agent_id: str, request_data: dict) -> tuple[bool, float, dict]:
        safe_agent = str(agent_id or "unknown")
        now = float(request_data.get("timestamp", time.time()) if isinstance(request_data, dict) else time.time())
        with self._lock:
            baseline = self._get_or_create_baseline(safe_agent)
            window = self._timing_windows.get(safe_agent)
            if window is None:
                window = deque(maxlen=self.window_size)
                self._timing_windows[safe_agent] = window
            last_ts = self._last_timestamp.get(safe_agent)
            if isinstance(last_ts, float):
                interval = max(0.0, now - last_ts)
                window.append(interval)
            self._last_timestamp[safe_agent] = now

            enriched = dict(request_data or {})
            enriched["intervals"] = list(window)
            profile = self.analyze_request(enriched)

            is_anom, score, details = baseline.is_anomalous(profile)
            if baseline.observation_count < self.min_observations:
                is_anom = False
                score = 0.0
                details = {
                    **details,
                    "note": f"warming_up:{baseline.observation_count}/{self.min_observations}",
                }

            profile.anomaly_score = score
            profile.is_anomalous = is_anom
            baseline.update(profile)
            details = {**details, "profile": profile.__dict__.copy()}
            return is_anom, score, details

    def get_baseline(self, agent_id: str) -> Optional[dict]:
        with self._lock:
            baseline = self._baselines.get(str(agent_id or "unknown"))
            if baseline is None:
                return None
            return baseline.as_dict()

    def get_all_baselines(self) -> dict:
        with self._lock:
            return {agent: baseline.as_dict() for agent, baseline in self._baselines.items()}

    def reset(self, agent_id: str) -> None:
        key = str(agent_id or "unknown")
        with self._lock:
            self._baselines.pop(key, None)
            self._timing_windows.pop(key, None)
            self._last_timestamp.pop(key, None)
