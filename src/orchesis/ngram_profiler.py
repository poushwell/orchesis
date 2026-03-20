"""N-gram frequency profiling for agent language identity drift detection."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import math
import re
import threading
from typing import Optional

from orchesis.input_guard import sanitize_text


@dataclass
class NgramProfile:
    """N-gram frequency profile snapshot."""

    unigrams: dict[str, float]
    bigrams: dict[str, float]
    trigrams: dict[str, float]
    char_trigrams: dict[str, float]
    vocab_size: int
    total_tokens: int
    top_unigrams: list[tuple[str, float]]
    top_bigrams: list[tuple[str, float]]


@dataclass
class ProfileDrift:
    """Detected drift between current and baseline profile."""

    drift_score: float
    drift_type: str
    confidence: float
    changed_unigrams: list[str] = field(default_factory=list)
    changed_bigrams: list[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)


def cosine_similarity(vec_a: dict[str, float], vec_b: dict[str, float]) -> float:
    """Cosine similarity between sparse vectors."""

    if not vec_a and not vec_b:
        return 1.0
    if not vec_a or not vec_b:
        return 0.0
    dot = 0.0
    for key, value in vec_a.items():
        dot += value * vec_b.get(key, 0.0)
    mag_a = math.sqrt(sum(v * v for v in vec_a.values()))
    mag_b = math.sqrt(sum(v * v for v in vec_b.values()))
    if mag_a == 0.0 or mag_b == 0.0:
        return 0.0
    return max(0.0, min(1.0, dot / (mag_a * mag_b)))


def js_divergence(p: dict[str, float], q: dict[str, float], epsilon: float = 1e-12) -> float:
    """Jensen-Shannon divergence in [0, 1] with log2."""

    keys = set(p.keys()) | set(q.keys())
    if not keys:
        return 0.0

    def _kl(a: dict[str, float], b: dict[str, float]) -> float:
        total = 0.0
        for key in keys:
            pa = max(epsilon, float(a.get(key, 0.0)))
            pb = max(epsilon, float(b.get(key, 0.0)))
            total += pa * math.log2(pa / pb)
        return total

    m = {key: 0.5 * (float(p.get(key, 0.0)) + float(q.get(key, 0.0))) for key in keys}
    jsd = 0.5 * _kl(p, m) + 0.5 * _kl(q, m)
    return max(0.0, min(1.0, jsd))


def vocab_change_ratios(baseline: NgramProfile, current: NgramProfile) -> tuple[float, float]:
    """Return (new_ratio, missing_ratio)."""

    b = set(baseline.unigrams.keys())
    c = set(current.unigrams.keys())
    new_ratio = len(c - b) / float(max(1, len(c)))
    missing_ratio = len(b - c) / float(max(1, len(b)))
    return new_ratio, missing_ratio


def _stddev(values: list[float]) -> float:
    if not values:
        return 0.0
    mean = sum(values) / float(len(values))
    variance = sum((v - mean) ** 2 for v in values) / float(len(values))
    return math.sqrt(variance)


def classify_drift(
    drift_score: float,
    new_vocab: float,
    missing_vocab: float,
    char_change: float,
    uniform_shift: bool,
    threshold: float,
    gradual: bool = False,
) -> str:
    """Classify drift type based on metric signatures."""

    if drift_score < threshold:
        return "normal"
    if new_vocab > 0.4 and char_change > 0.3:
        return "injection"
    if uniform_shift:
        return "model_switch"
    if gradual or (missing_vocab > 0.25 and new_vocab > 0.15):
        return "persona_drift"
    return "persona_drift"


class NgramProfiler:
    """N-gram frequency profiler for agent language fingerprinting."""

    def __init__(self, config: Optional[dict] = None):
        cfg = config or {}
        self.ngram_sizes = [int(n) for n in cfg.get("ngram_sizes", [1, 2, 3]) if int(n) in (1, 2, 3)]
        if not self.ngram_sizes:
            self.ngram_sizes = [1, 2, 3]
        self.char_ngram_size = max(2, int(cfg.get("char_ngram_size", 3)))
        self.baseline_messages = max(3, int(cfg.get("baseline_messages", 20)))
        self.top_k = max(1, int(cfg.get("top_k", 20)))
        self.drift_threshold = max(0.05, min(1.0, float(cfg.get("drift_threshold", 0.3))))
        self.window_size = max(3, int(cfg.get("window_size", 10)))
        self.min_tokens = max(1, int(cfg.get("min_tokens", 50)))
        self._profile_cache_max = max(16, int(cfg.get("profile_cache_size", 256)))
        self._lock = threading.Lock()
        self._state: dict[str, dict] = {}
        self._profile_cache: dict[str, NgramProfile] = {}
        self._profile_cache_order: deque[str] = deque(maxlen=self._profile_cache_max)

    def tokenize(self, text: str) -> list[str]:
        """Lowercase + punctuation-stripped tokenizer."""

        safe = sanitize_text(text)
        if safe is None:
            return []
        # Unicode-friendly word extraction.
        tokens = re.findall(r"[^\W_]+(?:['-][^\W_]+)?", safe.lower(), flags=re.UNICODE)
        return [tok for tok in tokens if tok]

    def compute_ngrams(self, tokens: list[str], n: int) -> dict[str, int]:
        """Compute token n-gram counts."""

        size = max(1, int(n))
        if len(tokens) < size:
            return {}
        out: dict[str, int] = {}
        for i in range(len(tokens) - size + 1):
            key = " ".join(tokens[i : i + size])
            out[key] = out.get(key, 0) + 1
        return out

    def compute_char_ngrams(self, text: str, n: int) -> dict[str, int]:
        """Compute character-level n-gram counts."""

        size = max(1, int(n))
        normalized = re.sub(r"\s+", " ", (text or "").lower()).strip()
        if len(normalized) < size:
            return {}
        out: dict[str, int] = {}
        for i in range(len(normalized) - size + 1):
            key = normalized[i : i + size]
            out[key] = out.get(key, 0) + 1
        return out

    def _normalize_counts(self, counts: dict[str, int]) -> dict[str, float]:
        if not counts:
            return {}
        total = float(sum(counts.values()))
        pairs = sorted(((k, v / total) for k, v in counts.items()), key=lambda kv: kv[1], reverse=True)
        trimmed = pairs[: self.top_k]
        renorm_total = sum(v for _, v in trimmed) or 1.0
        return {k: v / renorm_total for k, v in trimmed}

    def build_profile(self, text: str) -> NgramProfile:
        """Build full n-gram profile for text."""

        safe = sanitize_text(text)
        if safe is None:
            return NgramProfile(
                unigrams={},
                bigrams={},
                trigrams={},
                char_trigrams={},
                vocab_size=0,
                total_tokens=0,
                top_unigrams=[],
                top_bigrams=[],
            )
        cached = self._profile_cache.get(safe)
        if cached is not None:
            return cached
        tokens = self.tokenize(safe)
        uni = self._normalize_counts(self.compute_ngrams(tokens, 1) if 1 in self.ngram_sizes else {})
        bi = self._normalize_counts(self.compute_ngrams(tokens, 2) if 2 in self.ngram_sizes else {})
        tri = self._normalize_counts(self.compute_ngrams(tokens, 3) if 3 in self.ngram_sizes else {})
        ctri = self._normalize_counts(self.compute_char_ngrams(safe, self.char_ngram_size))
        top_uni = sorted(uni.items(), key=lambda kv: kv[1], reverse=True)[:20]
        top_bi = sorted(bi.items(), key=lambda kv: kv[1], reverse=True)[:20]
        profile = NgramProfile(
            unigrams=uni,
            bigrams=bi,
            trigrams=tri,
            char_trigrams=ctri,
            vocab_size=len(set(tokens)),
            total_tokens=len(tokens),
            top_unigrams=top_uni,
            top_bigrams=top_bi,
        )
        self._profile_cache[safe] = profile
        self._profile_cache_order.append(safe)
        while len(self._profile_cache_order) > self._profile_cache_max:
            old = self._profile_cache_order.popleft()
            self._profile_cache.pop(old, None)
        # deque(maxlen=...) may evict silently; clean keys not in order.
        if len(self._profile_cache) > self._profile_cache_max:
            keep = set(self._profile_cache_order)
            self._profile_cache = {k: v for k, v in self._profile_cache.items() if k in keep}
        return profile

    def compare_profiles(self, baseline: NgramProfile, current: NgramProfile) -> ProfileDrift:
        """Compare two profiles and compute drift."""

        uni_cos = cosine_similarity(baseline.unigrams, current.unigrams)
        bi_cos = cosine_similarity(baseline.bigrams, current.bigrams)
        tri_js = js_divergence(baseline.trigrams, current.trigrams)
        new_vocab, missing_vocab = vocab_change_ratios(baseline, current)
        char_cos = cosine_similarity(baseline.char_trigrams, current.char_trigrams)
        novel_long_ratio = (
            len(
                [
                    tok
                    for tok in current.unigrams.keys()
                    if tok not in baseline.unigrams and len(tok) >= 16
                ]
            )
            / float(max(1, len(current.unigrams)))
        )

        uni_drift = 1.0 - uni_cos
        bi_drift = 1.0 - bi_cos
        char_drift = 1.0 - char_cos
        metrics = [uni_drift, bi_drift, tri_js, new_vocab, missing_vocab, char_drift]
        uniform_shift = _stddev(metrics) < 0.1

        drift_score = (
            (0.25 * uni_drift)
            + (0.20 * bi_drift)
            + (0.15 * tri_js)
            + (0.15 * new_vocab)
            + (0.10 * missing_vocab)
            + (0.15 * char_drift)
            + (0.30 * novel_long_ratio)
        )
        drift_score = max(0.0, min(1.0, drift_score))

        changed_uni = sorted(
            set(current.unigrams.keys()) ^ set(baseline.unigrams.keys())
            | {
                k
                for k in set(current.unigrams.keys()) & set(baseline.unigrams.keys())
                if abs(current.unigrams.get(k, 0.0) - baseline.unigrams.get(k, 0.0)) > 0.05
            }
        )
        changed_bi = sorted(
            set(current.bigrams.keys()) ^ set(baseline.bigrams.keys())
            | {
                k
                for k in set(current.bigrams.keys()) & set(baseline.bigrams.keys())
                if abs(current.bigrams.get(k, 0.0) - baseline.bigrams.get(k, 0.0)) > 0.03
            }
        )

        drift_type = classify_drift(
            drift_score=drift_score,
            new_vocab=new_vocab,
            missing_vocab=missing_vocab,
            char_change=max(char_drift, novel_long_ratio),
            uniform_shift=uniform_shift,
            threshold=self.drift_threshold,
            gradual=False,
        )
        confidence = max(0.0, min(1.0, drift_score + (0.1 if drift_type != "normal" else 0.0)))
        return ProfileDrift(
            drift_score=round(drift_score, 6),
            drift_type=drift_type,
            confidence=round(confidence, 6),
            changed_unigrams=changed_uni[: self.top_k],
            changed_bigrams=changed_bi[: self.top_k],
            details={
                "unigram_cosine": round(uni_cos, 6),
                "bigram_cosine": round(bi_cos, 6),
                "trigram_js": round(tri_js, 6),
                "new_vocab_ratio": round(new_vocab, 6),
                "missing_vocab_ratio": round(missing_vocab, 6),
                "char_trigram_cosine": round(char_cos, 6),
                "novel_long_ratio": round(novel_long_ratio, 6),
                "uniform_shift": uniform_shift,
            },
        )

    def _get_or_create_state(self, agent_id: str) -> dict:
        state = self._state.get(agent_id)
        if state is None:
            state = {
                "baseline_msgs": deque(maxlen=self.baseline_messages),
                "window_msgs": deque(maxlen=self.window_size),
                "baseline_profile": None,
                "current_profile": None,
                "previous_window_profile": None,
                "updates": 0,
            }
            self._state[agent_id] = state
        return state

    def update(self, agent_id: str, text: str, role: str = "assistant") -> None:
        """Add text to profile (assistant responses only)."""

        if str(role).strip().lower() != "assistant":
            return
        safe = sanitize_text(text)
        if safe is None:
            return
        key = str(agent_id or "unknown")
        value = safe
        with self._lock:
            state = self._get_or_create_state(key)
            state["updates"] += 1
            state["window_msgs"].append(value)
            if len(state["baseline_msgs"]) < self.baseline_messages:
                state["baseline_msgs"].append(value)
            baseline_text = " ".join(state["baseline_msgs"])
            window_text = " ".join(state["window_msgs"])
            state["baseline_profile"] = self.build_profile(baseline_text)
            state["current_profile"] = self.build_profile(window_text)

    def check(self, agent_id: str, text: str) -> tuple[bool, ProfileDrift]:
        """Update profile and check for drift."""

        key = str(agent_id or "unknown")
        self.update(key, text, role="assistant")
        with self._lock:
            state = self._get_or_create_state(key)
            baseline = state.get("baseline_profile")
            current = state.get("current_profile")
            previous_window = state.get("previous_window_profile")
            state["previous_window_profile"] = current
            updates = int(state.get("updates", 0))

        if not isinstance(baseline, NgramProfile) or not isinstance(current, NgramProfile):
            empty = ProfileDrift(0.0, "normal", 0.0, details={"reason": "insufficient_data"})
            return False, empty
        if baseline.total_tokens < self.min_tokens or updates < self.baseline_messages:
            warm = ProfileDrift(
                0.0,
                "normal",
                0.0,
                details={"reason": "baseline_warmup", "updates": updates, "tokens": baseline.total_tokens},
            )
            return False, warm

        drift = self.compare_profiles(baseline, current)
        # Gradual drift check against previous window profile.
        if (
            isinstance(previous_window, NgramProfile)
            and drift.drift_score >= self.drift_threshold
        ):
            prev_to_current = self.compare_profiles(previous_window, current).drift_score
            if prev_to_current < self.drift_threshold * 0.6 and drift.drift_type not in ("injection", "model_switch"):
                drift.drift_type = "persona_drift"
                drift.details["gradual"] = True
                drift.details["prev_window_drift"] = round(prev_to_current, 6)

        has_drift = drift.drift_score >= self.drift_threshold and drift.drift_type != "normal"
        return has_drift, drift

    def get_profile(self, agent_id: str) -> Optional[dict]:
        key = str(agent_id or "unknown")
        with self._lock:
            state = self._state.get(key)
            if state is None:
                return None
            baseline = state.get("baseline_profile")
            current = state.get("current_profile")
            return {
                "updates": int(state.get("updates", 0)),
                "baseline_tokens": int(getattr(baseline, "total_tokens", 0) or 0),
                "current_tokens": int(getattr(current, "total_tokens", 0) or 0),
                "vocab_size": int(getattr(current, "vocab_size", 0) or 0),
                "top_unigrams": list(getattr(current, "top_unigrams", []) or []),
                "top_bigrams": list(getattr(current, "top_bigrams", []) or []),
            }

    def get_all_profiles(self) -> dict:
        with self._lock:
            keys = list(self._state.keys())
        return {key: self.get_profile(key) for key in keys}

    def reset(self, agent_id: str) -> None:
        key = str(agent_id or "unknown")
        with self._lock:
            self._state.pop(key, None)
