"""Context Quality Index - unified CQS computation.

CQS = weighted combination of:
- Coherence (IACS score)
- Freshness (recency of information)
- Density (information per token)
- Relevance (Sperber-Wilson relevance score)
"""

from __future__ import annotations

import math


class ContextQualityIndex:
    """Unified Context Quality Score computation."""

    WEIGHTS = {
        "coherence": 0.35,
        "freshness": 0.25,
        "density": 0.20,
        "relevance": 0.20,
    }

    def __init__(self, config: dict | None = None):
        cfg = config or {}
        self.weights = {k: float(cfg.get(f"w_{k}", v)) for k, v in self.WEIGHTS.items()}

    def compute_coherence(self, iacs_score: float) -> float:
        return max(0.0, min(1.0, float(iacs_score)))

    def compute_freshness(self, messages: list[dict], decay: float = 0.1) -> float:
        """Freshness is a recency-weighted score in [0, 1]."""
        if not messages:
            return 0.0
        n = len(messages)
        weighted = 0.0
        total = 0.0
        for i in range(n):
            age = n - i - 1
            w = math.exp(-float(decay) * age)
            recency_score = float(i + 1) / float(n)
            weighted += w * recency_score
            total += w
        if total <= 0.0:
            return 0.0
        return round(max(0.0, min(1.0, weighted / total)), 4)

    def compute_density(self, messages: list[dict]) -> float:
        """Information density = unique tokens / total tokens."""
        all_words: list[str] = []
        for msg in messages:
            content = str(msg.get("content", ""))
            all_words.extend(content.lower().split())
        if not all_words:
            return 0.0
        unique = len(set(all_words))
        return round(unique / max(1, len(all_words)), 4)

    def compute_cqs(self, metrics: dict) -> dict:
        """Compute unified CQS from component metrics."""
        coherence = self.compute_coherence(float(metrics.get("iacs", 0.5)))
        freshness = max(0.0, min(1.0, float(metrics.get("freshness", 0.5))))
        density = max(0.0, min(1.0, float(metrics.get("density", 0.5))))
        relevance = max(0.0, min(1.0, float(metrics.get("relevance", 0.5))))

        cqs = (
            self.weights["coherence"] * coherence
            + self.weights["freshness"] * freshness
            + self.weights["density"] * density
            + self.weights["relevance"] * relevance
        )

        return {
            "cqs": round(cqs, 4),
            "components": {
                "coherence": round(coherence, 4),
                "freshness": round(freshness, 4),
                "density": round(density, 4),
                "relevance": round(relevance, 4),
            },
            "grade": "A" if cqs > 0.8 else "B" if cqs > 0.6 else "C" if cqs > 0.4 else "D",
        }

