"""PAR — Proxy Abductive Reasoning (T5 theorem implementation).

When N < 2^k -> abductive mode (IBE - Inference to Best Explanation).
When N -> inf -> full causal discovery.

T5 theorem: From single-agent trace, cross-agent causal graph
cannot be recovered without proxy-level observation.
"""

from __future__ import annotations

import math
import threading


class PARReasoner:
    """Proxy Abductive Reasoning for DENY diagnosis."""

    T5_THEOREM = "Cross-agent causal graph unrecoverable from single-agent trace"
    MAX_OBSERVATIONS = 10_000
    MAX_HYPOTHESES = 1_000

    def __init__(self, config: dict | None = None):
        cfg = config or {}
        self.abductive_threshold = int(cfg.get("abductive_threshold", 32))
        self._observations: list[dict] = []
        self._hypotheses: list[dict] = []
        self._lock = threading.Lock()

    def observe(self, event: dict) -> None:
        """Record proxy-level observation."""
        with self._lock:
            self._observations.append(dict(event or {}))
            if len(self._observations) > self.MAX_OBSERVATIONS:
                self._observations = self._observations[-self.MAX_OBSERVATIONS :]

    def abduce(self, deny_event: dict) -> dict:
        """Generate best explanation for DENY event (IBE)."""
        n = len(self._observations)
        mode = "abductive" if n < self.abductive_threshold else "causal"

        hypotheses = self._generate_hypotheses(deny_event)
        ranked = self._rank_by_simplicity(hypotheses)
        with self._lock:
            self._hypotheses.extend(ranked)
            if len(self._hypotheses) > self.MAX_HYPOTHESES:
                self._hypotheses = self._hypotheses[-self.MAX_HYPOTHESES :]

        return {
            "mode": mode,
            "n_observations": n,
            "best_explanation": ranked[0] if ranked else None,
            "all_hypotheses": ranked,
            "confidence": self._compute_confidence(n),
            "t5_applies": n < self.abductive_threshold,
        }

    def _generate_hypotheses(self, event: dict) -> list[dict]:
        reasons = list(event.get("reasons", []) or [])
        hypotheses: list[dict] = []
        for reason in reasons:
            text = str(reason)
            hypotheses.append(
                {
                    "hypothesis": f"Caused by: {text}",
                    "simplicity": 1.0 / max(1, len(text)),
                    "consistency": 1.0,
                }
            )
        if not hypotheses:
            hypotheses.append(
                {
                    "hypothesis": "Unknown cause - insufficient data",
                    "simplicity": 0.5,
                    "consistency": 0.5,
                }
            )
        return hypotheses

    def _rank_by_simplicity(self, hypotheses: list[dict]) -> list[dict]:
        return sorted(hypotheses, key=lambda h: -float(h["simplicity"]))

    def _compute_confidence(self, n: int) -> float:
        """Confidence grows with observations (asymptotic)."""
        return 1.0 - math.exp(-float(n) / float(self.abductive_threshold))

    def get_causal_graph(self) -> dict:
        """Partial causal graph from proxy observations."""
        n = len(self._observations)
        return {
            "nodes": n,
            "mode": "abductive" if n < self.abductive_threshold else "causal",
            "completeness": self._compute_confidence(n),
            "t5_limitation": n < self.abductive_threshold,
        }

    def get_stats(self) -> dict:
        with self._lock:
            observations = len(self._observations)
            return {
                "observations": observations,
                "hypotheses_generated": len(self._hypotheses),
                "mode": "abductive" if observations < self.abductive_threshold else "causal",
            }

