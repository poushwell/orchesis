"""NLCE experiment runner and results persistence."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from orchesis.context_dna import ContextDNA


class NLCEExperimentRunner:
    """Runs NLCE research experiments and saves results."""

    EXPERIMENTS = {
        "exp1": "Context DNA Baseline",
        "exp4": "Collapse Detection",
        "exp5": "TCP Backpressure",
        "exp8": "Zipf Law Verification",
        "exp13": "RG Universality",
    }

    def __init__(self, config: dict | None = None):
        cfg = config if isinstance(config, dict) else {}
        self.results_dir = str(cfg.get("results_dir", "experiments/results"))

    @staticmethod
    def _token_value(item: dict[str, Any]) -> int:
        for key in ("token_count", "tokens", "total_tokens"):
            raw = item.get(key)
            if isinstance(raw, int | float):
                return int(raw)
        usage = item.get("usage")
        if isinstance(usage, dict):
            inp = usage.get("input_tokens", usage.get("prompt_tokens", 0))
            out = usage.get("output_tokens", usage.get("completion_tokens", 0))
            if isinstance(inp, int | float) and isinstance(out, int | float):
                return int(inp) + int(out)
        return 0

    def _exp_zipf(self, data: list[dict]) -> dict:
        """Exp 8: Verify Zipf's law in token distributions."""
        tokens = sorted([self._token_value(item) for item in data if isinstance(item, dict)], reverse=True)
        tokens = [value for value in tokens if value > 0]
        if len(tokens) < 2:
            return {"zipf_score": 0.0, "matches_zipf": False, "sample_size": len(tokens)}
        first = float(tokens[0])
        expected = [first / float(rank + 1) for rank in range(len(tokens))]
        err = 0.0
        total = 0.0
        for actual, exp in zip(tokens, expected):
            err += abs(float(actual) - exp)
            total += max(1e-6, exp)
        score = max(0.0, min(1.0, 1.0 - (err / total)))
        return {"zipf_score": round(score, 6), "matches_zipf": score >= 0.5, "sample_size": len(tokens)}

    def _exp_collapse(self, data: list[dict]) -> dict:
        """Exp 4: Detect context collapse from token growth."""
        tokens = [self._token_value(item) for item in data if isinstance(item, dict)]
        tokens = [value for value in tokens if value >= 0]
        if len(tokens) < 2:
            return {"collapse_detected": False, "growth_ratio": 0.0, "sample_size": len(tokens)}
        first = max(1.0, float(tokens[0]))
        last = float(tokens[-1])
        growth_ratio = last / first
        return {
            "collapse_detected": growth_ratio >= 2.0,
            "growth_ratio": round(growth_ratio, 6),
            "sample_size": len(tokens),
        }

    def _exp_baseline(self, data: list[dict]) -> dict:
        """Exp 1: Compute Context DNA baseline."""
        dna = ContextDNA("nlce-exp")
        for item in data:
            if not isinstance(item, dict):
                continue
            dna.observe(
                request={
                    "model": item.get("model", ""),
                    "messages": item.get("messages", []),
                    "tools": item.get("tools", []),
                    "topic": item.get("topic", "unknown"),
                },
                decision={
                    "duration_ms": item.get("duration_ms", 0.0),
                    "cache_hit": bool(item.get("cache_hit", False)),
                    "decision": str(item.get("decision", "ALLOW")),
                    "error": bool(item.get("error", False)),
                },
            )
        baseline = dna.compute_baseline()
        return {"baseline": baseline, "observation_count": len(data)}

    def run(self, experiment_id: str, data: list[dict]) -> dict:
        """Run experiment and return results."""
        exp_id = str(experiment_id or "").strip().lower()
        if exp_id not in self.EXPERIMENTS:
            return {
                "experiment_id": exp_id,
                "name": "Unknown",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "status": "failed",
                "results": {"error": "unknown experiment"},
                "key_metric": 0.0,
                "interpretation": "Experiment id is not supported.",
            }
        try:
            if exp_id == "exp8":
                results = self._exp_zipf(data)
                key_metric = float(results.get("zipf_score", 0.0) or 0.0)
                interpretation = "Token distribution approximates Zipf law." if key_metric >= 0.5 else "Token distribution deviates from Zipf law."
            elif exp_id == "exp4":
                results = self._exp_collapse(data)
                key_metric = float(results.get("growth_ratio", 0.0) or 0.0)
                interpretation = "Context collapse likely detected." if bool(results.get("collapse_detected")) else "No collapse signal detected."
            elif exp_id == "exp1":
                results = self._exp_baseline(data)
                key_metric = float(results.get("baseline", {}).get("error_rate", 0.0) or 0.0)
                interpretation = "Context DNA baseline computed."
            else:
                results = {"sample_size": len(data), "status": "placeholder"}
                key_metric = float(len(data))
                interpretation = "Experiment completed with placeholder implementation."
            return {
                "experiment_id": exp_id,
                "name": self.EXPERIMENTS[exp_id],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "status": "completed",
                "results": results,
                "key_metric": float(key_metric),
                "interpretation": interpretation,
            }
        except Exception as error:
            return {
                "experiment_id": exp_id,
                "name": self.EXPERIMENTS.get(exp_id, "Unknown"),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "status": "failed",
                "results": {"error": str(error)},
                "key_metric": 0.0,
                "interpretation": "Experiment execution failed.",
            }

    def save(self, result: dict) -> str:
        """Save to experiments/results/{id}_{date}.json"""
        payload = dict(result) if isinstance(result, dict) else {}
        exp_id = str(payload.get("experiment_id", "unknown"))
        date_token = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out_dir = Path(self.results_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"{exp_id}_{date_token}.json"
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return str(path)

    def list_results(self) -> list[dict]:
        """List all saved experiment results."""
        out_dir = Path(self.results_dir)
        if not out_dir.exists():
            return []
        items: list[dict] = []
        for file_path in sorted(out_dir.glob("*.json")):
            try:
                payload = json.loads(file_path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if isinstance(payload, dict):
                payload["file"] = str(file_path)
                items.append(payload)
        return items

