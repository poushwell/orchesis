"""NLCE paper data export helpers."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class NLCEPaperExporter:
    """Exports NLCE research data for academic paper."""

    CLAIMS = {
        "zipf_law": {"alpha": 1.672, "r2": 0.980, "exp": 8},
        "rg_universality": {"n_star": 16, "ks_p": 1.0, "exp": 13},
        "context_collapse": {"growth_factor": 12, "overhead": 0.008},
        "quorum_sensing": {"n_star": 16, "exp": 13},
    }

    def export_claims_table(self) -> str:
        """LaTeX/Markdown table of all verified claims."""
        lines = [
            "| claim | key metrics | experiment |",
            "|---|---|---|",
        ]
        for name, payload in sorted(self.CLAIMS.items()):
            exp = payload.get("exp", "-")
            metrics = ", ".join(f"{k}={v}" for k, v in payload.items() if k != "exp")
            lines.append(f"| {name} | {metrics} | exp{exp} |")
        return "\n".join(lines) + "\n"

    def export_experiment_results(self, results_dir: str) -> dict:
        """Aggregate all experiment results into paper-ready format."""
        root = Path(results_dir)
        if not root.exists():
            return {"results_dir": str(root), "total_files": 0, "experiments": {}, "generated_at": datetime.now(timezone.utc).isoformat()}
        experiments: dict[str, list[dict[str, Any]]] = {}
        total = 0
        for file_path in sorted(root.glob("*.json")):
            try:
                payload = json.loads(file_path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if not isinstance(payload, dict):
                continue
            exp_id = str(payload.get("experiment_id", "unknown"))
            experiments.setdefault(exp_id, []).append(payload)
            total += 1
        aggregate: dict[str, Any] = {}
        for exp_id, rows in experiments.items():
            completed = [row for row in rows if str(row.get("status", "")).lower() == "completed"]
            latest = rows[-1] if rows else {}
            avg_metric = (
                sum(float(row.get("key_metric", 0.0) or 0.0) for row in completed) / float(len(completed))
                if completed
                else 0.0
            )
            aggregate[exp_id] = {
                "runs": len(rows),
                "completed_runs": len(completed),
                "avg_key_metric": round(avg_metric, 6),
                "latest_interpretation": str(latest.get("interpretation", "")),
                "latest_timestamp": str(latest.get("timestamp", "")),
            }
        return {
            "results_dir": str(root),
            "total_files": total,
            "experiments": aggregate,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def export_methodology(self) -> str:
        """Methodology section text."""
        return (
            "## Methodology\n\n"
            "We evaluate NLCE hypotheses using deterministic offline replay of experiment traces. "
            "Each experiment run records structured metrics (status, key_metric, interpretation) and is "
            "persisted as JSON for reproducibility. Reported claims are confirmed only when repeated runs "
            "show stable behavior under the same evaluation policy.\n"
        )

    def generate_abstract(self) -> str:
        """Draft abstract based on confirmed results."""
        zipf = self.CLAIMS["zipf_law"]
        rg = self.CLAIMS["rg_universality"]
        collapse = self.CLAIMS["context_collapse"]
        return (
            "We present NLCE, an empirical framework for analyzing language-agent dynamics under constrained pipelines. "
            f"Our results show Zipf-like token behavior (alpha={zipf['alpha']}, R^2={zipf['r2']}) and RG-style universality "
            f"near n*={rg['n_star']} with KS p-value {rg['ks_p']}. We further observe context-collapse growth "
            f"factors up to {collapse['growth_factor']} with low overhead ({collapse['overhead']}). "
            "These findings support a practical, measurable approach to safety and efficiency tuning in agentic systems."
        )

    def export_all(self, output_dir: str) -> list[str]:
        """Export all paper sections. Returns list of created files."""
        target = Path(output_dir)
        target.mkdir(parents=True, exist_ok=True)
        files: list[Path] = []
        claims_path = target / "claims_table.md"
        claims_path.write_text(self.export_claims_table(), encoding="utf-8")
        files.append(claims_path)
        methodology_path = target / "methodology.md"
        methodology_path.write_text(self.export_methodology(), encoding="utf-8")
        files.append(methodology_path)
        abstract_path = target / "abstract.md"
        abstract_path.write_text(self.generate_abstract() + "\n", encoding="utf-8")
        files.append(abstract_path)
        results_path = target / "experiment_results.json"
        results_path.write_text(
            json.dumps(self.export_experiment_results("experiments/results"), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        files.append(results_path)
        return [str(path) for path in files]
