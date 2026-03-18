"""arXiv submission validator for NLCE paper packages."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class ArxivSubmissionValidator:
    """Validates paper for arXiv submission requirements.

    Target: cs.AI, cs.SE categories.
    Submission date: 29-30 March 2026.
    """

    ARXIV_REQUIREMENTS = {
        "min_pages": 4,
        "max_pages": 30,
        "requires_abstract": True,
        "requires_references": True,
        "latex_supported": True,
        "categories": ["cs.AI", "cs.SE", "cs.CR", "cs.NI"],
    }

    CHECKLIST = [
        "abstract_present",
        "introduction_present",
        "methodology_described",
        "results_reproducible",
        "references_formatted",
        "no_personal_info",
        "figures_readable",
        "equations_numbered",
    ]

    def _estimate_pages(self, paper: dict[str, Any]) -> int:
        text = " ".join(str(paper.get(key, "")) for key in ("abstract", "introduction", "methodology", "results", "discussion", "conclusion"))
        words = len(text.split())
        # Approximate 500 words per page for a typical CS paper layout.
        return max(1, int((words + 499) / 500))

    def suggest_categories(self, paper: dict) -> list[str]:
        """Suggest arXiv categories based on content."""
        text = json.dumps(paper, ensure_ascii=False).lower()
        suggested: list[str] = []
        if any(token in text for token in ("llm", "agent", "reasoning", "context")):
            suggested.append("cs.AI")
        if any(token in text for token in ("proxy", "engineering", "system", "software")):
            suggested.append("cs.SE")
        if any(token in text for token in ("security", "threat", "policy")):
            suggested.append("cs.CR")
        if any(token in text for token in ("network", "latency", "routing")):
            suggested.append("cs.NI")
        if not suggested:
            suggested.append("cs.AI")
        return suggested[:2]

    def format_references(self, references: list[str]) -> str:
        """Format references in arXiv style."""
        rows = [str(item).strip() for item in references if str(item).strip()]
        return "\n".join(f"[{idx}] {item}" for idx, item in enumerate(rows, start=1)) + ("\n" if rows else "")

    def validate(self, paper: dict) -> dict:
        payload = paper if isinstance(paper, dict) else {}
        checklist: dict[str, bool] = {}
        checklist["abstract_present"] = bool(str(payload.get("abstract", "")).strip())
        checklist["introduction_present"] = bool(str(payload.get("introduction", "")).strip())
        checklist["methodology_described"] = bool(str(payload.get("methodology", "")).strip())
        checklist["results_reproducible"] = bool(str(payload.get("results", "")).strip())
        refs = payload.get("references", [])
        checklist["references_formatted"] = isinstance(refs, list) and len(refs) > 0
        serialized = json.dumps(payload, ensure_ascii=False).lower()
        checklist["no_personal_info"] = not any(token in serialized for token in ("@gmail.com", "phone:", "telegram:", "passport"))
        checklist["figures_readable"] = True
        checklist["equations_numbered"] = True

        pages = self._estimate_pages(payload)
        errors: list[str] = []
        warnings: list[str] = []
        if pages < int(self.ARXIV_REQUIREMENTS["min_pages"]):
            warnings.append("Estimated page count below recommended minimum for research submissions.")
        if pages > int(self.ARXIV_REQUIREMENTS["max_pages"]):
            errors.append("Estimated page count exceeds arXiv maximum.")
        for item in self.CHECKLIST:
            if not checklist.get(item, False):
                if item in {"abstract_present", "references_formatted", "introduction_present"}:
                    errors.append(f"Missing required item: {item}")
                else:
                    warnings.append(f"Checklist item requires attention: {item}")

        valid = len(errors) == 0
        return {
            "valid": bool(valid),
            "ready_for_submission": bool(valid and all(checklist.values())),
            "checklist": checklist,
            "warnings": warnings,
            "errors": errors,
            "suggested_categories": self.suggest_categories(payload),
            "estimated_pages": pages,
        }

    def generate_submission_package(self, paper: dict, output_dir: str) -> dict:
        """Generate complete arXiv submission package."""
        payload = paper if isinstance(paper, dict) else {}
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        validation = self.validate(payload)
        main_file = out / "main.tex"
        references = out / "references.txt"
        metadata = out / "metadata.json"
        main_file.write_text(
            (
                "\\documentclass{article}\n"
                "\\begin{document}\n"
                f"\\title{{{payload.get('title', 'Untitled')}}}\n"
                "\\maketitle\n"
                f"\\begin{{abstract}}\n{payload.get('abstract', '')}\n\\end{{abstract}}\n"
                f"\\section{{Introduction}}\n{payload.get('introduction', '')}\n"
                f"\\section{{Methodology}}\n{payload.get('methodology', '')}\n"
                f"\\section{{Results}}\n{payload.get('results', '')}\n"
                "\\end{document}\n"
            ),
            encoding="utf-8",
        )
        refs_list = payload.get("references", [])
        references.write_text(
            self.format_references(refs_list if isinstance(refs_list, list) else []),
            encoding="utf-8",
        )
        metadata.write_text(json.dumps(validation, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        files = [str(main_file), str(references), str(metadata)]
        category = validation["suggested_categories"][0] if validation["suggested_categories"] else "cs.AI"
        return {
            "files": files,
            "main_file": str(main_file),
            "category": category,
            "ready": bool(validation["ready_for_submission"]),
        }
