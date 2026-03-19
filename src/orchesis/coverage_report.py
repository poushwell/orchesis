"""Coverage Report - test and module coverage analysis."""

from __future__ import annotations

from pathlib import Path


class CoverageReportGenerator:
    """Analyzes test and module coverage."""

    def analyze(self, src_dir: str = "src/orchesis", test_dir: str = "tests") -> dict:
        src_modules = list(Path(src_dir).rglob("*.py"))
        test_files = list(Path(test_dir).glob("test_*.py"))

        module_names = [f.stem for f in src_modules if not f.stem.startswith("_")]
        tested = [m for m in module_names if any(f"test_{m}" in t.stem for t in test_files)]

        coverage = len(tested) / max(1, len(module_names))

        return {
            "total_modules": len(module_names),
            "tested_modules": len(tested),
            "untested_modules": len(module_names) - len(tested),
            "coverage_rate": round(coverage, 4),
            "test_files": len(test_files),
            "grade": "A" if coverage > 0.8 else "B" if coverage > 0.6 else "C",
        }

    def get_untested(self, src_dir: str = "src/orchesis", test_dir: str = "tests") -> list[str]:
        src_modules = list(Path(src_dir).rglob("*.py"))
        test_files = list(Path(test_dir).glob("test_*.py"))
        module_names = [f.stem for f in src_modules if not f.stem.startswith("_")]
        return [m for m in module_names if not any(f"test_{m}" in t.stem for t in test_files)]
