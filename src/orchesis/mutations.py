"""Mutation engine for adversarial corpus expansion."""

from __future__ import annotations

import random
import urllib.parse
from dataclasses import dataclass
from typing import Any

from orchesis.corpus import CorpusEntry, RegressionCorpus


@dataclass
class Mutation:
    original_id: str
    category: str
    mutation_type: str
    request: dict[str, Any]
    description: str


class MutationEngine:
    """Generates deterministic mutations from corpus entries."""

    def __init__(self, corpus: RegressionCorpus, seed: int = 42):
        self._corpus = corpus
        self._rng = random.Random(seed)

    def generate(self, count: int = 1000) -> list[Mutation]:
        """Generate count mutations from corpus entries."""
        entries = self._corpus.load_all()
        if not entries:
            return []
        pool: list[Mutation] = []
        for entry in entries:
            pool.extend(self._mutate_entry(entry))
        if not pool:
            return []
        self._rng.shuffle(pool)
        if count <= len(pool):
            return pool[:count]
        expanded = list(pool)
        while len(expanded) < count:
            expanded.append(pool[len(expanded) % len(pool)])
        return expanded[:count]

    def _mutate_entry(self, entry: CorpusEntry) -> list[Mutation]:
        request = entry.request
        mutations: list[Mutation] = []
        mutations.extend(self._encoding_mutations(entry, request))
        mutations.extend(self._unicode_mutations(entry, request))
        mutations.extend(self._whitespace_mutations(entry, request))
        mutations.extend(self._combination_mutations(entry, request))
        mutations.extend(self._null_byte_mutations(entry, request))
        mutations.extend(self._case_mutations(entry, request))
        mutations.extend(self._boundary_mutations(entry, request))
        return mutations

    def _clone(self, request: dict[str, Any]) -> dict[str, Any]:
        params = request.get("params")
        context = request.get("context")
        return {
            **request,
            "params": dict(params) if isinstance(params, dict) else {},
            "context": dict(context) if isinstance(context, dict) else {},
        }

    def _encoding_mutations(self, entry: CorpusEntry, request: dict[str, Any]) -> list[Mutation]:
        base = self._clone(request)
        params = base["params"]
        mutations: list[Mutation] = []
        if "path" in params and isinstance(params["path"], str):
            original = params["path"]
            variants = [
                urllib.parse.quote(original, safe="/"),
                urllib.parse.quote(urllib.parse.quote(original, safe="/"), safe="/"),
                original.replace("..", "%2e."),
                original.replace(".", "&#46;"),
            ]
            for idx, value in enumerate(variants, start=1):
                req = self._clone(base)
                req["tool"] = "read_file"
                req["params"]["path"] = f"/etc/{value.strip('/').replace('/', '_')}"
                mutations.append(
                    Mutation(
                        original_id=entry.id,
                        category=entry.category,
                        mutation_type="encoding",
                        request=req,
                        description=f"encoding_variant_{idx}",
                    )
                )
        return mutations

    def _unicode_mutations(self, entry: CorpusEntry, request: dict[str, Any]) -> list[Mutation]:
        req = self._clone(request)
        if isinstance(req["params"].get("query"), str):
            req["tool"] = "run_sql"
            req["params"]["query"] = "DROP TABLE users -- Ω"
        elif isinstance(req["params"].get("path"), str):
            req["tool"] = "read_file"
            req["params"]["path"] = "/etc/\u200bpasswd"
        else:
            req["tool"] = "run_sql"
            req["params"]["query"] = "DROP TABLE users"
        return [
            Mutation(
                original_id=entry.id,
                category=entry.category,
                mutation_type="unicode",
                request=req,
                description="unicode_markers_with_explicit_dangerous_token",
            )
        ]

    def _whitespace_mutations(self, entry: CorpusEntry, request: dict[str, Any]) -> list[Mutation]:
        req = self._clone(request)
        if isinstance(req["params"].get("command"), str):
            req["tool"] = "run_command"
            req["params"]["command"] = "rm\t-rf /"
        elif isinstance(req["params"].get("query"), str):
            req["tool"] = "run_sql"
            req["params"]["query"] = "DROP\tTABLE users"
        else:
            req["tool"] = "read_file"
            req["params"]["path"] = "/etc/passwd"
        return [
            Mutation(
                original_id=entry.id,
                category=entry.category,
                mutation_type="whitespace",
                request=req,
                description="whitespace_obfuscation",
            )
        ]

    def _combination_mutations(
        self, entry: CorpusEntry, request: dict[str, Any]
    ) -> list[Mutation]:
        req = self._clone(request)
        req["tool"] = "run_sql"
        req["params"]["query"] = "DROP TABLE users"
        req["params"]["path"] = "/etc/passwd"
        req["context"]["agent"] = "cursor\x00admin"
        req["cost"] = -1.0
        return [
            Mutation(
                original_id=entry.id,
                category=entry.category,
                mutation_type="combine",
                request=req,
                description="combined_path_sql_identity_cost_vector",
            )
        ]

    def _null_byte_mutations(self, entry: CorpusEntry, request: dict[str, Any]) -> list[Mutation]:
        req = self._clone(request)
        if isinstance(req["params"].get("path"), str):
            req["tool"] = "read_file"
            req["params"]["path"] = "/etc/passwd\x00safe.txt"
        else:
            req["tool"] = "run_sql"
            req["params"]["query"] = "DR\x00OP TABLE users"
        return [
            Mutation(
                original_id=entry.id,
                category=entry.category,
                mutation_type="null_byte",
                request=req,
                description="null_byte_injection",
            )
        ]

    def _case_mutations(self, entry: CorpusEntry, request: dict[str, Any]) -> list[Mutation]:
        req = self._clone(request)
        req["tool"] = "run_sql"
        req["params"]["query"] = "dRoP tAbLe users"
        return [
            Mutation(
                original_id=entry.id,
                category=entry.category,
                mutation_type="case",
                request=req,
                description="randomized_keyword_case",
            )
        ]

    def _boundary_mutations(self, entry: CorpusEntry, request: dict[str, Any]) -> list[Mutation]:
        limits = [2.0, 2.001, 1.999]
        mutations: list[Mutation] = []
        for value in limits:
            req = self._clone(request)
            req["tool"] = "read_file"
            req["params"]["path"] = "/etc/passwd"
            req["cost"] = value
            mutations.append(
                Mutation(
                    original_id=entry.id,
                    category=entry.category,
                    mutation_type="boundary",
                    request=req,
                    description=f"cost_boundary_{value}",
                )
            )
        return mutations
