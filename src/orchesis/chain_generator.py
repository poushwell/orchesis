"""Synthetic chain generator for calibration and offline evaluation.

Produces reproducible synthetic agent chains with ground-truth hazard
values (sigma_true) that downstream calibration code uses to fit observed
hazard signals against the truth. v1 minimum viable per SPEC §2.5:

  - Single chain_type "research" (others raise NotImplementedError)
  - Five drift profiles (no_drift, linear, step, sinusoidal, exponential)
  - Two injection events fully implemented (factual_drift, tool_failure);
    the remaining four are recognized but stubbed (zero severity).
  - Seed-driven reproducibility — same seed produces byte-identical JSON.
  - JSON schema v1 with round-trip parsing.

Public API:

    ChainGenerator(seed=42).generate(length, drift_profile, injection_events)
    Chain.to_dict() / .to_json() / from_dict() / from_json()
    DriftProfile + factory helpers: no_drift(), linear_drift(), step_drift(),
        sinusoidal_drift(), exponential_drift()
    InjectionEvent
    validate_chain_schema(d)        — raises ChainSchemaError on invalid input
    SCHEMA_VERSION                  — increment when breaking the format
"""

from __future__ import annotations

import json
import math
import random
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Literal, Sequence


SCHEMA_VERSION = 1


# ---------------------------------------------------------------------------
# Drift profiles
# ---------------------------------------------------------------------------


DriftKind = Literal["no_drift", "linear", "step", "sinusoidal", "exponential"]


@dataclass(frozen=True, slots=True)
class DriftProfile:
    kind: DriftKind
    magnitude: float = 0.5        # max contribution at saturation
    rate: float = 0.05            # per-step growth for linear/exponential
    period: int = 50              # full period for sinusoidal
    step_at: int = 25             # index where step drift fires
    phase: float = 0.0            # radians offset for sinusoidal

    def value_at(self, step: int) -> float:
        if self.kind == "no_drift":
            return 0.0
        if self.kind == "linear":
            return min(self.magnitude, self.rate * step)
        if self.kind == "step":
            return self.magnitude if step >= self.step_at else 0.0
        if self.kind == "sinusoidal":
            angle = 2.0 * math.pi * step / max(1, self.period) + self.phase
            return 0.5 * self.magnitude * (1.0 + math.sin(angle))
        if self.kind == "exponential":
            return min(self.magnitude, self.magnitude * (1.0 - math.exp(-self.rate * step)))
        raise ValueError(f"unknown drift kind {self.kind!r}")


def no_drift() -> DriftProfile:
    return DriftProfile(kind="no_drift")


def linear_drift(rate: float = 0.02, magnitude: float = 0.6) -> DriftProfile:
    return DriftProfile(kind="linear", rate=rate, magnitude=magnitude)


def step_drift(step_at: int = 25, magnitude: float = 0.5) -> DriftProfile:
    return DriftProfile(kind="step", step_at=step_at, magnitude=magnitude)


def sinusoidal_drift(period: int = 40, magnitude: float = 0.4) -> DriftProfile:
    return DriftProfile(kind="sinusoidal", period=period, magnitude=magnitude)


def exponential_drift(rate: float = 0.05, magnitude: float = 0.7) -> DriftProfile:
    return DriftProfile(kind="exponential", rate=rate, magnitude=magnitude)


# ---------------------------------------------------------------------------
# Injection events
# ---------------------------------------------------------------------------


InjectionKind = Literal[
    "factual_drift",
    "tool_failure",
    "context_leak",         # stubbed in v1
    "schema_violation",     # stubbed
    "loop_attack",          # stubbed
    "premature_conclusion", # stubbed
]


@dataclass(frozen=True, slots=True)
class InjectionEvent:
    kind: InjectionKind
    at_step: int
    severity: float = 0.6  # ground-truth severity in [0, 1]


_FULLY_IMPLEMENTED_INJECTIONS = frozenset({"factual_drift", "tool_failure"})


# ---------------------------------------------------------------------------
# Chain shape
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ChainStep:
    step: int
    prompt: str
    response: str
    tools_called: list[str]
    tool_results: list[dict[str, Any]]
    sigma_true: float
    drift_value: float
    injection: dict[str, Any] | None = None  # serialized InjectionEvent or None


@dataclass(slots=True)
class Chain:
    chain_id: str
    seed: int
    chain_type: str
    length: int
    drift_profile: DriftProfile
    schema_version: int
    steps: list[ChainStep] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "seed": self.seed,
            "chain_type": self.chain_type,
            "length": self.length,
            "drift_profile": asdict(self.drift_profile),
            "steps": [
                {
                    "step": s.step,
                    "prompt": s.prompt,
                    "response": s.response,
                    "tools_called": list(s.tools_called),
                    "tool_results": [dict(r) for r in s.tool_results],
                    "sigma_true": s.sigma_true,
                    "drift_value": s.drift_value,
                    "injection": dict(s.injection) if s.injection else None,
                }
                for s in self.steps
            ],
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Chain":
        validate_chain_schema(d)
        dp = DriftProfile(**d["drift_profile"])
        steps = [
            ChainStep(
                step=int(rec["step"]),
                prompt=str(rec["prompt"]),
                response=str(rec["response"]),
                tools_called=list(rec.get("tools_called", []) or []),
                tool_results=[dict(r) for r in rec.get("tool_results", []) or []],
                sigma_true=float(rec["sigma_true"]),
                drift_value=float(rec["drift_value"]),
                injection=dict(rec["injection"]) if rec.get("injection") else None,
            )
            for rec in d["steps"]
        ]
        return cls(
            chain_id=str(d["chain_id"]),
            seed=int(d["seed"]),
            chain_type=str(d["chain_type"]),
            length=int(d["length"]),
            drift_profile=dp,
            schema_version=int(d["schema_version"]),
            steps=steps,
        )

    @classmethod
    def from_json(cls, text: str) -> "Chain":
        return cls.from_dict(json.loads(text))


# ---------------------------------------------------------------------------
# Schema validation (stdlib, no external dep)
# ---------------------------------------------------------------------------


class ChainSchemaError(Exception):
    """Raised when a serialized chain does not match the v1 schema."""


def validate_chain_schema(d: Any) -> None:
    if not isinstance(d, dict):
        raise ChainSchemaError("chain must be a JSON object")
    required = {
        "schema_version": int,
        "chain_id": str,
        "seed": int,
        "chain_type": str,
        "length": int,
        "drift_profile": dict,
        "steps": list,
    }
    for key, typ in required.items():
        if key not in d:
            raise ChainSchemaError(f"missing required key {key!r}")
        if not isinstance(d[key], typ):
            raise ChainSchemaError(
                f"key {key!r}: expected {typ.__name__}, got {type(d[key]).__name__}"
            )
    if d["schema_version"] != SCHEMA_VERSION:
        raise ChainSchemaError(
            f"unsupported schema_version {d['schema_version']!r}, expected {SCHEMA_VERSION}"
        )
    if d["length"] != len(d["steps"]):
        raise ChainSchemaError(
            f"length {d['length']} does not match steps count {len(d['steps'])}"
        )
    dp = d["drift_profile"]
    if "kind" not in dp or dp["kind"] not in (
        "no_drift", "linear", "step", "sinusoidal", "exponential"
    ):
        raise ChainSchemaError("drift_profile.kind invalid")
    for i, rec in enumerate(d["steps"]):
        if not isinstance(rec, dict):
            raise ChainSchemaError(f"step {i}: must be an object")
        for key, typ in (
            ("step", int),
            ("prompt", str),
            ("response", str),
            ("tools_called", list),
            ("tool_results", list),
            ("sigma_true", (int, float)),
            ("drift_value", (int, float)),
        ):
            if key not in rec:
                raise ChainSchemaError(f"step {i}: missing key {key!r}")
            if not isinstance(rec[key], typ):
                want = (
                    typ.__name__
                    if isinstance(typ, type)
                    else " or ".join(t.__name__ for t in typ)
                )
                raise ChainSchemaError(
                    f"step {i}.{key}: expected {want}, got {type(rec[key]).__name__}"
                )
        if not (0.0 <= float(rec["sigma_true"]) <= 1.0):
            raise ChainSchemaError(f"step {i}.sigma_true out of [0, 1]")


# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------


_RESEARCH_PROMPT_TEMPLATES: tuple[str, ...] = (
    "Summarize the key claims of {topic}.",
    "Compare and contrast {topic} with {alt_topic}.",
    "What are the main open questions in {topic}?",
    "Explain {topic} to a sceptical reader and address two counter-arguments.",
    "Trace the evolution of {topic} over the past decade.",
    "Identify three load-bearing assumptions behind {topic}.",
    "Provide a concise literature review of {topic}, citing seminal works.",
    "Outline an experiment that would falsify the strongest claim of {topic}.",
    "What is the relationship between {topic} and {alt_topic}?",
    "Quantify the cost-benefit trade-offs of {topic} in production settings.",
    "Survey practical deployment issues with {topic}.",
    "Map the major schools of thought within {topic}.",
    "Identify recent surprises or reversals in {topic}.",
)


_RESEARCH_TOPICS: tuple[str, ...] = (
    "distributed consensus", "context window optimization", "long-running agent reliability",
    "differential privacy in inference", "graph-based retrieval augmentation",
    "tool calling reliability", "load shedding under contention",
    "online calibration of language models", "fault-tolerant orchestration",
    "cost-aware request routing", "agent failure attribution",
    "structured prompt compression", "selective context retention",
)


_TOOL_NAMES: tuple[str, ...] = (
    "search_web", "fetch_paper", "summarize_text", "extract_entities",
    "compare_versions", "cite_source", "score_relevance",
)


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _BaselineParams:
    """Tuning constants for ground-truth sigma. Defaults pending empirical
    calibration; hot-reload path preserved via the dataclass (caller may
    pass a custom instance to generate())."""
    sigma_baseline_low: float = 0.05
    sigma_baseline_high: float = 0.15
    drift_to_sigma: float = 0.5      # multiplier on drift_value
    injection_severity_weight: float = 0.8

    def baseline_at(self, rng: random.Random) -> float:
        return rng.uniform(self.sigma_baseline_low, self.sigma_baseline_high)


class ChainGenerator:
    """Deterministic chain generator. Same seed → byte-identical output."""

    def __init__(
        self,
        seed: int = 42,
        *,
        baseline_params: _BaselineParams | None = None,
    ) -> None:
        self._seed = int(seed)
        self._baseline = baseline_params or _BaselineParams()

    def generate(
        self,
        length: int,
        chain_type: str = "research",
        drift_profile: DriftProfile | None = None,
        injection_events: Sequence[InjectionEvent] | None = None,
    ) -> Chain:
        if length <= 0:
            raise ValueError("length must be positive")
        if chain_type != "research":
            raise NotImplementedError(
                f"chain_type {chain_type!r} not supported in v1 "
                "(only 'research' is implemented)"
            )

        drift = drift_profile or no_drift()
        injections_by_step: dict[int, InjectionEvent] = {}
        for ev in injection_events or ():
            if ev.at_step < 0 or ev.at_step >= length:
                raise ValueError(
                    f"injection at_step {ev.at_step} out of range [0, {length})"
                )
            injections_by_step[ev.at_step] = ev

        rng = random.Random(self._seed)
        chain_id = uuid.UUID(int=rng.getrandbits(128)).hex
        steps: list[ChainStep] = []
        for i in range(length):
            prompt = self._gen_prompt(rng)
            response = self._gen_response(rng, i)
            tool_calls, tool_results, tool_inj_severity = self._gen_tools(
                rng, injections_by_step.get(i)
            )
            drift_value = drift.value_at(i)
            sigma_true = self._compute_sigma(
                rng=rng,
                drift_value=drift_value,
                injection=injections_by_step.get(i),
                tool_failure_severity=tool_inj_severity,
            )
            inj = injections_by_step.get(i)
            steps.append(ChainStep(
                step=i,
                prompt=prompt,
                response=response,
                tools_called=tool_calls,
                tool_results=tool_results,
                sigma_true=round(sigma_true, 6),
                drift_value=round(drift_value, 6),
                injection={
                    "kind": inj.kind, "at_step": inj.at_step, "severity": inj.severity
                } if inj else None,
            ))

        return Chain(
            chain_id=chain_id,
            seed=self._seed,
            chain_type=chain_type,
            length=length,
            drift_profile=drift,
            schema_version=SCHEMA_VERSION,
            steps=steps,
        )

    # -- generators --------------------------------------------------------

    def _gen_prompt(self, rng: random.Random) -> str:
        template = rng.choice(_RESEARCH_PROMPT_TEMPLATES)
        topic = rng.choice(_RESEARCH_TOPICS)
        alt_topic = rng.choice([t for t in _RESEARCH_TOPICS if t != topic])
        return template.format(topic=topic, alt_topic=alt_topic)

    def _gen_response(self, rng: random.Random, step: int) -> str:
        # v1 keeps responses structurally consistent for reproducibility
        # without leaning on an embedding model. v2 will plug in real
        # embeddings for semantic drift.
        sentences = rng.randint(2, 5)
        words_per_sentence = rng.randint(8, 15)
        bag = ("graph", "context", "agent", "score", "tool", "result", "model",
               "policy", "metric", "session", "request", "phase")
        out = []
        for _ in range(sentences):
            ws = [rng.choice(bag) for _ in range(words_per_sentence)]
            ws[0] = ws[0].capitalize()
            out.append(" ".join(ws) + ".")
        return f"[step={step}] " + " ".join(out)

    def _gen_tools(
        self,
        rng: random.Random,
        injection: InjectionEvent | None,
    ) -> tuple[list[str], list[dict[str, Any]], float]:
        n = rng.choices([0, 1, 2, 3], weights=[2, 4, 3, 1])[0]
        calls = [rng.choice(_TOOL_NAMES) for _ in range(n)]
        results: list[dict[str, Any]] = []
        injection_failure_severity = 0.0
        force_tool_failure = (
            injection is not None
            and injection.kind == "tool_failure"
            and injection.kind in _FULLY_IMPLEMENTED_INJECTIONS
        )
        for j, name in enumerate(calls):
            failed = False
            if force_tool_failure and j == 0:
                failed = True
            else:
                # Small baseline failure rate; deterministic from rng.
                failed = rng.random() < 0.02
            if failed:
                results.append({"tool": name, "status": "error", "error": "synthetic_failure"})
                if force_tool_failure and j == 0:
                    injection_failure_severity = injection.severity  # type: ignore[union-attr]
            else:
                results.append({"tool": name, "status": "ok"})
        return calls, results, injection_failure_severity

    def _compute_sigma(
        self,
        *,
        rng: random.Random,
        drift_value: float,
        injection: InjectionEvent | None,
        tool_failure_severity: float,
    ) -> float:
        sigma = self._baseline.baseline_at(rng)
        sigma += self._baseline.drift_to_sigma * drift_value
        if injection is not None and injection.kind in _FULLY_IMPLEMENTED_INJECTIONS:
            sigma += self._baseline.injection_severity_weight * injection.severity
        elif injection is not None:
            # Stubbed kinds — recognized but contribute zero severity. The
            # ground-truth column still reflects the injection occurred via
            # the chain step's `injection` field so v2 can wire them in.
            pass
        if tool_failure_severity > 0.0:
            # Already counted when injection kind == tool_failure, but kept
            # explicit so callers can read off this contribution.
            pass
        return max(0.0, min(1.0, sigma))
