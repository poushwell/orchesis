"""Property tests for the synthetic chain generator (SPEC §2.5 v1)."""

from __future__ import annotations

import json

import pytest

from orchesis.chain_generator import (
    Chain,
    ChainGenerator,
    ChainSchemaError,
    DriftProfile,
    InjectionEvent,
    SCHEMA_VERSION,
    exponential_drift,
    linear_drift,
    no_drift,
    sinusoidal_drift,
    step_drift,
    validate_chain_schema,
)


# ---------------------------------------------------------------------------
# Drift profile math
# ---------------------------------------------------------------------------


class TestDriftProfileMath:
    def test_no_drift_always_zero(self):
        p = no_drift()
        for i in range(0, 100, 7):
            assert p.value_at(i) == 0.0

    def test_linear_monotonic(self):
        p = linear_drift(rate=0.01, magnitude=0.5)
        values = [p.value_at(i) for i in range(40)]
        assert all(values[i] <= values[i + 1] for i in range(len(values) - 1))
        assert values[-1] <= 0.5

    def test_linear_saturates(self):
        p = linear_drift(rate=0.1, magnitude=0.3)
        # 0.1 * 4 = 0.4 > 0.3 so step 4 must already saturate
        assert p.value_at(4) == 0.3

    def test_step_profile(self):
        p = step_drift(step_at=5, magnitude=0.4)
        assert p.value_at(0) == 0.0
        assert p.value_at(4) == 0.0
        assert p.value_at(5) == 0.4
        assert p.value_at(99) == 0.4

    def test_sinusoidal_bounded(self):
        p = sinusoidal_drift(period=20, magnitude=0.5)
        values = [p.value_at(i) for i in range(50)]
        assert min(values) >= 0.0
        assert max(values) <= 0.5

    def test_exponential_increasing(self):
        p = exponential_drift(rate=0.05, magnitude=0.6)
        values = [p.value_at(i) for i in range(0, 80, 5)]
        for i in range(len(values) - 1):
            assert values[i] <= values[i + 1] + 1e-9
        assert values[-1] <= 0.6 + 1e-9


# ---------------------------------------------------------------------------
# Reproducibility + structure
# ---------------------------------------------------------------------------


class TestGenerator:
    def test_seed_reproducibility(self):
        a = ChainGenerator(seed=42).generate(length=20, drift_profile=linear_drift())
        b = ChainGenerator(seed=42).generate(length=20, drift_profile=linear_drift())
        assert a.to_json() == b.to_json()

    def test_different_seeds_different_chains(self):
        a = ChainGenerator(seed=42).generate(length=10)
        b = ChainGenerator(seed=99).generate(length=10)
        # Likely different prompts / responses.
        assert a.to_json() != b.to_json()

    def test_chain_length_matches(self):
        chain = ChainGenerator().generate(length=15)
        assert len(chain.steps) == 15
        assert chain.length == 15

    def test_chain_id_is_hex(self):
        chain = ChainGenerator().generate(length=3)
        assert len(chain.chain_id) == 32
        assert all(c in "0123456789abcdef" for c in chain.chain_id)

    def test_zero_length_rejected(self):
        with pytest.raises(ValueError, match="positive"):
            ChainGenerator().generate(length=0)

    def test_unsupported_chain_type_rejected(self):
        with pytest.raises(NotImplementedError, match="chain_type"):
            ChainGenerator().generate(length=3, chain_type="coding")


# ---------------------------------------------------------------------------
# Drift → sigma relationships (SPEC §2.5 property tests)
# ---------------------------------------------------------------------------


class TestNoDriftClean:
    def test_no_drift_clean_baseline(self):
        """Clean chains should sit near baseline σ_true."""
        chain = ChainGenerator(seed=42).generate(length=50, drift_profile=no_drift())
        sigmas = [s.sigma_true for s in chain.steps]
        # Baseline is 0.05-0.15; all steps within that band when no drift / no injection.
        assert max(sigmas) <= 0.3, f"max sigma {max(sigmas)} too high for clean chain"


class TestLinearDriftMonotonic:
    def test_long_run_linear_drift_trend_up(self):
        """Long enough chain with linear drift should trend upwards."""
        chain = ChainGenerator(seed=42).generate(
            length=60,
            drift_profile=linear_drift(rate=0.02, magnitude=0.7),
        )
        first_window = chain.steps[:10]
        last_window = chain.steps[-10:]
        avg_first = sum(s.sigma_true for s in first_window) / len(first_window)
        avg_last = sum(s.sigma_true for s in last_window) / len(last_window)
        assert avg_last > avg_first


class TestInjectionSpike:
    def test_factual_drift_injection_spikes_sigma(self):
        injections = [InjectionEvent(kind="factual_drift", at_step=10, severity=0.9)]
        chain = ChainGenerator(seed=42).generate(
            length=20,
            drift_profile=no_drift(),
            injection_events=injections,
        )
        injected_step = chain.steps[10]
        neighbour = chain.steps[9]
        assert injected_step.sigma_true > neighbour.sigma_true + 0.3
        assert injected_step.injection == {"kind": "factual_drift", "at_step": 10, "severity": 0.9}

    def test_tool_failure_injection_spikes_sigma(self):
        injections = [InjectionEvent(kind="tool_failure", at_step=5, severity=0.8)]
        chain = ChainGenerator(seed=42).generate(
            length=15,
            drift_profile=no_drift(),
            injection_events=injections,
        )
        step = chain.steps[5]
        assert step.sigma_true >= 0.5  # 0.05-0.15 baseline + 0.8 * 0.8 = 0.59+

    def test_stubbed_injection_no_severity_contribution(self):
        injections = [InjectionEvent(kind="context_leak", at_step=5, severity=0.9)]
        chain = ChainGenerator(seed=42).generate(
            length=15,
            drift_profile=no_drift(),
            injection_events=injections,
        )
        injected = chain.steps[5]
        neighbour = chain.steps[6]
        # Stubbed kinds don't push sigma above baseline range.
        assert abs(injected.sigma_true - neighbour.sigma_true) < 0.2
        # But the injection is recorded in step metadata for v2.
        assert injected.injection["kind"] == "context_leak"

    def test_injection_out_of_range_rejected(self):
        with pytest.raises(ValueError, match="out of range"):
            ChainGenerator().generate(
                length=10,
                injection_events=[InjectionEvent("tool_failure", at_step=99, severity=0.5)],
            )


# ---------------------------------------------------------------------------
# Serialization round-trip
# ---------------------------------------------------------------------------


class TestSerialization:
    def test_json_roundtrip(self):
        original = ChainGenerator(seed=7).generate(
            length=12,
            drift_profile=step_drift(step_at=4, magnitude=0.4),
            injection_events=[InjectionEvent("tool_failure", at_step=7, severity=0.6)],
        )
        encoded = original.to_json()
        decoded = Chain.from_json(encoded)
        assert decoded.to_json() == encoded

    def test_to_dict_keys(self):
        chain = ChainGenerator().generate(length=2)
        d = chain.to_dict()
        for k in ("schema_version", "chain_id", "seed", "chain_type",
                  "length", "drift_profile", "steps"):
            assert k in d


class TestSchemaValidation:
    def _good(self):
        return ChainGenerator(seed=1).generate(length=3).to_dict()

    def test_well_formed_passes(self):
        validate_chain_schema(self._good())

    def test_missing_key_rejected(self):
        d = self._good()
        del d["chain_id"]
        with pytest.raises(ChainSchemaError, match="chain_id"):
            validate_chain_schema(d)

    def test_wrong_type_rejected(self):
        d = self._good()
        d["length"] = "fifteen"
        with pytest.raises(ChainSchemaError, match="length"):
            validate_chain_schema(d)

    def test_version_mismatch_rejected(self):
        d = self._good()
        d["schema_version"] = SCHEMA_VERSION + 1
        with pytest.raises(ChainSchemaError, match="schema_version"):
            validate_chain_schema(d)

    def test_length_mismatch_rejected(self):
        d = self._good()
        d["length"] = 999
        with pytest.raises(ChainSchemaError, match="length"):
            validate_chain_schema(d)

    def test_sigma_out_of_range_rejected(self):
        d = self._good()
        d["steps"][0]["sigma_true"] = 1.5
        with pytest.raises(ChainSchemaError, match="sigma_true"):
            validate_chain_schema(d)

    def test_invalid_drift_kind_rejected(self):
        d = self._good()
        d["drift_profile"]["kind"] = "exponential_decay"
        with pytest.raises(ChainSchemaError, match="drift_profile"):
            validate_chain_schema(d)

    def test_non_object_rejected(self):
        with pytest.raises(ChainSchemaError, match="JSON object"):
            validate_chain_schema("not a chain")
