"""Fuzz the Orchesis policy engine with mutated YAML inputs."""

from __future__ import annotations

import os
import sys
import tempfile

try:
    import atheris
except ImportError:
    print("Atheris not installed. Install with: pip install atheris")
    print("Recommended: use Linux or WSL2")
    sys.exit(1)

with atheris.instrument_imports():
    import yaml
    from orchesis.config import PolicyError, load_policy, validate_policy
    from orchesis.engine import PolicyEngine


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    yaml_str = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 10_000))
    if not yaml_str:
        return

    try:
        parsed = yaml.safe_load(yaml_str)
    except (yaml.YAMLError, RecursionError, MemoryError):
        return

    if not isinstance(parsed, dict):
        return

    policy_path = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as tmp:
            tmp.write(yaml_str)
            policy_path = tmp.name
        policy = load_policy(policy_path)
    except (PolicyError, ValueError, TypeError, KeyError):
        return
    finally:
        if isinstance(policy_path, str):
            try:
                os.unlink(policy_path)
            except OSError:
                pass

    if not isinstance(policy, dict):
        return

    # Rejecting invalid policy is expected.
    _ = validate_policy(policy)

    try:
        engine = PolicyEngine(policy)
        request = {
            "tool": fdp.ConsumeUnicodeNoSurrogates(120),
            "params": {},
            "cost": 0.0,
            "context": {"agent": "fuzz-agent", "session": "fuzz-session"},
        }
        _ = engine.evaluate(request, session_type="cli")
    except (PolicyError, ValueError, TypeError, KeyError):
        return


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
