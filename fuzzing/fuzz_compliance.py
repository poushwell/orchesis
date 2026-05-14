"""Fuzz compliance engine with type-confused policies."""

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
    from orchesis.compliance import ComplianceEngine, FRAMEWORK_CHECKS


def _mutated_policy(fdp: atheris.FuzzedDataProvider) -> dict[str, object]:
    return {
        "version": fdp.PickValueInList(["1.0", 1, True, None]),
        "policy_version": fdp.PickValueInList(["v1", 123, None, ["x"]]),
        "tool_access": fdp.PickValueInList(
            [
                {"mode": "allowlist", "allowed": ["read_file"]},
                ["not-a-dict"],
                None,
                {"mode": 123, "allowed": "all"},
            ]
        ),
        "rules": fdp.PickValueInList(
            [
                [],
                [{"name": "rate_limit", "max_requests_per_minute": 60}],
                {"name": "invalid"},
                [None, 1, "x"],
            ]
        ),
        "alerts": fdp.PickValueInList([{"recipients": ["secops@example.com"]}, None, "oops", 7]),
    }


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    policy = _mutated_policy(fdp)
    raw = yaml.safe_dump(policy, allow_unicode=True, sort_keys=False)

    path = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as tmp:
            tmp.write(raw)
            path = tmp.name
        engine = ComplianceEngine(policy_path=path)
        framework = fdp.PickValueInList(list(FRAMEWORK_CHECKS.keys()))
        _ = engine.check(framework)
        if fdp.ConsumeBool():
            _ = engine.check_all()
    except (ValueError, TypeError, KeyError, AttributeError, yaml.YAMLError):
        return
    finally:
        if isinstance(path, str):
            try:
                os.unlink(path)
            except OSError:
                pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
