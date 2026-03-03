# Orchesis Red Team Suite

We attack our own security tool to find weaknesses before attackers do.

## What This Is

`red-team/` is a standalone adversarial test project that runs 50+ security attacks directly against Orchesis policy evaluation, scanning, rate limiting, proxy-facing behaviors, and credential handling.

## Run

```bash
python run_all.py
```

Windows and Linux are both supported.

## Output

After execution:

- `red-team/results/report.md` (human-readable)
- `red-team/results/report.json` (machine-readable)

## PASS / FAIL / PARTIAL / ERROR

- `PASS`: Orchesis blocked or safely handled the attack.
- `FAIL`: Attack bypassed protection.
- `PARTIAL`: Some vectors blocked, some ambiguous or bypassed.
- `ERROR`: Test harness failed unexpectedly.

## Attack Categories

- Policy bypass
- Secret scanner evasion
- PII detector evasion
- Proxy stress
- Rate-limit bypass
- Credential injection safety

## Add New Attacks

1. Create a new `test_*.py` in the appropriate category.
2. Add one function decorated with `@run_attack`.
3. Return `AttackReport`.
4. Re-run `python run_all.py`.

## Philosophy

Every FAIL we find and fix makes Orchesis stronger.
