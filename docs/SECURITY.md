# Security

See the formal threat model in `docs/THREAT_MODEL.md`.

## Security approach

Orchesis applies policy checks at runtime before tool execution and defaults to fail-closed behavior on state or rule errors.  
All decisions are auditable and can be replayed deterministically.

## Adversarial testing methodology

- Synthetic fuzzing over multiple attack categories
- Scenario-based attack sequences
- Mutation engine for continuous corpus evolution
- Formal invariants for runtime correctness properties

## Fuzzer and mutation engine

- Fuzzer stresses policy with synthetic malicious requests
- Mutation engine mutates known bypass inputs to discover variants
- Nightly pipeline can raise incident issues automatically

## Invariant checker

Runtime invariants cover:

- never-fail-open behavior
- deterministic replay
- state and session isolation
- fail-closed on state errors
- identity and rate-limit guarantees

## Regression corpus

- Corpus stores known bypass patterns as regression fixtures
- Auto-generated regression tests ensure fixed issues stay fixed
- Corpus stats are included in reliability reporting

## Reporting Vulnerabilities

If you find a security vulnerability in Orchesis:

1. **DO NOT** open a public GitHub issue
2. Email: security@orchesis.dev (or create a private advisory)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Expected vs actual behavior
   - Orchesis version
4. We will respond within 48 hours
5. Fix will be released with credit (unless you prefer anonymity)

## Security Testing

We encourage security research on Orchesis:
```bash
# Run the fuzzer
orchesis fuzz --policy your_policy.yaml --count 10000 --save-bypasses

# Run mutation engine
orchesis mutate --policy your_policy.yaml --count 5000

# Check invariants
orchesis invariants --policy your_policy.yaml

# Run adversarial scenarios
orchesis scenarios --policy your_policy.yaml
```

Any bypass found through these tools is a valid report.
