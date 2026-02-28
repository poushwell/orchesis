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

## Reporting vulnerabilities

Please open a private security report through your organization channel or repository security contact.  
Include reproduction steps, policy snippet, request payload, and observed vs expected decision.
