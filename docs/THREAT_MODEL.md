# Orchesis Threat Model v2

## Scope

This model defines what Orchesis enforces at the tool-call boundary and where explicit limits remain.

## Trust Boundaries

- Agent -> Orchesis -> Tool (enforcement point)
- Orchesis trusts: policy file, policy author
- Orchesis does NOT trust: agent requests, agent identity claims

## Attack Categories

### Covered (with corpus references)

| Category | Corpus Entries | Status |
|----------|----------------|--------|
| Path Traversal | BYPASS-001..003 | Fixed |
| SQL Injection | BYPASS-004..008 | Fixed |
| Cost Manipulation | BYPASS-009 | Fixed |
| Identity Spoofing | BYPASS-010..012 | Fixed |
| Regex Evasion | BYPASS-013..014 | Fixed |
| Rate Limit Gaming | Tested via scenarios | Mitigated |
| Budget Drain | Tested via scenarios | Mitigated |

### Known Limitations (explicit)

| Limitation | Description | Mitigation |
|-----------|-------------|------------|
| Semantic tool poisoning | Cannot detect malicious semantics in MCP/tool output | Out of scope (output validation layer) |
| Schema manipulation | Cannot verify MCP server schema integrity at runtime | External schema signing/validation |
| Prompt injection via tools | Tool outputs can contain prompt injection content | Downstream LLM safety controls |
| Identity rotation | Agent can rotate `agent_id` across requests | Future: network-level attribution/IP quotas |
| Session hopping | Agent can rotate `session` values | Partial: session-level limits + anomaly monitoring |
| Base64 encoded payloads | No generic decode of arbitrary encoded params | Pattern/decoder extensions (future) |
| ML-based evasion | Static regex rules can be evaded by adversarial transforms | Future ML-assisted detection layer |

## Formal Guarantees

| Guarantee | Status |
|-----------|--------|
| Deterministic evaluation | Verified via replay engine |
| Fail-closed | All rule/runtime errors resolve to DENY |
| No fail-open paths | Verified via adversarial tests |
| Per-agent state isolation | Verified under 500 concurrent |
| Atomic rate-limit updates | `check_and_record()` |
| Cryptographic audit trail | Ed25519 signed decisions |

## Security Testing

- 208+ automated tests
- 30 adversarial attack tests
- 7 adversarial scenarios
- Synthetic fuzzer with 1000+ generated attacks
- 14-entry regression corpus (growing)
- Deterministic replay verification
