# Threat Model: Adversarial Testing

This document summarizes adversarial tests executed against Orchesis and the resulting hardening actions.

## Findings

### VULN-001: Path traversal and path canonicalization bypass
- **Severity:** High
- **Attack examples:** `/data/../etc/passwd`, `/data/%2e%2e/etc/passwd`, `//etc//passwd`
- **Risk:** Prefix-only path checks could be bypassed.
- **Fix:** Added URL decode + path normalization before `file_access` checks.
- **Status:** Fixed

### VULN-002: SQL restriction bypass via formatting tricks
- **Severity:** High
- **Attack examples:** mixed case, SQL comments, newline split, chained statements, unicode homoglyphs.
- **Risk:** First-token-only parsing missed dangerous operations.
- **Fix:** Added normalized/fuzzy SQL operation detection across query text.
- **Status:** Fixed

### VULN-003: Cost manipulation with invalid types/negative values
- **Severity:** Medium
- **Attack examples:** `"0.1"` (string), `-5.0`, `None`, huge numbers.
- **Risk:** Numeric validation gaps could bypass budget checks or allow malformed input.
- **Fix:** Added robust cost coercion and explicit negative-cost denial.
- **Status:** Fixed

### VULN-004: Context agent spoofing and null-byte injection
- **Severity:** Medium
- **Attack examples:** empty agent, `"*"`, embedded null bytes.
- **Risk:** Agent matching ambiguity and string smuggling.
- **Fix:** Added agent normalization and explicit deny reasons for unsafe agent values.
- **Status:** Fixed

### VULN-005: Rate-limit boundary bypass
- **Severity:** Medium
- **Attack examples:** calls at 99/100/101 boundary.
- **Risk:** Off-by-one mistakes around threshold.
- **Fix:** Boundary behavior validated and enforced with tests.
- **Status:** Fixed

### VULN-006: Rate-limit alias bypass across different tool names
- **Severity:** Low
- **Attack examples:** semantically similar operations using different tool names.
- **Risk:** Per-tool limiter can be bypassed by renaming tool.
- **Fix:** Not changed by design (limiter is intentionally per tool key).
- **Status:** Not fixed (documented limitation)

### VULN-007: Regex evasion tricks
- **Severity:** Medium
- **Attack examples:** extra whitespace, tabs, null-byte-inserted command.
- **Risk:** Pattern matching gaps for dangerous command forms.
- **Fix:** Added string normalization before regex evaluation.
- **Status:** Fixed

### VULN-008: YAML parser stress via deeply nested input
- **Severity:** Medium
- **Attack examples:** deep nested YAML/bomb-like shape.
- **Risk:** Parser exceptions propagating unexpectedly.
- **Fix:** Hardened YAML loading error handling (`YAMLError`, recursion/memory errors -> `ValueError`).
- **Status:** Fixed

### VULN-009: Very large policy file
- **Severity:** Low
- **Attack examples:** policy with 10k rules.
- **Risk:** Resource pressure / performance.
- **Fix:** Tested to ensure graceful load (no crash). No hard cutoff added.
- **Status:** Partially mitigated (tested), not constrained

### VULN-010: Circular composite rule references
- **Severity:** High
- **Attack examples:** `A -> B -> A`.
- **Risk:** Infinite recursion during evaluation.
- **Fix:** Added cycle detection in policy validation and runtime composite evaluation guard.
- **Status:** Fixed

### VULN-011: Catastrophic regex backtracking patterns
- **Severity:** Medium
- **Attack examples:** `(a+)+`.
- **Risk:** Potential ReDoS behavior.
- **Fix:** Added unsafe-regex heuristic rejection in validation and runtime checks.
- **Status:** Fixed (heuristic)

### VULN-012: Oversized request payloads
- **Severity:** Low
- **Attack examples:** 10MB string parameters.
- **Risk:** Performance degradation.
- **Fix:** Verified no crash; no hard size limit enforced in kernel.
- **Status:** Tested, not constrained

### VULN-013: Circular in-memory request objects
- **Severity:** Low
- **Attack examples:** Python dict self-reference.
- **Risk:** Unexpected recursion in evaluators.
- **Fix:** Verified evaluation path does not recurse across arbitrary object graph.
- **Status:** Fixed by design (no code change required)

### VULN-014: Null-byte injection across request string fields
- **Severity:** Medium
- **Attack examples:** null bytes in query/path/agent.
- **Risk:** Policy matching inconsistencies.
- **Fix:** Added string normalization for SQL/regex/context processing.
- **Status:** Fixed

## Explicit limitations

- Orchesis does not decode/inspect encoded payloads beyond direct string normalization; base64-obfuscated dangerous commands are not semantically decoded.
- Rate limiting is keyed by tool name; semantic alias grouping is not implemented.
- Policy size and regex complexity controls are heuristic-based, not formal resource isolation guarantees.
