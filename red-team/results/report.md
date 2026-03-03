# Orchesis Red Team Report v1 - 2026-03-03 00:38:00Z

## Summary

20/46 attacks blocked, 18 bypasses found, 0 errors, 8 partial findings.

## Attack Matrix

| Attack | Category | Result | Severity | Description |
|--------|----------|--------|----------|-------------|
| credential_in_error | credential_injection | PASS | LOW | Credential errors should not leak raw secret values. |
| credential_in_logs | credential_injection | PASS | LOW | Injected credential should not appear in scrubbed log payloads. |
| credential_in_response | credential_injection | PASS | LOW | Credential value should not leak back in response/log material. |
| missing_credential_handling | credential_injection | PASS | LOW | Missing alias should deny/raise safely, not crash or silently pass. |
| vault_file_permissions | credential_injection | PARTIAL | LOW | Vault should warn/reject when permissions are too open. |
| bidi_override | pii_evasion | PASS | LOW | Bidi control chars around PII. |
| fullwidth_digits | pii_evasion | FAIL | HIGH | Fullwidth digit variants for SSN/credit card. |
| mixed_scripts | pii_evasion | PASS | LOW | PII with mixed Latin and Arabic-Indic digits. |
| partial_pii | pii_evasion | PARTIAL | LOW | Partial PII disclosure patterns. |
| reversed_format | pii_evasion | PARTIAL | MEDIUM | Reversed or reordered PII format. |
| separator_variants | pii_evasion | PARTIAL | MEDIUM | PII with non-standard separators. |
| spelled_out_numbers | pii_evasion | PARTIAL | MEDIUM | PII represented as words instead of digits. |
| zero_width_in_pii | pii_evasion | FAIL | HIGH | Zero-width chars inserted into SSN. |
| case_sensitivity | policy_bypass | PASS | LOW | Case variants should not bypass deny rules. |
| contradictory_rules | policy_bypass | FAIL | HIGH | Contradictory policy entries should resolve deterministically to safe behavior. |
| effect_type_confusion | policy_bypass | PASS | LOW | Non-string effect values should be rejected or safely ignored. |
| empty_tool_name | policy_bypass | PASS | LOW | Empty/missing tool names should never pass policy checks. |
| null_byte_injection | policy_bypass | FAIL | HIGH | Null-byte payloads should be rejected or safely blocked. |
| path_normalization | policy_bypass | FAIL | CRITICAL | Path canonicalization should prevent traversal and alias bypasses. |
| unicode_normalization | policy_bypass | FAIL | CRITICAL | Unicode tool-name variants should not bypass denylist. |
| whitespace_padding | policy_bypass | FAIL | MEDIUM | Whitespace-obfuscated tool/path inputs should not bypass controls. |
| wildcard_abuse | policy_bypass | PASS | LOW | Wildcard-like patterns should not accidentally allow dangerous tools. |
| yaml_type_coercion | policy_bypass | PASS | LOW | YAML auto-typing should not cause policy misinterpretation. |
| binary_payload | proxy_stress | PARTIAL | MEDIUM | Binary values in request fields should be safely rejected. |
| concurrent_calls | proxy_stress | FAIL | HIGH | Concurrent evaluate calls should remain stable and enforce limits. |
| deeply_nested_json | proxy_stress | PASS | LOW | Extremely nested params should not trigger stack overflows. |
| empty_request | proxy_stress | PASS | LOW | Empty requests should be denied and never crash evaluation. |
| malformed_json | proxy_stress | PASS | LOW | Malformed JSON inputs should not crash policy checks. |
| missing_fields | proxy_stress | PASS | LOW | Requests missing mandatory fields should be denied or safely handled. |
| oversized_payload | proxy_stress | PARTIAL | MEDIUM | Very large params payload should not crash evaluator. |
| rapid_fire_calls | proxy_stress | FAIL | HIGH | High-rate evaluate() loop should activate rate limiting and remain stable. |
| burst_then_wait | rate_limit_bypass | PASS | LOW | Burst then wait should enforce then reset sliding window. |
| concurrent_rate_limit | rate_limit_bypass | PASS | LOW | Concurrent calls should still trigger rate limits atomically. |
| per_tool_vs_global | rate_limit_bypass | FAIL | MEDIUM | Per-tool and global limits should compose without bypass. |
| sliding_window_edge | rate_limit_bypass | PASS | LOW | Boundary-window calls should not allow free bypasses. |
| tool_name_variants | rate_limit_bypass | FAIL | MEDIUM | Tool-name variants should not bypass per-tool counters. |
| base64_encoding | secret_evasion | FAIL | MEDIUM | Base64 encoded secret should be detected or flagged. |
| chunked_secret | secret_evasion | PASS | LOW | Secret split across separate chunks/fields. |
| hex_encoding | secret_evasion | FAIL | MEDIUM | Hex-escaped secret text. |
| homoglyph_substitution | secret_evasion | FAIL | HIGH | Homoglyph secret obfuscation. |
| newline_splitting | secret_evasion | FAIL | HIGH | Split secrets with newline characters. |
| paraphrased_secret | secret_evasion | PARTIAL | MEDIUM | Paraphrased/reconstructable secret disclosure. |
| rot13_encoding | secret_evasion | FAIL | LOW | ROT13-obfuscated secret values. |
| unicode_escapes | secret_evasion | FAIL | MEDIUM | Unicode-escaped secret text. |
| url_encoding | secret_evasion | PASS | LOW | Percent-encoded secret strings. |
| zero_width_chars | secret_evasion | FAIL | HIGH | Zero-width separators between secret characters. |

## Bypass Details

### fullwidth_digits

- **Category:** pii_evasion
- **Severity:** HIGH
- **Vectors tested:** 2
- **Vectors bypassed:** 1
- **Details:** n/a
- **Fix suggestion:** Normalize Unicode digits to ASCII before PII regex evaluation.

### zero_width_in_pii

- **Category:** pii_evasion
- **Severity:** HIGH
- **Vectors tested:** 1
- **Vectors bypassed:** 1
- **Details:** n/a
- **Fix suggestion:** Remove zero-width codepoints before applying PII regexes.

### contradictory_rules

- **Category:** policy_bypass
- **Severity:** HIGH
- **Vectors tested:** 3
- **Vectors bypassed:** 1
- **Details:** shell_execute allowed despite deny entry
- **Fix suggestion:** Enforce deny-precedence and reject contradictory rules during validation.

### null_byte_injection

- **Category:** policy_bypass
- **Severity:** HIGH
- **Vectors tested:** 4
- **Vectors bypassed:** 1
- **Details:** allowed `read_file` with params={'path': '/allowed/path\x00/etc/passwd'}
- **Fix suggestion:** Reject control characters (including NUL) in tool names and paths before policy matching.

### path_normalization

- **Category:** policy_bypass
- **Severity:** CRITICAL
- **Vectors tested:** 7
- **Vectors bypassed:** 1
- **Details:** allowed path `/ETC/PASSWD`
- **Fix suggestion:** Canonicalize and decode paths before denied-path checks (including backslashes/URL encoding).

### unicode_normalization

- **Category:** policy_bypass
- **Severity:** CRITICAL
- **Vectors tested:** 5
- **Vectors bypassed:** 4
- **Details:** allowed variant `ｓｈｅｌｌ＿ｅｘｅｃｕｔｅ`; allowed variant `shell_exécute`; allowed variant `ѕhеll_ехесutе`; allowed variant `shеll_execuтe`
- **Fix suggestion:** Apply Unicode NFKC normalization before tool-name comparisons in engine tool access checks.

### whitespace_padding

- **Category:** policy_bypass
- **Severity:** MEDIUM
- **Vectors tested:** 4
- **Vectors bypassed:** 3
- **Details:** allowed `  shell_execute  `; allowed `shell	execute`; allowed `shell
execute`
- **Fix suggestion:** Normalize whitespace in tool names and paths before matching.

### concurrent_calls

- **Category:** proxy_stress
- **Severity:** HIGH
- **Vectors tested:** 200
- **Vectors bypassed:** 1
- **Details:** allowed=200, denied=0
- **Fix suggestion:** Ensure atomic counter updates in concurrent rate-limit checks.

### rapid_fire_calls

- **Category:** proxy_stress
- **Severity:** HIGH
- **Vectors tested:** 1000
- **Vectors bypassed:** 1000
- **Details:** allowed=1000, denied=0
- **Fix suggestion:** Ensure rate limiter always applies under high call volume.

### per_tool_vs_global

- **Category:** rate_limit_bypass
- **Severity:** MEDIUM
- **Vectors tested:** 4
- **Vectors bypassed:** 1
- **Details:** denied=0
- **Fix suggestion:** Ensure per-tool and global counters are both applied consistently.

### tool_name_variants

- **Category:** rate_limit_bypass
- **Severity:** MEDIUM
- **Vectors tested:** 3
- **Vectors bypassed:** 1
- **Details:** denied=0 across variants
- **Fix suggestion:** Normalize tool names before rate-limit keying.

### base64_encoding

- **Category:** secret_evasion
- **Severity:** MEDIUM
- **Vectors tested:** 1
- **Vectors bypassed:** 1
- **Details:** n/a
- **Fix suggestion:** Add optional decoding heuristics for base64-like segments before scanning.

### hex_encoding

- **Category:** secret_evasion
- **Severity:** MEDIUM
- **Vectors tested:** 1
- **Vectors bypassed:** 1
- **Details:** n/a
- **Fix suggestion:** Decode hex escape sequences before evaluating secret patterns.

### homoglyph_substitution

- **Category:** secret_evasion
- **Severity:** HIGH
- **Vectors tested:** 1
- **Vectors bypassed:** 1
- **Details:** n/a
- **Fix suggestion:** Normalize confusable Unicode characters before secret scanning.

### newline_splitting

- **Category:** secret_evasion
- **Severity:** HIGH
- **Vectors tested:** 3
- **Vectors bypassed:** 3
- **Details:** n/a
- **Fix suggestion:** Normalize/remove newline separators before secret pattern evaluation.

### rot13_encoding

- **Category:** secret_evasion
- **Severity:** LOW
- **Vectors tested:** 1
- **Vectors bypassed:** 1
- **Details:** n/a
- **Fix suggestion:** Optional: add decoder heuristics for known weak obfuscation schemes like ROT13.

### unicode_escapes

- **Category:** secret_evasion
- **Severity:** MEDIUM
- **Vectors tested:** 1
- **Vectors bypassed:** 1
- **Details:** n/a
- **Fix suggestion:** Decode unicode escapes in suspicious text before scanning.

### zero_width_chars

- **Category:** secret_evasion
- **Severity:** HIGH
- **Vectors tested:** 1
- **Vectors bypassed:** 1
- **Details:** n/a
- **Fix suggestion:** Strip zero-width characters before pattern matching.
