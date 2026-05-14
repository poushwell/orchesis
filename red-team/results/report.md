# Orchesis Red Team Report v1 - 2026-03-03 08:07:03Z

## Summary

38/46 attacks blocked, 0 bypasses found, 0 errors, 8 partial findings.

## Attack Matrix

| Attack | Category | Result | Severity | Description |
|--------|----------|--------|----------|-------------|
| credential_in_error | credential_injection | PASS | LOW | Credential errors should not leak raw secret values. |
| credential_in_logs | credential_injection | PASS | LOW | Injected credential should not appear in scrubbed log payloads. |
| credential_in_response | credential_injection | PASS | LOW | Credential value should not leak back in response/log material. |
| missing_credential_handling | credential_injection | PASS | LOW | Missing alias should deny/raise safely, not crash or silently pass. |
| vault_file_permissions | credential_injection | PARTIAL | LOW | Vault should warn/reject when permissions are too open. |
| bidi_override | pii_evasion | PASS | LOW | Bidi control chars around PII. |
| fullwidth_digits | pii_evasion | PASS | LOW | Fullwidth digit variants for SSN/credit card. |
| mixed_scripts | pii_evasion | PASS | LOW | PII with mixed Latin and Arabic-Indic digits. |
| partial_pii | pii_evasion | PARTIAL | LOW | Partial PII disclosure patterns. |
| reversed_format | pii_evasion | PARTIAL | MEDIUM | Reversed or reordered PII format. |
| separator_variants | pii_evasion | PARTIAL | MEDIUM | PII with non-standard separators. |
| spelled_out_numbers | pii_evasion | PARTIAL | MEDIUM | PII represented as words instead of digits. |
| zero_width_in_pii | pii_evasion | PASS | LOW | Zero-width chars inserted into SSN. |
| case_sensitivity | policy_bypass | PASS | LOW | Case variants should not bypass deny rules. |
| contradictory_rules | policy_bypass | PASS | LOW | Contradictory policy entries should resolve deterministically to safe behavior. |
| effect_type_confusion | policy_bypass | PASS | LOW | Non-string effect values should be rejected or safely ignored. |
| empty_tool_name | policy_bypass | PASS | LOW | Empty/missing tool names should never pass policy checks. |
| null_byte_injection | policy_bypass | PASS | LOW | Null-byte payloads should be rejected or safely blocked. |
| path_normalization | policy_bypass | PASS | LOW | Path canonicalization should prevent traversal and alias bypasses. |
| unicode_normalization | policy_bypass | PASS | LOW | Unicode tool-name variants should not bypass denylist. |
| whitespace_padding | policy_bypass | PASS | LOW | Whitespace-obfuscated tool/path inputs should not bypass controls. |
| wildcard_abuse | policy_bypass | PASS | LOW | Wildcard-like patterns should not accidentally allow dangerous tools. |
| yaml_type_coercion | policy_bypass | PASS | LOW | YAML auto-typing should not cause policy misinterpretation. |
| binary_payload | proxy_stress | PARTIAL | MEDIUM | Binary values in request fields should be safely rejected. |
| concurrent_calls | proxy_stress | PASS | LOW | Concurrent evaluate calls should remain stable and enforce limits. |
| deeply_nested_json | proxy_stress | PASS | LOW | Extremely nested params should not trigger stack overflows. |
| empty_request | proxy_stress | PASS | LOW | Empty requests should be denied and never crash evaluation. |
| malformed_json | proxy_stress | PASS | LOW | Malformed JSON inputs should not crash policy checks. |
| missing_fields | proxy_stress | PASS | LOW | Requests missing mandatory fields should be denied or safely handled. |
| oversized_payload | proxy_stress | PARTIAL | MEDIUM | Very large params payload should not crash evaluator. |
| rapid_fire_calls | proxy_stress | PASS | LOW | High-rate evaluate() loop should activate rate limiting and remain stable. |
| burst_then_wait | rate_limit_bypass | PASS | LOW | Burst then wait should enforce then reset sliding window. |
| concurrent_rate_limit | rate_limit_bypass | PASS | LOW | Concurrent calls should still trigger rate limits atomically. |
| per_tool_vs_global | rate_limit_bypass | PASS | LOW | Per-tool and global limits should compose without bypass. |
| sliding_window_edge | rate_limit_bypass | PASS | LOW | Boundary-window calls should not allow free bypasses. |
| tool_name_variants | rate_limit_bypass | PASS | LOW | Tool-name variants should not bypass per-tool counters. |
| base64_encoding | secret_evasion | PASS | LOW | Base64 encoded secret should be detected or flagged. |
| chunked_secret | secret_evasion | PASS | LOW | Secret split across separate chunks/fields. |
| hex_encoding | secret_evasion | PASS | LOW | Hex-escaped secret text. |
| homoglyph_substitution | secret_evasion | PASS | LOW | Homoglyph secret obfuscation. |
| newline_splitting | secret_evasion | PASS | LOW | Split secrets with newline characters. |
| paraphrased_secret | secret_evasion | PARTIAL | MEDIUM | Paraphrased/reconstructable secret disclosure. |
| rot13_encoding | secret_evasion | PASS | LOW | ROT13-obfuscated secret values. |
| unicode_escapes | secret_evasion | PASS | LOW | Unicode-escaped secret text. |
| url_encoding | secret_evasion | PASS | LOW | Percent-encoded secret strings. |
| zero_width_chars | secret_evasion | PASS | LOW | Zero-width separators between secret characters. |
