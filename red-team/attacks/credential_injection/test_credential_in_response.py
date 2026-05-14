from __future__ import annotations

import tempfile
from pathlib import Path

from config import AttackReport, AttackResult, run_attack
from orchesis.credential_injector import CredentialInjector
from orchesis.credential_vault import FileVault


@run_attack
def attack_credential_in_response() -> AttackReport:
    with tempfile.TemporaryDirectory() as tmp:
        vault = FileVault(vault_path=Path(tmp) / "vault.enc", passphrase="rt-pass")
        vault.set("api_key", "TOP-SECRET-XYZ")
        injector = CredentialInjector(
            {"inject": [{"alias": "api_key", "target": "param", "param_name": "api_key", "match_tools": ["send_*"]}]},
            vault,
        )
        injected, _ = injector.inject({"tool_name": "send_email", "params": {"to": "a@b"}, "headers": {}})
        # Simulated response should use scrubbed payload, not raw injected object.
        scrubbed = injector.scrub(injected)
        leaked = "TOP-SECRET-XYZ" in str(scrubbed)
        result = AttackResult.PASS if not leaked else AttackResult.FAIL
        return AttackReport(
            name="credential_in_response",
            category="credential_injection",
            description="Credential value should not leak back in response/log material.",
            result=result,
            vectors_tested=1,
            vectors_blocked=1 if not leaked else 0,
            vectors_bypassed=1 if leaked else 0,
            severity="HIGH" if leaked else "LOW",
            fix_suggestion="Apply response/log redaction for injected credential fields before returning data.",
        )
