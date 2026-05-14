from __future__ import annotations

import tempfile
from pathlib import Path

from config import AttackReport, AttackResult, run_attack
from orchesis.credential_injector import CredentialInjector
from orchesis.credential_vault import CredentialNotFoundError, FileVault


@run_attack
def attack_credential_in_error() -> AttackReport:
    with tempfile.TemporaryDirectory() as tmp:
        vault = FileVault(vault_path=Path(tmp) / "vault.enc", passphrase="rt-pass")
        injector = CredentialInjector(
            {"inject": [{"alias": "missing_alias", "target": "param", "param_name": "token", "match_tools": ["web_*"]}]},
            vault,
        )
        try:
            injector.inject({"tool_name": "web_search", "params": {"query": "x"}})
            leaked = True
            message = "missing alias unexpectedly succeeded"
        except CredentialNotFoundError as error:
            message = str(error)
            leaked = "SECRET" in message or "token=" in message
        result = AttackResult.PASS if not leaked else AttackResult.FAIL
        return AttackReport(
            name="credential_in_error",
            category="credential_injection",
            description="Credential errors should not leak raw secret values.",
            result=result,
            details=message,
            vectors_tested=1,
            vectors_blocked=1 if not leaked else 0,
            vectors_bypassed=1 if leaked else 0,
            severity="MEDIUM" if leaked else "LOW",
            fix_suggestion="Keep credential error messages alias-only and never include resolved values.",
        )
