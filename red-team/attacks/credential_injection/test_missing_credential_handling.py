from __future__ import annotations

import tempfile
from pathlib import Path

from config import AttackReport, AttackResult, run_attack
from orchesis.credential_injector import CredentialInjector
from orchesis.credential_vault import CredentialNotFoundError, FileVault


@run_attack
def attack_missing_credential_handling() -> AttackReport:
    with tempfile.TemporaryDirectory() as tmp:
        vault = FileVault(vault_path=Path(tmp) / "vault.enc", passphrase="rt-pass")
        injector = CredentialInjector(
            {"inject": [{"alias": "does_not_exist", "target": "header", "header_name": "Authorization", "match_tools": ["*"]}]},
            vault,
        )
        try:
            injector.inject({"tool_name": "read_file", "params": {"path": "/tmp/x"}})
            result = AttackResult.FAIL
            details = "Missing credential alias did not raise error."
        except CredentialNotFoundError as error:
            result = AttackResult.PASS
            details = str(error)
        return AttackReport(
            name="missing_credential_handling",
            category="credential_injection",
            description="Missing alias should deny/raise safely, not crash or silently pass.",
            result=result,
            details=details,
            vectors_tested=1,
            vectors_blocked=1 if result == AttackResult.PASS else 0,
            vectors_bypassed=1 if result == AttackResult.FAIL else 0,
            severity="HIGH" if result == AttackResult.FAIL else "LOW",
            fix_suggestion="Keep fail-closed behavior for unresolved credential aliases.",
        )
