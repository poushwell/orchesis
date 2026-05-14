from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path

from config import AttackReport, AttackResult, run_attack
from orchesis.credential_vault import FileVault


@run_attack
def attack_vault_file_permissions() -> AttackReport:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "vault.enc"
        vault = FileVault(vault_path=path, passphrase="rt-pass")
        vault.set("alias", "value")
        logger = logging.getLogger("orchesis.credentials")
        records: list[str] = []

        class _Handler(logging.Handler):
            def emit(self, record):
                records.append(record.getMessage())

        handler = _Handler()
        logger.addHandler(handler)
        try:
            if os.name == "posix":
                os.chmod(path, 0o644)
            _ = FileVault(vault_path=path, passphrase="rt-pass")
        finally:
            logger.removeHandler(handler)
        warned = any("too open" in msg.lower() for msg in records)
        if os.name == "posix":
            result = AttackResult.PASS if warned else AttackResult.FAIL
        else:
            result = AttackResult.PARTIAL
        return AttackReport(
            name="vault_file_permissions",
            category="credential_injection",
            description="Vault should warn/reject when permissions are too open.",
            result=result,
            details="warning_emitted=" + str(warned),
            vectors_tested=1,
            vectors_blocked=1 if warned else 0,
            vectors_bypassed=0 if warned else 1,
            severity="MEDIUM" if result == AttackResult.FAIL else "LOW",
            fix_suggestion="Enforce strict file permission checks for credential vault on supported OSes.",
        )
