from __future__ import annotations

import json
import tempfile
from pathlib import Path

from config import AttackReport, AttackResult, run_attack
from orchesis.credential_injector import CredentialInjector
from orchesis.credential_vault import FileVault


@run_attack
def attack_credential_in_logs() -> AttackReport:
    with tempfile.TemporaryDirectory() as tmp:
        vault_path = Path(tmp) / "vault.enc"
        vault = FileVault(vault_path=vault_path, passphrase="rt-pass")
        vault.set("api_token", "SECRET-VALUE-123")
        injector = CredentialInjector(
            {"inject": [{"alias": "api_token", "target": "header", "header_name": "Authorization", "match_tools": ["web_*"]}]},
            vault,
        )
        injected, _ = injector.inject({"tool_name": "web_search", "params": {"query": "x"}, "headers": {}})
        scrubbed = injector.scrub(injected)
        raw = json.dumps(scrubbed)
        leaked = "SECRET-VALUE-123" in raw
        result = AttackResult.PASS if not leaked else AttackResult.FAIL
        return AttackReport(
            name="credential_in_logs",
            category="credential_injection",
            description="Injected credential should not appear in scrubbed log payloads.",
            result=result,
            vectors_tested=1,
            vectors_blocked=1 if not leaked else 0,
            vectors_bypassed=1 if leaked else 0,
            severity="HIGH" if leaked else "LOW",
            fix_suggestion="Always log scrubbed tool-call payloads and never raw injected values.",
        )
