"""Agent authentication helpers (HMAC token binding)."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass
class AgentCredential:
    agent_id: str
    secret_key: str
    created_at: float
    last_used: float = 0.0
    enabled: bool = True


class AgentAuthenticator:
    """HMAC-based agent authentication."""

    def __init__(
        self,
        credentials: dict[str, AgentCredential] | None = None,
        mode: str = "enforce",
        max_clock_skew: int = 300,
    ):
        self._credentials = credentials or {}
        self._mode = mode
        self._max_clock_skew = max(1, int(max_clock_skew))
        self._used_signatures: dict[str, float] = {}

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def credentials(self) -> dict[str, AgentCredential]:
        return self._credentials

    @staticmethod
    def generate_secret() -> str:
        return secrets.token_hex(32)

    def register(self, agent_id: str) -> AgentCredential:
        safe_agent = agent_id.strip()
        cred = AgentCredential(
            agent_id=safe_agent,
            secret_key=self.generate_secret(),
            created_at=time.time(),
        )
        self._credentials[safe_agent] = cred
        return cred

    def revoke(self, agent_id: str) -> bool:
        if agent_id in self._credentials:
            self._credentials[agent_id].enabled = False
            return True
        return False

    def rotate(self, agent_id: str) -> AgentCredential | None:
        if agent_id not in self._credentials:
            return None
        cred = self._credentials[agent_id]
        cred.secret_key = self.generate_secret()
        return cred

    def list_agents(self) -> list[dict[str, Any]]:
        return [
            {
                "agent_id": cred.agent_id,
                "enabled": cred.enabled,
                "created_at": cred.created_at,
                "last_used": cred.last_used,
            }
            for cred in self._credentials.values()
        ]

    def compute_signature(
        self,
        secret_key: str,
        agent_id: str,
        timestamp: str,
        tool: str,
        params_hash: str,
    ) -> str:
        message = f"{agent_id}:{timestamp}:{tool}:{params_hash}"
        return hmac.new(
            bytes.fromhex(secret_key),
            message.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def verify(
        self,
        agent_id: str,
        timestamp: str,
        tool: str,
        params_hash: str,
        signature: str,
    ) -> tuple[bool, str]:
        cred = self._credentials.get(agent_id)
        if cred is None:
            return False, f"unknown agent '{agent_id}'"
        if not cred.enabled:
            return False, f"agent '{agent_id}' is revoked"

        try:
            ts = int(timestamp)
        except (TypeError, ValueError):
            return False, "invalid timestamp"

        now = int(time.time())
        skew = abs(now - ts)
        if skew > self._max_clock_skew:
            return False, f"timestamp too old/new (skew: {skew}s > {self._max_clock_skew}s)"

        if signature in self._used_signatures:
            return False, "replay detected: signature already used"

        expected = self.compute_signature(cred.secret_key, agent_id, timestamp, tool, params_hash)
        if not hmac.compare_digest(signature, expected):
            return False, "invalid signature"

        now_f = time.time()
        cred.last_used = now_f
        self._used_signatures[signature] = now_f
        self._cleanup_old_signatures()
        return True, ""

    def authenticate_request(
        self,
        request: dict[str, Any],
        headers: dict[str, Any],
    ) -> tuple[bool, str, str]:
        agent_id = headers.get("X-Orchesis-Agent") or headers.get("x-orchesis-agent")
        timestamp = headers.get("X-Orchesis-Timestamp") or headers.get("x-orchesis-timestamp")
        signature = headers.get("X-Orchesis-Signature") or headers.get("x-orchesis-signature")

        if not agent_id and not signature:
            if self._mode == "enforce":
                return False, "", "authentication required (no credentials provided)"
            return True, "", ""

        if not all([agent_id, timestamp, signature]):
            return False, str(agent_id or ""), "incomplete authentication headers"

        tool = request.get("tool", "")
        params = request.get("params", {})
        params_hash = hashlib.sha256(
            json.dumps(params, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        valid, reason = self.verify(str(agent_id), str(timestamp), str(tool), params_hash, str(signature))
        return valid, str(agent_id), reason

    def _cleanup_old_signatures(self) -> None:
        cutoff = time.time() - (self._max_clock_skew * 2)
        expired = [sig for sig, ts in self._used_signatures.items() if ts < cutoff]
        for sig in expired:
            del self._used_signatures[sig]


class CredentialStore:
    """Persist agent credentials in YAML."""

    def __init__(self, path: str = ".orchesis/credentials.yaml"):
        self._path = Path(path)

    def exists(self) -> bool:
        return self._path.exists()

    def load(self) -> dict[str, AgentCredential]:
        if not self._path.exists():
            return {}
        loaded = yaml.safe_load(self._path.read_text(encoding="utf-8"))
        if not isinstance(loaded, dict):
            return {}
        agents = loaded.get("agents")
        if not isinstance(agents, dict):
            return {}
        creds: dict[str, AgentCredential] = {}
        for agent_id, payload in agents.items():
            if not isinstance(agent_id, str) or not isinstance(payload, dict):
                continue
            key = payload.get("secret_key")
            created = payload.get("created_at")
            last_used = payload.get("last_used", 0.0)
            enabled = payload.get("enabled", True)
            if not isinstance(key, str) or not key:
                continue
            if not isinstance(created, int | float):
                continue
            creds[agent_id] = AgentCredential(
                agent_id=agent_id,
                secret_key=key,
                created_at=float(created),
                last_used=float(last_used) if isinstance(last_used, int | float) else 0.0,
                enabled=bool(enabled),
            )
        return creds

    def save(self, credentials: dict[str, AgentCredential]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "agents": {
                agent_id: {
                    "secret_key": cred.secret_key,
                    "created_at": cred.created_at,
                    "last_used": cred.last_used,
                    "enabled": cred.enabled,
                }
                for agent_id, cred in credentials.items()
            }
        }
        self._path.write_text(yaml.safe_dump(payload, sort_keys=True), encoding="utf-8")
        try:
            if os.name != "nt":
                os.chmod(self._path, 0o600)
        except OSError:
            pass
