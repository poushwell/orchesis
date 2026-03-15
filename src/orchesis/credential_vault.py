"""Credential vaults for proxy-time secret resolution."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import sys
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class CredentialNotFoundError(KeyError):
    """Raised when a credential alias cannot be resolved."""


class SecurityWarning(UserWarning):
    """Security posture warning for credential vault configuration."""


class CredentialVault:
    """Abstract credential vault interface."""

    def get(self, alias: str) -> str:
        raise NotImplementedError

    def list_aliases(self) -> list[str]:
        raise NotImplementedError

    def set(self, alias: str, value: str) -> None:
        raise NotImplementedError

    def remove(self, alias: str) -> bool:
        raise NotImplementedError


@dataclass
class EnvVault(CredentialVault):
    """Environment-backed vault with optional alias -> env variable mapping."""

    mapping_path: str | Path = ".orchesis/credentials_env.json"

    def __post_init__(self) -> None:
        self._mapping_path = Path(self.mapping_path)
        self._mapping_cache: dict[str, str] | None = None
        self._value_cache: dict[str, str] = {}

    def _load_mapping(self) -> dict[str, str]:
        if self._mapping_cache is not None:
            return self._mapping_cache
        if not self._mapping_path.exists():
            self._mapping_cache = {}
            return self._mapping_cache
        try:
            payload = json.loads(self._mapping_path.read_text(encoding="utf-8"))
        except Exception:
            payload = {}
        mapping: dict[str, str] = {}
        if isinstance(payload, dict):
            for alias, env_name in payload.items():
                if isinstance(alias, str) and alias.strip() and isinstance(env_name, str) and env_name.strip():
                    mapping[alias.strip()] = env_name.strip()
        self._mapping_cache = mapping
        return mapping

    def _save_mapping(self, mapping: dict[str, str]) -> None:
        self._mapping_path.parent.mkdir(parents=True, exist_ok=True)
        self._mapping_path.write_text(json.dumps(mapping, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        self._mapping_cache = dict(mapping)

    @staticmethod
    def _default_env_name(alias: str) -> str:
        return alias.strip().upper()

    def set_mapping(self, alias: str, env_name: str) -> None:
        mapping = self._load_mapping()
        mapping[alias] = env_name
        self._save_mapping(mapping)
        self._value_cache.pop(alias, None)

    def get(self, alias: str) -> str:
        if alias in self._value_cache:
            return self._value_cache[alias]
        mapping = self._load_mapping()
        env_name = mapping.get(alias, self._default_env_name(alias))
        value = os.getenv(env_name)
        if not isinstance(value, str) or value == "":
            raise CredentialNotFoundError(f"Credential alias '{alias}' is not available")
        self._value_cache[alias] = value
        return value

    def list_aliases(self) -> list[str]:
        aliases = set(self._load_mapping().keys())
        for key in os.environ:
            if key.strip():
                aliases.add(key.lower())
                aliases.add(key.upper())
        return sorted(item for item in aliases if isinstance(item, str) and item.strip())

    def set(self, alias: str, value: str) -> None:
        _ = value
        self.set_mapping(alias, self._default_env_name(alias))

    def remove(self, alias: str) -> bool:
        mapping = self._load_mapping()
        removed = alias in mapping
        mapping.pop(alias, None)
        self._save_mapping(mapping)
        self._value_cache.pop(alias, None)
        return removed


@dataclass
class FileVault(CredentialVault):
    """File vault with PBKDF2 + XOR stream encryption (basic v1 obfuscation)."""

    vault_path: str | Path = ".orchesis/credentials.enc"
    passphrase: str | None = None

    def __post_init__(self) -> None:
        self._path = Path(self.vault_path)
        self._passphrase = self._resolve_passphrase(self.passphrase)
        self._cache: dict[str, str] | None = None
        self._warn_if_permissions_too_open()

    def _warn_if_permissions_too_open(self) -> None:
        if os.name != "posix" or not self._path.exists():
            return
        mode = self._path.stat().st_mode & 0o777
        if mode & 0o077:
            logging.getLogger("orchesis.credentials").warning(
                "Credential vault permissions are too open; recommended chmod 600"
            )

    def _resolve_passphrase(self, explicit: str | None) -> str:
        if isinstance(explicit, str) and explicit.strip():
            return explicit
        env_value = os.getenv("ORCHESIS_VAULT_PASSPHRASE")
        if isinstance(env_value, str) and env_value.strip():
            return env_value
        legacy_env = os.getenv("ORCHESIS_CREDENTIALS_PASSPHRASE")
        if isinstance(legacy_env, str) and legacy_env.strip():
            return legacy_env
        return self._get_or_create_machine_key()

    def _get_or_create_machine_key(self) -> str:
        key_path = Path.home() / ".orchesis" / ".vault_key"
        key_path.parent.mkdir(parents=True, exist_ok=True)
        if key_path.exists():
            try:
                mode = key_path.stat().st_mode
                if mode & 0o077:
                    warnings.warn(
                        f"Vault key file {key_path} has insecure permissions. "
                        "Run: chmod 600 ~/.orchesis/.vault_key",
                        SecurityWarning,
                        stacklevel=3,
                    )
            except OSError:
                pass
            return key_path.read_text(encoding="utf-8").strip()
        key = secrets.token_hex(32)
        key_path.write_text(key, encoding="utf-8")
        if os.name == "posix":
            try:
                key_path.chmod(0o600)
            except OSError:
                pass
        print("[Orchesis] Vault key generated at ~/.orchesis/.vault_key", file=sys.stderr)
        print("[Orchesis] Set ORCHESIS_VAULT_PASSPHRASE env var for explicit control.", file=sys.stderr)
        print("[Orchesis] Keep this file secure - losing it means losing vault access.", file=sys.stderr)
        return key

    @staticmethod
    def _xor_bytes(data: bytes, key: bytes) -> bytes:
        return bytes(data[idx] ^ key[idx % len(key)] for idx in range(len(data)))

    def _derive_key(self, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac("sha256", self._passphrase.encode("utf-8"), salt, 120_000, dklen=32)

    def _load(self) -> dict[str, str]:
        if self._cache is not None:
            return self._cache
        if not self._path.exists():
            self._cache = {}
            return self._cache
        payload = json.loads(self._path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            self._cache = {}
            return self._cache
        salt_b64 = payload.get("salt")
        ciphertext_b64 = payload.get("ciphertext")
        if not isinstance(salt_b64, str) or not isinstance(ciphertext_b64, str):
            self._cache = {}
            return self._cache
        salt = base64.b64decode(salt_b64.encode("utf-8"))
        ciphertext = base64.b64decode(ciphertext_b64.encode("utf-8"))
        key = self._derive_key(salt)
        plaintext = self._xor_bytes(ciphertext, key)
        decoded = json.loads(plaintext.decode("utf-8"))
        if not isinstance(decoded, dict):
            self._cache = {}
            return self._cache
        creds = decoded.get("credentials")
        result: dict[str, str] = {}
        if isinstance(creds, dict):
            for alias, value in creds.items():
                if isinstance(alias, str) and alias.strip() and isinstance(value, str):
                    result[alias.strip()] = value
        self._cache = result
        return self._cache

    def _save(self, values: dict[str, str]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        salt = os.urandom(16)
        key = self._derive_key(salt)
        plaintext = json.dumps({"credentials": values}, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ciphertext = self._xor_bytes(plaintext, key)
        payload = {
            "version": 1,
            "algorithm": "pbkdf2-sha256+xor",
            "salt": base64.b64encode(salt).decode("utf-8"),
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        }
        self._path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        if os.name == "posix":
            os.chmod(self._path, 0o600)
        self._cache = dict(values)

    def get(self, alias: str) -> str:
        values = self._load()
        if alias not in values:
            raise CredentialNotFoundError(f"Credential alias '{alias}' is not available")
        return values[alias]

    def list_aliases(self) -> list[str]:
        return sorted(self._load().keys())

    def set(self, alias: str, value: str) -> None:
        values = self._load()
        values[alias] = value
        self._save(values)

    def remove(self, alias: str) -> bool:
        values = self._load()
        if alias not in values:
            return False
        values.pop(alias, None)
        self._save(values)
        return True


def build_vault_from_policy(policy: dict[str, Any], *, passphrase: str | None = None) -> CredentialVault:
    credentials_cfg = policy.get("credentials")
    cfg = credentials_cfg if isinstance(credentials_cfg, dict) else {}
    vault_mode = str(cfg.get("vault", "file")).strip().lower()
    if vault_mode == "env":
        mapping_path = cfg.get("mapping_path", ".orchesis/credentials_env.json")
        return EnvVault(mapping_path=mapping_path)
    path = cfg.get("vault_path", ".orchesis/credentials.enc")
    return FileVault(vault_path=path, passphrase=passphrase)
