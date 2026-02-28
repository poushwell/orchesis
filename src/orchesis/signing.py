"""Ed25519 signing helpers for decision log entries."""

from __future__ import annotations

import base64
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def _canonical_payload(entry: dict[str, object]) -> bytes:
    payload = {
        "timestamp": entry.get("timestamp"),
        "tool": entry.get("tool"),
        "decision": entry.get("decision"),
        "reasons": entry.get("reasons"),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return canonical.encode("utf-8")


def generate_keypair(keys_dir: str | Path) -> tuple[Path, Path]:
    """Generate Ed25519 private/public key pair and store as PEM files."""
    target_dir = Path(keys_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_path = target_dir / "private.pem"
    public_path = target_dir / "public.pem"

    private_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return private_path, public_path


def sign_entry(entry: dict[str, object], private_key_path: str | Path) -> str:
    """Create base64 Ed25519 signature for canonical decision fields."""
    private_key_bytes = Path(private_key_path).read_bytes()
    private_key = serialization.load_pem_private_key(private_key_bytes, password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("Private key is not an Ed25519 key")
    signature = private_key.sign(_canonical_payload(entry))
    return base64.b64encode(signature).decode("ascii")


def verify_entry(
    entry: dict[str, object], signature_b64: str, public_key_path: str | Path
) -> bool:
    """Verify base64 Ed25519 signature against canonical decision fields."""
    public_key_bytes = Path(public_key_path).read_bytes()
    public_key = serialization.load_pem_public_key(public_key_bytes)
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("Public key is not an Ed25519 key")

    try:
        signature = base64.b64decode(signature_b64.encode("ascii"), validate=True)
        public_key.verify(signature, _canonical_payload(entry))
        return True
    except (InvalidSignature, ValueError):
        return False
