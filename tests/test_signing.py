from pathlib import Path

from orchesis.signing import generate_keypair, sign_entry, verify_entry


def test_generate_keypair_creates_private_and_public_pem(tmp_path: Path) -> None:
    private_path, public_path = generate_keypair(tmp_path / ".orchesis" / "keys")

    assert private_path.exists()
    assert public_path.exists()
    assert "BEGIN PRIVATE KEY" in private_path.read_text(encoding="utf-8")
    assert "BEGIN PUBLIC KEY" in public_path.read_text(encoding="utf-8")


def test_sign_and_verify_entry_success(tmp_path: Path) -> None:
    private_path, public_path = generate_keypair(tmp_path / ".orchesis" / "keys")
    entry = {
        "timestamp": "2026-03-01T14:30:00+00:00",
        "tool": "sql_query",
        "decision": "DENY",
        "reasons": ["sql_restriction: DROP is denied"],
    }

    signature = sign_entry(entry, private_path)
    verified = verify_entry(entry, signature, public_path)

    assert isinstance(signature, str)
    assert verified is True


def test_verify_entry_fails_for_tampered_data(tmp_path: Path) -> None:
    private_path, public_path = generate_keypair(tmp_path / ".orchesis" / "keys")
    entry = {
        "timestamp": "2026-03-01T14:30:00+00:00",
        "tool": "sql_query",
        "decision": "DENY",
        "reasons": ["sql_restriction: DROP is denied"],
    }

    signature = sign_entry(entry, private_path)
    tampered = dict(entry)
    tampered["decision"] = "ALLOW"

    assert verify_entry(tampered, signature, public_path) is False
