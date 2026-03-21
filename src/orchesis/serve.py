"""Production server bootstrap helpers with optional TLS."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import importlib
import os
from pathlib import Path
import subprocess
import sys
from typing import Optional

from orchesis import __version__

try:
    import uvicorn
except ModuleNotFoundError:  # pragma: no cover
    uvicorn = None  # type: ignore[assignment]


@dataclass
class ServeConfig:
    host: str = "0.0.0.0"
    port: int = 8100
    tls_cert: Optional[str] = None
    tls_key: Optional[str] = None
    tls_self_signed: bool = False
    workers: int = 1
    log_level: str = "info"
    policy: Optional[str] = None
    skip_verify: bool = False


def generate_self_signed_cert(output_dir: str | os.PathLike[str] | None = None) -> tuple[str, str]:
    """Generate self-signed TLS cert and key and return their paths."""
    target_dir = Path(output_dir).expanduser() if output_dir is not None else (Path.home() / ".orchesis" / "tls")
    target_dir.mkdir(parents=True, exist_ok=True)
    cert_path = target_dir / "cert.pem"
    key_path = target_dir / "key.pem"

    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=30))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        return str(cert_path), str(key_path)
    except ModuleNotFoundError:
        pass
    except Exception:
        pass

    openssl_cmd = [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-keyout",
        str(key_path),
        "-out",
        str(cert_path),
        "-days",
        "30",
        "-nodes",
        "-subj",
        "/CN=localhost",
        "-addext",
        "subjectAltName=DNS:localhost,IP:127.0.0.1",
    ]
    try:
        completed = subprocess.run(openssl_cmd, capture_output=True, text=True, check=False)
        if completed.returncode == 0 and cert_path.exists() and key_path.exists():
            return str(cert_path), str(key_path)
    except Exception:
        pass

    raise RuntimeError(
        "Unable to generate self-signed cert. Install 'cryptography' or OpenSSL and retry."
    )


def validate_config(config: ServeConfig) -> list[str]:
    errors: list[str] = []
    if config.port < 1 or config.port > 65535:
        errors.append("port must be in range 1..65535")
    cert_set = bool(config.tls_cert)
    key_set = bool(config.tls_key)
    if cert_set and not key_set:
        errors.append("tls-key is required when tls-cert is provided")
    if key_set and not cert_set:
        errors.append("tls-cert is required when tls-key is provided")
    if cert_set and config.tls_cert and not Path(config.tls_cert).exists():
        errors.append(f"tls-cert file not found: {config.tls_cert}")
    if key_set and config.tls_key and not Path(config.tls_key).exists():
        errors.append(f"tls-key file not found: {config.tls_key}")
    if config.workers < 1:
        errors.append("workers must be >= 1")
    if config.policy and not Path(config.policy).exists():
        errors.append(f"policy file not found: {config.policy}")
    return errors


def build_startup_banner(config: ServeConfig, tls_info: str) -> str:
    scheme = "https" if tls_info != "disabled" else "http"
    policy_text = config.policy or "default"
    return (
        "╔══════════════════════════════════════╗\n"
        f"║  Orchesis Control Plane v{__version__:<10}   ║\n"
        f"║  {scheme}://localhost:{config.port:<20}║\n"
        f"║  TLS: {tls_info:<29}║\n"
        f"║  Policy: {policy_text:<25}║\n"
        "╚══════════════════════════════════════╝"
    )


def run_preflight(policy: str | None = None) -> bool:
    """Basic import and policy parse preflight."""
    try:
        from orchesis.config import load_policy
        from orchesis.proxy import LLMHTTPProxy

        _ = LLMHTTPProxy
        if isinstance(policy, str) and policy.strip():
            _ = load_policy(policy)
        return True
    except Exception:
        return False


def start_server(config: ServeConfig) -> None:
    errors = validate_config(config)
    if errors:
        raise ValueError("; ".join(errors))

    if not config.skip_verify and not run_preflight(config.policy):
        raise RuntimeError("Preflight failed. Use --skip-verify to bypass checks.")

    tls_cert = config.tls_cert
    tls_key = config.tls_key
    tls_info = "disabled"
    if config.tls_self_signed and not (tls_cert and tls_key):
        tls_cert, tls_key = generate_self_signed_cert()
        tls_info = "self-signed"
    elif tls_cert and tls_key:
        tls_info = Path(tls_cert).name

    if config.policy:
        os.environ["ORCHESIS_POLICY"] = config.policy

    print(build_startup_banner(config, tls_info))
    if tls_info == "disabled":
        print("WARNING: TLS disabled; running plain HTTP.", file=sys.stderr)

    if uvicorn is None:  # pragma: no cover
        raise RuntimeError("uvicorn is not installed. Run: pip install orchesis[server]")

    api_module = importlib.import_module("orchesis.api")
    app_target = "orchesis.api:app"
    if hasattr(api_module, "app"):
        uvicorn.run(
            app_target,
            host=config.host,
            port=config.port,
            workers=config.workers,
            log_level=config.log_level,
            ssl_certfile=tls_cert,
            ssl_keyfile=tls_key,
        )
        return

    create_api_app = getattr(api_module, "create_api_app", None)
    if callable(create_api_app):
        app = create_api_app(policy_path=(config.policy or "policy.yaml"))
        uvicorn.run(
            app,
            host=config.host,
            port=config.port,
            workers=config.workers,
            log_level=config.log_level,
            ssl_certfile=tls_cert,
            ssl_keyfile=tls_key,
        )
        return

    raise RuntimeError("Unable to resolve API app target.")
