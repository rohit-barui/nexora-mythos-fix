"""
mTLS Certificate Utilities (Blueprint Pillar 13).

Self-signed CA + CA-signed identity certificates for gRPC mutual TLS. Used by
the V2 Agent gRPC server and client. Certificates are cached on disk and
refreshed in-memory; production deployments replace these with a real PKI.
"""

import os
import tempfile
from datetime import datetime, timezone
from typing import Tuple


def generate_self_signed_ca(cn: str = "nexora-ca") -> Tuple[str, str]:
    """Return (cert_pem, key_pem) for a self-signed CA."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, "Nexora"),
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, cn),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc).replace(year=2100))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return _serialize(cert, key)


def generate_self_signed_cert(cn: str = "nexora-agent") -> Tuple[str, str]:
    """Return (cert_pem, key_pem) for a standalone self-signed identity cert."""
    ca_cert, ca_key = generate_self_signed_ca("nexora-self-ca")
    return generate_identity_cert(ca_cert, ca_key, cn)


def generate_identity_cert(
    ca_cert_pem: str, ca_key_pem: str, cn: str = "nexora-agent"
) -> Tuple[str, str]:
    """Return (cert_pem, key_pem) for an identity cert signed by the given CA."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    ca_key = serialization.load_pem_private_key(ca_key_pem.encode("utf-8"), password=None)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode("utf-8"))

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Nexora"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc).replace(year=2100))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=False)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(_ip("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return _serialize(cert, key)


def _serialize(cert, key) -> Tuple[str, str]:
    from cryptography.hazmat.primitives import serialization

    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode("utf-8")
    return cert_pem, key_pem


def _ip(value: str):
    import ipaddress

    return ipaddress.ip_address(value)


def cert_dir() -> str:
    """Return the default on-disk certificate directory."""
    directory = os.environ.get("NEXORA_TLS_DIR") or os.path.join(
        tempfile.gettempdir(), "nexora-tls"
    )
    os.makedirs(directory, exist_ok=True)
    return directory


def write_pem(path: str, pem: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(pem)


def ensure_cert_kit(identity: str = "nexora-agent") -> dict:
    """Idempotently materialize CA + identity cert/key PEMs on disk.

    The CA is generated once and reused across identities so an already running
    server does not get invalidated when a new client identity is created.
    """
    directory = cert_dir()
    paths = {
        "ca_cert": os.path.join(directory, "ca.pem"),
        "ca_key": os.path.join(directory, "ca.key"),
        "cert": os.path.join(directory, f"{identity}.crt"),
        "key": os.path.join(directory, f"{identity}.key"),
    }
    if not (os.path.exists(paths["ca_cert"]) and os.path.exists(paths["ca_key"])):
        ca_cert, ca_key = generate_self_signed_ca()
        write_pem(paths["ca_cert"], ca_cert)
        write_pem(paths["ca_key"], ca_key)
    if not (os.path.exists(paths["cert"]) and os.path.exists(paths["key"])):
        with open(paths["ca_cert"], "r", encoding="utf-8") as fh:
            ca_cert = fh.read()
        with open(paths["ca_key"], "r", encoding="utf-8") as fh:
            ca_key = fh.read()
        cert, key = generate_identity_cert(ca_cert, ca_key, identity)
        write_pem(paths["cert"], cert)
        write_pem(paths["key"], key)
    return paths
