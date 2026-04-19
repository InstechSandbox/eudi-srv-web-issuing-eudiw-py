#!/usr/bin/env python3

import base64
import json
import os
import shutil
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwcrypto import jwk


def _runtime_dir() -> Path:
    return Path(os.environ.get("ISSUER_RUNTIME_DIR", "/tmp/eudiw/pid-issuer-runtime"))


def _env_path(name: str, default: Path) -> Path:
    return Path(os.environ.get(name, str(default))).expanduser()


def _write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value if value.endswith("\n") else value + "\n", encoding="utf-8")


def _write_bytes(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)


def _copy_if_missing(source: Path, destination: Path) -> None:
    if source.exists() and not destination.exists():
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)


def _pem_from_der(der_bytes: bytes) -> bytes:
    certificate = x509.load_der_x509_certificate(der_bytes)
    return certificate.public_bytes(serialization.Encoding.PEM)


def _der_from_pem(pem_bytes: bytes) -> bytes:
    certificate = x509.load_pem_x509_certificate(pem_bytes)
    return certificate.public_bytes(serialization.Encoding.DER)


def _sync_utopia_signer_assets(privkey_dir: Path, cert_dir: Path) -> None:
    key_primary = privkey_dir / "PID-DS-0001_UT.pem"
    key_local = privkey_dir / "PID-DS-LOCAL-UT.pem"
    cert_der_primary = cert_dir / "PID-DS-0001_UT_cert.der"
    cert_der_local = cert_dir / "PID-DS-LOCAL-UT_cert.der"
    cert_pem_primary = cert_dir / "PID-DS-0001_UT_cert.pem"
    cert_pem_local = cert_dir / "PID-DS-LOCAL-UT_cert.pem"

    signer_key_pem = os.environ.get("UTOPIA_SIGNER_KEY_PEM", "")
    signer_cert_pem = os.environ.get("UTOPIA_SIGNER_CERT_PEM", "")
    signer_cert_der_b64 = os.environ.get("UTOPIA_SIGNER_CERT_DER_BASE64", "")

    if signer_key_pem:
        _write_text(key_primary, signer_key_pem)
    _copy_if_missing(key_primary, key_local)
    _copy_if_missing(key_local, key_primary)

    if signer_cert_pem:
        _write_text(cert_pem_primary, signer_cert_pem)
    if signer_cert_der_b64:
        _write_bytes(cert_der_primary, base64.b64decode(signer_cert_der_b64))

    if cert_der_primary.exists() and not cert_pem_primary.exists():
        _write_bytes(cert_pem_primary, _pem_from_der(cert_der_primary.read_bytes()))
    if cert_pem_primary.exists() and not cert_der_primary.exists():
        _write_bytes(cert_der_primary, _der_from_pem(cert_pem_primary.read_bytes()))

    _copy_if_missing(cert_der_primary, cert_der_local)
    _copy_if_missing(cert_der_local, cert_der_primary)
    _copy_if_missing(cert_pem_primary, cert_pem_local)
    _copy_if_missing(cert_pem_local, cert_pem_primary)

    if not key_primary.exists() or not cert_der_primary.exists() or not cert_pem_primary.exists():
        raise SystemExit(
            "Missing issuer signer assets. Provide UTOPIA_SIGNER_KEY_PEM and either "
            "UTOPIA_SIGNER_CERT_PEM or UTOPIA_SIGNER_CERT_DER_BASE64, or mount matching files at runtime."
        )


def _ensure_ec_private_key(path: Path) -> None:
    if path.exists():
        return

    configured_pem = os.environ.get("CREDENTIAL_REQUEST_KEY_PEM", "")
    if configured_pem:
        _write_text(path, configured_pem)
        return

    private_key = ec.generate_private_key(ec.SECP256R1())
    _write_bytes(
        path,
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )


def _ensure_rsa_private_key(path: Path) -> None:
    if path.exists():
        return

    configured_pem = os.environ.get("NONCE_KEY_PEM", "")
    if configured_pem:
        _write_text(path, configured_pem)
        return

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _write_bytes(
        path,
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )


def _write_metadata_overrides(credential_key_path: Path, override_path: Path) -> None:
    override_path.parent.mkdir(parents=True, exist_ok=True)
    public_jwk = json.loads(jwk.JWK.from_pem(credential_key_path.read_bytes()).export(private_key=False))
    public_jwk["use"] = "enc"
    public_jwk["alg"] = "ECDH-ES"
    override_path.write_text(
        json.dumps({"credential_request_encryption_jwk": public_jwk}, indent=2) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    runtime_dir = _runtime_dir()
    trust_dir = _env_path("TRUSTED_CAS_PATH", runtime_dir / "cert")
    privkey_dir = _env_path("PRIVKEY_PATH", runtime_dir / "privKey")
    nonce_key_path = _env_path("NONCE_KEY", privkey_dir / "nonce_rsa2048.pem")
    credential_key_path = _env_path("CREDENTIAL_KEY", privkey_dir / "credential_request_ec.pem")
    metadata_override_path = _env_path(
        "ISSUER_METADATA_OVERRIDES_FILE",
        runtime_dir / "metadata_overrides.json",
    )

    trust_dir.mkdir(parents=True, exist_ok=True)
    privkey_dir.mkdir(parents=True, exist_ok=True)

    _sync_utopia_signer_assets(privkey_dir, trust_dir)
    _ensure_ec_private_key(credential_key_path)
    _ensure_rsa_private_key(nonce_key_path)
    _write_metadata_overrides(credential_key_path, metadata_override_path)

    print(f"Prepared issuer runtime assets under {runtime_dir}")


if __name__ == "__main__":
    main()