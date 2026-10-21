"""Self-signed certificate creation and fingerprints for the TLS mode."""

from __future__ import annotations

import hashlib
import os
import ssl
import subprocess
from pathlib import Path


def fingerprint_of_der(der: bytes) -> str:
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def fingerprint_of_pem(pem: str) -> str:
    return fingerprint_of_der(ssl.PEM_cert_to_DER_cert(pem))


def short_fingerprint(fingerprint: str, groups: int = 8) -> str:
    return ":".join(fingerprint.split(":")[:groups]) + ":..."


def ensure_certificate(home: str | os.PathLike[str]) -> tuple[Path, Path] | None:
    """Return (cert, key) in `home`, creating a self-signed pair with openssl.

    Returns None if openssl is not available, so the caller can fall back to
    plain TCP with a warning instead of crashing.
    """
    home = Path(home)
    cert, key = home / "server.crt", home / "server.key"
    if cert.exists() and key.exists():
        return cert, key
    home.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-days", "825", "-subj", "/CN=lanchat",
                "-keyout", str(key), "-out", str(cert),
            ],
            check=True,
            capture_output=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        for leftover in (cert, key):
            leftover.unlink(missing_ok=True)
        return None
    os.chmod(key, 0o600)
    return cert, key
