"""Client-side policy-bundle signing for ``artzain policy`` (FR-6, WS3).

Private keys are generated and used **here**, on your machine — only the public
key is ever sent to the server (``artzain policy register-key``).  The
canonicalisation and key-id rules match the server (``services/policy_bundles.py``)
so a bundle signed here verifies there:

* canonical body = the bundle JSON minus the top-level ``signature`` key,
  ``json.dumps(sort_keys=True, ensure_ascii=False, separators=(",",":"))``,
* signature = URL-safe base64 Ed25519 over the **ascii hex** of SHA-256(body),
* key_id = first 16 hex chars of SHA-256(public-key PEM).

Requires ``cryptography`` (the ``artzain[policy]`` extra).
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

_PRIV_NAME = "policy_signing_key.pem"
_PUB_NAME = "policy_signing_key.pub.pem"


class PolicySigningError(RuntimeError):
    """Raised for keygen/sign failures (missing crypto, missing key, etc.)."""


def _require_crypto():
    try:
        from cryptography.hazmat.primitives import serialization  # noqa: F401
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: F401
            Ed25519PrivateKey,
        )
    except Exception as exc:  # pragma: no cover - import guard
        raise PolicySigningError(
            "policy signing needs the 'cryptography' package — install artzain[policy]."
        ) from exc


def canonical_body(bundle: dict[str, Any]) -> bytes:
    body = {k: v for k, v in bundle.items() if k != "signature"}
    return json.dumps(
        body, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def body_sha256(bundle: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_body(bundle)).hexdigest()


def key_id_for_pem(public_key_pem: str) -> str:
    return hashlib.sha256(public_key_pem.encode("ascii")).hexdigest()[:16]


def generate_keypair(out_dir: Path) -> tuple[str, str]:
    """Generate an Ed25519 keypair into *out_dir*. Returns ``(key_id, public_pem)``.

    The private key is written mode ``0600`` and never leaves the machine.
    Refuses to overwrite an existing key.
    """
    _require_crypto()
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    out_dir.mkdir(parents=True, exist_ok=True)
    priv_path = out_dir / _PRIV_NAME
    pub_path = out_dir / _PUB_NAME
    if priv_path.exists():
        raise PolicySigningError(f"refusing to overwrite existing key at {priv_path}")

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    priv_path.write_bytes(priv_pem)
    pub_path.write_text(pub_pem, encoding="ascii")
    try:
        priv_path.chmod(0o600)
    except OSError:
        pass
    return key_id_for_pem(pub_pem), pub_pem


def load_public_pem(key_dir: Path) -> str:
    pub_path = key_dir / _PUB_NAME
    if not pub_path.is_file():
        raise PolicySigningError(f"no public key at {pub_path} — run 'artzain policy keygen' first")
    return pub_path.read_text(encoding="ascii")


def sign_bundle(bundle: dict[str, Any], key_dir: Path) -> dict[str, Any]:
    """Attach a ``signature`` block to *bundle* using the key in *key_dir*."""
    _require_crypto()
    from cryptography.hazmat.primitives import serialization

    priv_path = key_dir / _PRIV_NAME
    if not priv_path.is_file():
        raise PolicySigningError(f"no private key at {priv_path} — run 'artzain policy keygen' first")
    priv = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
    pub_pem = load_public_pem(key_dir)

    digest = body_sha256(bundle)
    sig_bytes = priv.sign(digest.encode("ascii"))
    out = dict(bundle)
    out["signature"] = {
        "key_id": key_id_for_pem(pub_pem),
        "sig": base64.urlsafe_b64encode(sig_bytes).decode("ascii"),
    }
    return out
