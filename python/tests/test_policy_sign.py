"""Tests for client-side policy bundle signing (FR-6, WS3).

Signature checks require ``cryptography`` (the ``artzain[policy]`` extra); the
crypto-dependent tests skip cleanly when it is unavailable so the suite still
runs in a zero-dependency environment.
"""

from __future__ import annotations

import json

import pytest

from artzain import policy_sign as ps

_HAS_CRYPTO = True
try:  # pragma: no cover - environment probe
    import cryptography  # noqa: F401
except Exception:  # pragma: no cover
    _HAS_CRYPTO = False

crypto_only = pytest.mark.skipif(not _HAS_CRYPTO, reason="cryptography not installed")


def _bundle() -> dict:
    return {
        "manifest": {"name": "acme", "version": "1.0.0", "team_id": 7, "schema_version": 1},
        "rules": [{"rule_id": "R1", "title": "t", "summary": "s", "category": "general"}],
        "rule_sets": ["base"],
        "guard_config": {"resolution": {"critical": "deny", "high": "review"}},
    }


def test_canonical_body_excludes_signature_and_is_sorted():
    b = _bundle()
    b["signature"] = {"key_id": "x", "sig": "y"}
    canon = ps.canonical_body(b)
    assert b"signature" not in canon
    # Keys are sorted: "manifest" sorts before "rules".
    assert canon.index(b"manifest") < canon.index(b"rules")


def test_body_sha256_stable_regardless_of_key_order():
    a = {"manifest": {"version": "1.0.0", "name": "x"}, "rules": []}
    b = {"rules": [], "manifest": {"name": "x", "version": "1.0.0"}}
    assert ps.body_sha256(a) == ps.body_sha256(b)


def test_key_id_is_16_hex():
    kid = ps.key_id_for_pem("-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----\n")
    assert len(kid) == 16
    int(kid, 16)  # hex-parseable


@crypto_only
def test_keygen_sign_roundtrip(tmp_path):
    key_id, pub_pem = ps.generate_keypair(tmp_path)
    assert ps.key_id_for_pem(pub_pem) == key_id

    signed = ps.sign_bundle(_bundle(), tmp_path)
    assert signed["signature"]["key_id"] == key_id

    # Verify the signature the same way the server does.
    import base64

    from cryptography.hazmat.primitives import serialization

    pub = serialization.load_pem_public_key(pub_pem.encode("ascii"))
    digest = ps.body_sha256(signed)
    sig_bytes = base64.urlsafe_b64decode(signed["signature"]["sig"] + "==")
    pub.verify(sig_bytes, digest.encode("ascii"))  # raises on failure


@crypto_only
def test_tampered_body_fails_verification(tmp_path):
    ps.generate_keypair(tmp_path)
    signed = ps.sign_bundle(_bundle(), tmp_path)

    tampered = json.loads(json.dumps(signed))
    tampered["rules"].append({"rule_id": "EVIL", "title": "x", "summary": "x", "category": "general"})

    import base64

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization

    pub = serialization.load_pem_public_key(ps.load_public_pem(tmp_path).encode("ascii"))
    sig_bytes = base64.urlsafe_b64decode(tampered["signature"]["sig"] + "==")
    with pytest.raises(InvalidSignature):
        pub.verify(sig_bytes, ps.body_sha256(tampered).encode("ascii"))


@crypto_only
def test_keygen_refuses_overwrite(tmp_path):
    ps.generate_keypair(tmp_path)
    with pytest.raises(ps.PolicySigningError):
        ps.generate_keypair(tmp_path)
