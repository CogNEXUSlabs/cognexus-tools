"""Tamper-matrix tests for the offline audit verifier (FR-3, WS2 §2.4).

Builds a small, validly-signed evidence bundle, asserts it verifies, then runs
each tamper case (edited / deleted / reordered leaf, forged signature, truncated
log, wrong key) and asserts verification fails with a precise reason.

Signature checks require ``cryptography``; the signature-specific cases are
skipped when it is not installed, but the hash/chain/Merkle cases always run.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from artzain.audit_verify import (
    _LEAF_BODY_FIELDS,
    _SEAL_BODY_FIELDS,
    _merkle_root,
    verify_bundle,
)

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    _HAVE_CRYPTO = True
except Exception:  # pragma: no cover
    _HAVE_CRYPTO = False

requires_crypto = pytest.mark.skipif(not _HAVE_CRYPTO, reason="cryptography not installed")

_GENESIS = "0" * 64


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


class _Signer:
    """Mirror of the server AuditSigner (Ed25519 + 16-hex key_id)."""

    def __init__(self) -> None:
        self._sk = Ed25519PrivateKey.generate()
        self._pk = self._sk.public_key()

    @property
    def public_key_pem(self) -> str:
        return self._pk.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    @property
    def key_id(self) -> str:
        return hashlib.sha256(self.public_key_pem.encode("ascii")).hexdigest()[:16]

    def sign(self, data: bytes) -> str:
        return base64.urlsafe_b64encode(self._sk.sign(data)).decode("ascii")


def _build_bundle(tmp: Path, signer, n: int = 5) -> Path:
    leaves = []
    prev = _GENESIS
    base_ts = datetime(2026, 6, 17, 19, 0, 0, tzinfo=timezone.utc)
    for seq in range(1, n + 1):
        body = {
            "leaf_id": f"L{seq:025d}",
            "decision_id": f"D{seq:025d}",
            "created_at": (base_ts + timedelta(seconds=seq)).isoformat(),
            "user_id": 1,
            "team_id": None,
            "agent_did": "agent-x",
            "action": "send_email",
            "target": "crm:1",
            "outcome": "allow",
            "payload_sha256": hashlib.sha256(str(seq).encode()).hexdigest(),
            "votes": [{"name": "pi", "verdict": "allow", "severity": "none"}],
            "bundle_version": "builtin:v0",
            "resolution": "builtin/strict-v0",
            "prev_leaf_hash": prev,
        }
        assert set(body) == set(_LEAF_BODY_FIELDS)
        lh = hashlib.sha256(_canonical(body)).hexdigest()
        rec = dict(body)
        rec.update(seq=seq, leaf_hash=lh, sig=signer.sign(lh.encode("ascii")),
                   signer_key_id=signer.key_id, seal_id="S0")
        leaves.append(rec)
        prev = lh

    root = _merkle_root([l["leaf_hash"] for l in leaves])
    seal_body = {
        "seal_id": "S0", "first_seq": 1, "last_seq": n, "merkle_root": root,
        "prev_seal_hash": _GENESIS,
        "sealed_at": (base_ts + timedelta(minutes=1)).isoformat(),
    }
    assert set(seal_body) == set(_SEAL_BODY_FIELDS)
    sh = hashlib.sha256(_canonical(seal_body)).hexdigest()
    seal = dict(seal_body)
    seal.update(seal_hash=sh, sig=signer.sign(sh.encode("ascii")), signer_key_id=signer.key_id)

    d = tmp / "bundle"
    d.mkdir()
    (d / "leaves.jsonl").write_text(
        "".join(json.dumps(l, sort_keys=True) + "\n" for l in leaves), encoding="utf-8"
    )
    (d / "seals.jsonl").write_text(json.dumps(seal, sort_keys=True) + "\n", encoding="utf-8")
    (d / "keys.json").write_text(
        json.dumps([{"key_id": signer.key_id, "public_key_pem": signer.public_key_pem, "scope": "audit"}]),
        encoding="utf-8",
    )
    (d / "manifest.json").write_text(json.dumps({"leaf_count": n}), encoding="utf-8")
    return d


def _read_leaves(d: Path) -> list[dict]:
    return [json.loads(l) for l in (d / "leaves.jsonl").read_text().splitlines() if l.strip()]


def _write_leaves(d: Path, leaves: list[dict]) -> None:
    (d / "leaves.jsonl").write_text(
        "".join(json.dumps(l, sort_keys=True) + "\n" for l in leaves), encoding="utf-8"
    )


@pytest.fixture()
def signer():
    if not _HAVE_CRYPTO:
        pytest.skip("cryptography not installed")
    return _Signer()


def test_clean_bundle_verifies(tmp_path, signer):
    d = _build_bundle(tmp_path, signer)
    r = verify_bundle(d)
    assert r.ok, r.error
    assert r.leaves_checked == 5
    assert r.seals_checked == 1
    assert r.signatures_checked == 6  # 5 leaves + 1 seal
    assert r.warnings == []


def test_edited_leaf_fails_and_names_seq(tmp_path, signer):
    d = _build_bundle(tmp_path, signer)
    leaves = _read_leaves(d)
    leaves[2]["target"] = "crm:999"  # flip a byte; keep stored leaf_hash
    _write_leaves(d, leaves)
    r = verify_bundle(d)
    assert not r.ok
    assert r.first_bad_seq == 3
    assert "leaf_hash mismatch" in r.error


def test_deleted_leaf_fails(tmp_path, signer):
    d = _build_bundle(tmp_path, signer)
    leaves = _read_leaves(d)
    del leaves[2]  # remove interior seq 3
    _write_leaves(d, leaves)
    r = verify_bundle(d)
    assert not r.ok
    assert "deleted leaf" in r.error or "chain linkage" in r.error


def test_reordered_leaf_fails(tmp_path, signer):
    d = _build_bundle(tmp_path, signer)
    leaves = _read_leaves(d)
    # Swap the seq numbers of two leaves; prev_leaf_hash (signed) no longer lines up.
    leaves[1]["seq"], leaves[3]["seq"] = leaves[3]["seq"], leaves[1]["seq"]
    _write_leaves(d, leaves)
    r = verify_bundle(d)
    assert not r.ok


def test_truncated_log_fails(tmp_path, signer):
    d = _build_bundle(tmp_path, signer)
    leaves = _read_leaves(d)
    _write_leaves(d, leaves[:-2])  # drop the last two leaves the seal commits to
    r = verify_bundle(d)
    assert not r.ok
    assert "truncated log" in r.error


@requires_crypto
def test_forged_signature_fails(tmp_path, signer):
    d = _build_bundle(tmp_path, signer)
    leaves = _read_leaves(d)
    leaves[1]["sig"] = base64.urlsafe_b64encode(b"\x00" * 64).decode("ascii")
    _write_leaves(d, leaves)
    r = verify_bundle(d)
    assert not r.ok
    assert "signature" in r.error


@requires_crypto
def test_wrong_key_fails(tmp_path, signer):
    d = _build_bundle(tmp_path, signer)
    other = _Signer()
    (d / "keys.json").write_text(
        json.dumps([{"key_id": signer.key_id, "public_key_pem": other.public_key_pem}]),
        encoding="utf-8",
    )
    r = verify_bundle(d)
    assert not r.ok
    assert "signature" in r.error


def test_signatures_skipped_without_crypto(tmp_path, signer, monkeypatch):
    d = _build_bundle(tmp_path, signer)
    # Force the "no cryptography" path.
    import artzain.audit_verify as av

    monkeypatch.setattr(av, "_load_public_keys", lambda keys: None)
    r = verify_bundle(d)
    assert r.ok, r.error
    assert r.signatures_skipped
    assert any("cryptography not installed" in w for w in r.warnings)
