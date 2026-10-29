"""``seals_digest`` binds the seals an export ships.

A bundle from before the field existed verifies as it did. A signed manifest
that carries the field fails when the seals in the bundle are not that set,
including when the signature itself was not checked.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from artzain.audit_verify import verify_bundle

from .test_audit_verify import (  # noqa: TID252
    _HAVE_CRYPTO,
    _canonical,
    _read_leaves,
    _signed_manifest,
    _Signer,
    _write_leaves,
)

pytestmark = pytest.mark.skipif(not _HAVE_CRYPTO, reason="cryptography not installed")


@pytest.fixture()
def signer():
    return _Signer()


def _with_seals_digest(d, signer, digest: str):
    leaves = _read_leaves(d)
    manifest = _signed_manifest(signer, 1, 5, 5, seal_count=1, leaves=leaves)
    manifest["seals_digest"] = digest
    body = {k: v for k, v in manifest.items() if k not in ("sig", "signer_key_id")}
    signed = hashlib.sha256(_canonical(body)).hexdigest()
    manifest["sig"] = signer.sign(signed.encode("ascii"))
    (d / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def test_a_bundle_without_seals_digest_still_verifies(tmp_path, signer):
    from .test_audit_verify import _build_bundle

    d = _build_bundle(tmp_path, signer)
    leaves = _read_leaves(d)
    (d / "manifest.json").write_text(json.dumps(
        _signed_manifest(signer, 1, 5, 5, seal_count=1, leaves=leaves)),
        encoding="utf-8")
    result = verify_bundle(d)
    assert result.ok, result.error
    assert "seals_digest" not in (d / "manifest.json").read_text(encoding="utf-8")


def test_a_seals_digest_mismatch_fails(tmp_path, signer):
    from .test_audit_verify import _build_bundle

    d = _build_bundle(tmp_path, signer)
    _with_seals_digest(d, signer, "00" * 32)
    result = verify_bundle(d)
    assert not result.ok
    assert result.error == (
        "seal set does not match the signed manifest (seals_digest mismatch)")


def test_an_unverified_manifest_names_the_seals_digest_mismatch(
        tmp_path, signer, monkeypatch):
    import artzain.audit_verify as av

    from .test_audit_verify import _build_bundle

    d = _build_bundle(tmp_path, signer)
    _with_seals_digest(d, signer, "00" * 32)
    monkeypatch.setattr(av, "_load_public_keys", lambda keys: None)
    result = verify_bundle(d)
    assert not result.ok
    assert result.error == (
        "seals differ (seals_digest mismatch, signature not verified)")


def test_covering_scope_words_a_single_seal_chain_gap(tmp_path, signer):
    """One gap keeps its own line, and a covering bundle says why the earlier
    seal is absent."""
    from artzain.audit_verify import _merkle_root

    from .test_audit_verify import _SEAL_BODY_FIELDS, _build_bundle

    d = _build_bundle(tmp_path, signer)
    leaves = _read_leaves(d)
    for leaf in leaves:
        leaf["seal_id"] = "S-a" if leaf["seq"] <= 2 else "S-c"
    _write_leaves(d, leaves)
    genesis = json.loads((d / "seals.jsonl").read_text().splitlines()[0])
    sealed_at = genesis["sealed_at"]

    def _seal(seal_id, first, last, prev):
        covered = [leaf["leaf_hash"] for leaf in leaves if first <= leaf["seq"] <= last]
        body = {
            "seal_id": seal_id, "first_seq": first, "last_seq": last,
            "merkle_root": _merkle_root(covered), "prev_seal_hash": prev,
            "sealed_at": sealed_at,
        }
        assert set(body) == set(_SEAL_BODY_FIELDS)
        seal_hash = hashlib.sha256(_canonical(body)).hexdigest()
        seal = dict(body)
        seal.update(seal_hash=seal_hash, sig=signer.sign(seal_hash.encode("ascii")),
                    signer_key_id=signer.key_id)
        return seal

    first = _seal("S-a", 1, 2, genesis["prev_seal_hash"])
    # The seal between them is not in the bundle: the link does not match.
    second = _seal("S-c", 3, 5, "ab" * 32)
    (d / "seals.jsonl").write_text(
        json.dumps(first, sort_keys=True) + "\n" + json.dumps(second, sort_keys=True) + "\n",
        encoding="utf-8")
    manifest = _signed_manifest(signer, 1, 5, 5, seal_count=2, leaves=leaves)
    manifest["seal_scope"] = "covering"
    body = {k: v for k, v in manifest.items() if k not in ("sig", "signer_key_id")}
    manifest["sig"] = signer.sign(hashlib.sha256(_canonical(body)).hexdigest().encode("ascii"))
    (d / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    result = verify_bundle(d)
    assert result.ok, (result.error, result.warnings)
    assert result.seal_chain_gaps == 1
    assert any("bundle carries only seals over these records" in warning
               for warning in result.warnings), result.warnings
