"""Request attributes beside the leaf (audit linkage plan, WP1).

A leaf may carry ``attrs`` (the request's own ``request_id``, ``surface``,
``payload_kind``, ``product``, ``workload_id`` and ``model_id``) signed by
the leaf's key over ``(leaf_hash, attrs)`` as ``attrs_sig``, and a signed
manifest commits the set as ``attrs_digest``. The signed leaf body is what it
was, so a bundle from before the attributes existed verifies as before, and a
release from before this one verifies a bundle that carries them.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import artzain.audit_verify as av
from artzain.audit_verify import _attrs_digest, _attrs_hash, verify_bundle

from .test_audit_verify import (  # noqa: TID252 - the tamper matrix's own builders
    _HAVE_CRYPTO,
    _build_bundle,
    _read_leaves,
    _signed_manifest,
    _Signer,
    _write_leaves,
)

requires_crypto = pytest.mark.skipif(not _HAVE_CRYPTO, reason="cryptography not installed")

_WITH_ATTRS = (2, 4)


def _attributes(seq: int) -> dict:
    return {"v": 1, "request_id": f"trace-{seq}", "surface": "sdk", "payload_kind": "tool_call",
            "product": "", "workload_id": "w-1", "model_id": ""}


def _with_attrs(d: Path, signer, seqs=_WITH_ATTRS) -> list[dict]:
    """Signed attributes on the leaves at *seqs*; the two keys null elsewhere."""
    leaves = _read_leaves(d)
    for leaf in leaves:
        if leaf["seq"] in seqs:
            leaf["attrs"] = _attributes(leaf["seq"])
            leaf["attrs_sig"] = signer.sign(
                _attrs_hash(leaf["leaf_hash"], leaf["attrs"]).encode("ascii"))
        else:
            leaf["attrs"], leaf["attrs_sig"] = None, None
    _write_leaves(d, leaves)
    return leaves


def _attrs_bundle(tmp: Path, signer, *, committed: bool = True) -> Path:
    """A clean bundle whose leaves 2 and 4 carry signed attributes and, when
    *committed*, a signed manifest that commits the set."""
    d = _build_bundle(tmp, signer)
    leaves = _with_attrs(d, signer)
    if committed:
        manifest = _signed_manifest(signer, 1, 5, 5, seal_count=1, leaves=leaves, attrs=leaves)
        (d / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return d


def _edit(d: Path, seq: int, **changes) -> None:
    leaves = _read_leaves(d)
    for leaf in leaves:
        if leaf["seq"] == seq:
            leaf.update(changes)
    _write_leaves(d, leaves)


@pytest.fixture()
def signer():
    if not _HAVE_CRYPTO:
        pytest.skip("cryptography not installed")
    return _Signer()


# -- the recipes, pinned at the byte level ----------------------------------------


def test_the_attributes_hash_is_over_the_leaf_hash_and_the_attributes():
    leaf_hash = "ab" * 32

    expected = hashlib.sha256(
        b'{"attrs":{"request_id":"r","v":1},"leaf_hash":"' + leaf_hash.encode("ascii") + b'"}'
    ).hexdigest()
    assert _attrs_hash(leaf_hash, {"v": 1, "request_id": "r"}) == expected


def test_the_digest_is_over_the_leaves_that_carry_attributes():
    leaves = [{"seq": 3, "attrs": {"v": 1}, "attrs_sig": "s3"},
              {"seq": 1, "attrs": None, "attrs_sig": None},
              {"seq": 2, "attrs": {"v": 1, "request_id": "r"}, "attrs_sig": "s2"}]

    assert _attrs_digest(leaves) == hashlib.sha256(b'[[2,"s2"],[3,"s3"]]').hexdigest()
    assert _attrs_digest([]) == hashlib.sha256(b"[]").hexdigest()


# -- what verifies ------------------------------------------------------------------


@requires_crypto
def test_signed_attributes_verify_and_are_counted(tmp_path, signer):
    (tmp_path / "plain").mkdir()
    plain = verify_bundle(_build_bundle(tmp_path / "plain", signer))
    assert plain.ok

    result = verify_bundle(_attrs_bundle(tmp_path, signer, committed=False))

    assert result.ok, (result.error, result.warnings)
    assert result.leaves_checked == 5
    assert result.signatures_checked == plain.signatures_checked + 2


@requires_crypto
def test_a_committed_set_verifies(tmp_path, signer):
    result = verify_bundle(_attrs_bundle(tmp_path, signer))

    assert result.ok, (result.error, result.warnings)
    assert result.attestation == "SELF-ATTESTED"


@requires_crypto
def test_a_bundle_from_before_attributes_verifies_as_before(tmp_path, signer):
    d = _build_bundle(tmp_path, signer)
    assert all("attrs" not in leaf for leaf in _read_leaves(d))

    result = verify_bundle(d)

    assert result.ok and result.signatures_checked == 6


# -- what fails ----------------------------------------------------------------------


@requires_crypto
def test_edited_attributes_fail_at_their_seq(tmp_path, signer):
    d = _attrs_bundle(tmp_path, signer)
    _edit(d, 4, attrs={**_attributes(4), "request_id": "trace-999"})

    result = verify_bundle(d)

    assert not result.ok
    assert result.first_bad_seq == 4
    assert result.error == "bad request attributes signature"
    assert result.leaves_checked == 3


@requires_crypto
def test_attributes_signed_by_another_key_fail(tmp_path, signer):
    d = _attrs_bundle(tmp_path, signer)
    other = _Signer()
    _edit(d, 2, attrs_sig=other.sign(_attrs_hash(_read_leaves(d)[1]["leaf_hash"],
                                                 _attributes(2)).encode("ascii")))

    result = verify_bundle(d)

    assert not result.ok and result.first_bad_seq == 2
    assert result.error == "bad request attributes signature"


@requires_crypto
def test_unsigned_attributes_fail(tmp_path, signer):
    d = _attrs_bundle(tmp_path, signer)
    _edit(d, 2, attrs_sig=None)

    result = verify_bundle(d)

    assert not result.ok and result.first_bad_seq == 2
    assert result.error == "request attributes unsigned"


def test_a_signature_without_attributes_fails(tmp_path, signer):
    d = _attrs_bundle(tmp_path, signer)
    _edit(d, 2, attrs=None)

    result = verify_bundle(d)

    assert not result.ok and result.first_bad_seq == 2
    assert result.error == "request attributes signature without attributes"


def test_attributes_that_are_not_an_object_fail(tmp_path, signer):
    d = _attrs_bundle(tmp_path, signer)
    _edit(d, 4, attrs=["trace-4"])

    result = verify_bundle(d)

    assert not result.ok and result.first_bad_seq == 4
    assert result.error == "malformed request attributes"


@requires_crypto
def test_attributes_dropped_from_the_committed_set_fail(tmp_path, signer):
    d = _attrs_bundle(tmp_path, signer)
    _edit(d, 4, attrs=None, attrs_sig=None)

    result = verify_bundle(d)

    assert not result.ok
    assert result.error == ("request attribute set does not match the signed manifest "
                            "(attrs_digest mismatch)")
    # Every leaf held on its own: the set is what no longer matches.
    assert result.leaves_checked == 5 and result.first_bad_seq is None


@requires_crypto
def test_attributes_added_to_the_committed_set_fail(tmp_path, signer):
    d = _attrs_bundle(tmp_path, signer)
    leaf = _read_leaves(d)[2]
    attrs = _attributes(3)
    _edit(d, 3, attrs=attrs, attrs_sig=signer.sign(_attrs_hash(leaf["leaf_hash"], attrs).encode("ascii")))

    result = verify_bundle(d)

    assert not result.ok
    assert result.error == ("request attribute set does not match the signed manifest "
                            "(attrs_digest mismatch)")


@requires_crypto
def test_without_cryptography_the_committed_set_is_still_checked(tmp_path, signer, monkeypatch):
    d = _attrs_bundle(tmp_path, signer)
    _edit(d, 4, attrs=None, attrs_sig=None)
    monkeypatch.setattr(av, "_load_public_keys", lambda keys: None)

    result = verify_bundle(d)

    assert not result.ok
    assert result.error == "request attributes differ (attrs_digest mismatch, signature not verified)"


@requires_crypto
def test_without_cryptography_the_signatures_are_not_counted(tmp_path, signer, monkeypatch):
    d = _attrs_bundle(tmp_path, signer)
    monkeypatch.setattr(av, "_load_public_keys", lambda keys: None)

    result = verify_bundle(d)

    assert result.ok and result.signatures_skipped
    assert result.signatures_checked == 0
