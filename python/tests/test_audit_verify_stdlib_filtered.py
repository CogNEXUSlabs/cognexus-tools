"""A filtered evidence bundle read without ``cryptography`` (the default install).

A hosted tenant's export ships only that tenant's leaves under seals it shares
with other tenants, so a seal can sit wholly inside the export's seq range and
still be only partly present. With ``cryptography`` the signed manifest's
``leaves_digest`` binds the exact leaves present, and the verifier reads such a
seal as a boundary of the filtered export; a leaf removed on the way is caught
by the manifest's record set. Without it, the manifest was not read at all, so
the first such seal read as a deleted leaf and an intact hosted bundle FAILED.

A signed manifest whose signer is in ``keys.json`` is now read the way a full
verifier reads it if its signature holds: its record set is compared with the
bundle, and the seal checks defer to its ``leaves_digest``. The signature is
the one thing left unchecked, as every other signature is on this install,
and the report says so. A bundle whose signatures hold therefore gets the same
verdict with and without ``cryptography``.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Callable

import pytest

import artzain.audit_verify as av

from .test_audit_verify import (  # noqa: TID252 - the tamper matrix's own builders
    _HAVE_CRYPTO,
    _canonical,
    _CertAuthority,
    _read_leaves,
    _read_proofs,
    _run_cli,
    _Signer,
    _sparse_sealed_bundle,
    _write_leaves,
    _write_proofs,
)
from .test_audit_verify_warning_summary import _tenant_bundle  # noqa: TID252

pytestmark = pytest.mark.skipif(not _HAVE_CRYPTO, reason="cryptography not installed")

_UNVERIFIED = ("signed manifest present but not verified (cryptography missing): the "
               "records it commits to are compared with the bundle, but nothing "
               "proves the server signed them")


@pytest.fixture()
def signer():
    return _Signer()


def _stdlib(monkeypatch, d: Path, **kw) -> av.VerifyResult:
    """``verify_bundle`` as the default install runs it: no ``cryptography``."""
    with monkeypatch.context() as m:
        m.setattr(av, "_load_public_keys", lambda keys: None)
        return av.verify_bundle(d, **kw)


def _manifest(d: Path) -> dict:
    return json.loads((d / "manifest.json").read_text(encoding="utf-8"))


def _resign(d: Path, signer: _Signer) -> None:
    body = {k: v for k, v in _manifest(d).items() if k not in ("sig", "signer_key_id")}
    sig = signer.sign(hashlib.sha256(_canonical(body)).hexdigest().encode("ascii"))
    (d / "manifest.json").write_text(
        json.dumps({**body, "sig": sig, "signer_key_id": signer.key_id}), encoding="utf-8")


def _drop(d: Path, *seqs: int) -> None:
    """Remove the leaves at *seqs*, and their inclusion proofs, from the bundle."""
    _write_leaves(d, [leaf for leaf in _read_leaves(d) if leaf["seq"] not in seqs])
    if (d / "proofs.jsonl").exists():
        _write_proofs(d, [p for p in _read_proofs(d) if p["seq"] not in seqs])


# -- bundles, each as the server exports it or as it might arrive ---------------


def _intact_tenant_export(tmp: Path, s: _Signer) -> Path:
    return _tenant_bundle(tmp, s)


def _intact_tenant_export_without_proofs(tmp: Path, s: _Signer) -> Path:
    return _tenant_bundle(tmp, s, proved=())


def _intact_dense_prefix_window(tmp: Path, s: _Signer) -> Path:
    # Contiguous leaves 1..3 under a seal over 1..9: the truncation shape.
    return _tenant_bundle(tmp, s, present=(1, 2, 3), batch=9, batches=1)


def _intact_full_export(tmp: Path, s: _Signer) -> Path:
    return _tenant_bundle(tmp, s, present=(1, 2, 3, 4), batch=4, batches=1)


def _tenant_leaf_removed_under_an_interior_seal(tmp: Path, s: _Signer) -> Path:
    d = _tenant_bundle(tmp, s)
    _drop(d, 18)
    return d


def _tenant_leaf_and_proof_removed_under_a_boundary_seal(tmp: Path, s: _Signer) -> Path:
    d = _sparse_sealed_bundle(tmp, s)
    _drop(d, 4)
    return d


def _tail_of_a_full_export_removed(tmp: Path, s: _Signer) -> Path:
    d = _tenant_bundle(tmp, s, present=(1, 2, 3, 4, 5), batch=5, batches=1)
    _drop(d, 4, 5)
    return d


def _tenant_export_under_an_unsigned_manifest(tmp: Path, s: _Signer) -> Path:
    d = _tenant_bundle(tmp, s)
    body = {k: v for k, v in _manifest(d).items() if k not in ("sig", "signer_key_id")}
    (d / "manifest.json").write_text(json.dumps(body), encoding="utf-8")
    return d


def _tenant_export_signed_by_a_key_not_in_the_bundle(tmp: Path, s: _Signer) -> Path:
    d = _tenant_bundle(tmp, s)
    _resign(d, _Signer())
    return d


_BUNDLES: dict[str, Callable[[Path, _Signer], Path]] = {
    fn.__name__.lstrip("_"): fn for fn in (
        _intact_tenant_export,
        _intact_tenant_export_without_proofs,
        _intact_dense_prefix_window,
        _intact_full_export,
        _tenant_leaf_removed_under_an_interior_seal,
        _tenant_leaf_and_proof_removed_under_a_boundary_seal,
        _tail_of_a_full_export_removed,
        _tenant_export_under_an_unsigned_manifest,
        _tenant_export_signed_by_a_key_not_in_the_bundle,
    )
}


@pytest.mark.parametrize("name", sorted(_BUNDLES))
def test_the_verdict_does_not_depend_on_cryptography(name, tmp_path, signer, monkeypatch):
    """Every signature in these bundles is genuine, so leaving them unchecked
    must not change whether the bundle verifies."""
    d = _BUNDLES[name](tmp_path, signer)
    full = av.verify_bundle(d)
    stdlib = _stdlib(monkeypatch, d)
    assert stdlib.signatures_skipped and not full.signatures_skipped
    assert stdlib.ok == full.ok, (full.error, stdlib.error)
    assert full.ok == name.startswith("intact"), full.error
    if full.ok:
        assert (stdlib.seals_checked, stdlib.seq_gaps, stdlib.seal_chain_gaps,
                stdlib.partial_seals, stdlib.partial_seals_proved) == \
               (full.seals_checked, full.seq_gaps, full.seal_chain_gaps,
                full.partial_seals, full.partial_seals_proved)


def test_an_intact_tenant_export_verifies_without_cryptography(tmp_path, signer, monkeypatch):
    r = _stdlib(monkeypatch, _tenant_bundle(tmp_path, signer))
    assert r.ok, r.error
    assert r.attestation == "SELF-ATTESTED"
    assert (r.leaves_checked, r.seals_checked, r.signatures_checked) == (8, 6, 0)
    assert r.warnings == [
        "cryptography not installed — signatures NOT verified. "
        "Install with: pip install 'artzain[verify]'",
        "7 seq gaps (tenant- or range-filtered export; chain linkage across the "
        "gaps not checkable offline)",
        _UNVERIFIED,
        "3 seals only partially present — boundaries of a filtered export; every "
        "present leaf proved included under its seal's merkle_root",
        "2 seal chain gaps (earlier seals not in this bundle)",
        "3 seals only partially present — boundaries of a filtered export, roots "
        "not recomputed",
    ]


def test_a_removed_leaf_fails_on_the_unverified_manifest(tmp_path, signer, monkeypatch):
    d = _tenant_leaf_removed_under_an_interior_seal(tmp_path, signer)
    r = _stdlib(monkeypatch, d)
    assert not r.ok
    assert r.first_bad_seq == 2
    assert r.error == (
        "the manifest (signature not verified) commits to records that are not "
        "present — records suppressed or substituted, or the manifest edited "
        "(leaf_count 8≠7, leaves_digest mismatch (exported leaf set altered))")


def test_a_leaf_removed_under_a_boundary_seal_is_now_caught(tmp_path, signer, monkeypatch):
    """No seal check sees this one: the seal reaches past the leaves on both
    sides, and the leaf went with its proof. Only the manifest's record set
    does, and without cryptography nothing compared it."""
    d = _tenant_leaf_and_proof_removed_under_a_boundary_seal(tmp_path, signer)
    r = _stdlib(monkeypatch, d)
    assert not r.ok
    assert "leaves_digest mismatch" in r.error, r.error


def test_dropped_proofs_fail_on_the_unverified_manifest(tmp_path, signer, monkeypatch):
    d = _sparse_sealed_bundle(tmp_path, signer)
    (d / "proofs.jsonl").unlink()
    r = _stdlib(monkeypatch, d)
    assert not r.ok
    assert r.error == ("inclusion proof set does not match the manifest, whose signature "
                       "was not verified (proofs_digest mismatch)")


def test_a_manifest_the_bundle_has_no_key_for_relaxes_nothing(tmp_path, signer, monkeypatch):
    """A full verifier would not trust it either: custody not verified."""
    d = _tenant_export_signed_by_a_key_not_in_the_bundle(tmp_path, signer)
    r = _stdlib(monkeypatch, d)
    assert not r.ok
    assert r.error.startswith("deleted leaf — seal S1"), r.error
    assert "signed manifest present but not verified (cryptography missing)" in r.warnings
    assert _UNVERIFIED not in r.warnings


def test_an_unsigned_manifest_relaxes_nothing(tmp_path, signer, monkeypatch):
    d = _tenant_export_under_an_unsigned_manifest(tmp_path, signer)
    r = _stdlib(monkeypatch, d)
    assert not r.ok
    assert r.error.startswith("deleted leaf — seal S1"), r.error
    assert not any("manifest" in w for w in r.warnings), r.warnings


def test_a_forged_manifest_signature_is_what_this_install_cannot_see(
        tmp_path, signer, monkeypatch):
    """The limit of the default install, stated: no signature is checked, the
    manifest's included, and the report says so on two lines."""
    d = _tenant_bundle(tmp_path, signer)
    manifest = _manifest(d)
    manifest["sig"] = base64.urlsafe_b64encode(bytes(64)).decode("ascii")
    (d / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert av.verify_bundle(d).error == "manifest signature invalid (custody broken)"
    r = _stdlib(monkeypatch, d)
    assert r.ok and r.signatures_skipped
    assert r.warnings[0].startswith("cryptography not installed — signatures NOT verified")
    assert _UNVERIFIED in r.warnings


def test_attestation_is_unchanged_without_cryptography(tmp_path, signer, monkeypatch):
    a = _CertAuthority()
    d = _tenant_bundle(tmp_path, signer)
    a.write_chain(d, a.deployment_cert(signer))
    assert av.verify_bundle(d, root_fingerprint=a.root_fingerprint).attestation == "ATTESTED"
    r = _stdlib(monkeypatch, d, root_fingerprint=a.root_fingerprint)
    assert r.ok, r.error
    assert r.attestation == "SELF-ATTESTED"
    assert r.attestation_reasons == ["cryptography not installed — certificate chain "
                                     "not evaluated"]


def test_cli_verifies_an_intact_tenant_export_without_cryptography(
        tmp_path, signer, monkeypatch, capsys):
    d = _tenant_bundle(tmp_path, signer)
    monkeypatch.setattr(av, "_load_public_keys", lambda keys: None)
    code, out = _run_cli(capsys, ["audit", "verify", str(d)])
    assert code == 0, out
    assert "  signatures:         SKIPPED (install 'artzain[verify]')" in out
    assert f"  ! {_UNVERIFIED}" in out
    assert "VERIFIED, SELF-ATTESTED — all leaf hashes, chain links, Merkle roots are intact." in out
