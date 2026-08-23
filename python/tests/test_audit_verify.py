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
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    _HAVE_CRYPTO = True
except Exception:  # pragma: no cover
    _HAVE_CRYPTO = False

requires_crypto = pytest.mark.skipif(not _HAVE_CRYPTO, reason="cryptography not installed")

_GENESIS = "0" * 64


def _canonical(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _leaves_digest(leaves: list[dict]) -> str:
    """Mirror of artzain.audit_verify._leaves_digest / the server helper."""
    pairs = sorted(([int(leaf["seq"]), leaf["leaf_hash"]] for leaf in leaves), key=lambda p: p[0])
    return hashlib.sha256(_canonical(pairs)).hexdigest()


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

    root = _merkle_root([leaf["leaf_hash"] for leaf in leaves])
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
        "".join(json.dumps(leaf, sort_keys=True) + "\n" for leaf in leaves), encoding="utf-8"
    )
    (d / "seals.jsonl").write_text(json.dumps(seal, sort_keys=True) + "\n", encoding="utf-8")
    (d / "keys.json").write_text(
        json.dumps([{"key_id": signer.key_id, "public_key_pem": signer.public_key_pem, "scope": "audit"}]),
        encoding="utf-8",
    )
    (d / "manifest.json").write_text(json.dumps({"leaf_count": n}), encoding="utf-8")
    return d


def _read_leaves(d: Path) -> list[dict]:
    return [json.loads(leaf) for leaf in (d / "leaves.jsonl").read_text().splitlines() if leaf.strip()]


def _write_leaves(d: Path, leaves: list[dict]) -> None:
    (d / "leaves.jsonl").write_text(
        "".join(json.dumps(leaf, sort_keys=True) + "\n" for leaf in leaves), encoding="utf-8"
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


# ---------------------------------------------------------------------------
# WS-4 — three-state verification against the Evidence Root
#
# The substituted-keypair test is the one that proves the evidentiary hole
# is closed: a fabricated bundle carrying its own keys must never claim more
# than SELF-ATTESTED.
# ---------------------------------------------------------------------------


def _sign_cert_body(body: dict, issuer: "_Signer") -> dict:
    h = hashlib.sha256(_canonical(body)).hexdigest()
    return {**body, "sig": issuer.sign(h.encode("ascii")),
            "signer_key_id": issuer.key_id}


class _CertAuthority:
    """Test-side root → issuing CA → deployment certificate chain."""

    def __init__(self) -> None:
        self.root = _Signer()
        self.issuing = _Signer()
        self.issuing_cert = _sign_cert_body({
            "format": "cognexus-issuing-certificate",
            "format_version": 1,
            "cert_id": "ISS-0001",
            "subject": "cognexus-issuing-ca",
            "not_before": "2026-01-01T00:00:00+00:00",
            "not_after": "2026-12-31T00:00:00+00:00",
            "public_key": self.issuing.public_key_pem,
            "issuer_key_id": self.root.key_id,
        }, self.root)

    @property
    def root_fingerprint(self) -> str:
        return hashlib.sha256(self.root.public_key_pem.encode("ascii")).hexdigest()

    def deployment_cert(self, subject: "_Signer", *,
                        not_before: str = "2026-06-01T00:00:00+00:00",
                        not_after: str = "2026-09-01T00:00:00+00:00") -> dict:
        return _sign_cert_body({
            "format": "cognexus-licence-certificate",
            "format_version": 1,
            "cert_id": "DEP-0001",
            "install_id": "inst-test-1",
            "customer_id": "cust-1",
            "licence_id": "lic-1",
            "deployment_class": "private",
            "not_before": not_before,
            "not_after": not_after,
            "decision_band": 12_000_000,
            "entitled_bundles": ["eu-ai-act"],
            "retention_floor_years": 7,
            "public_key": subject.public_key_pem,
            "issuer_key_id": self.issuing.key_id,
        }, self.issuing)

    def write_chain(self, d: Path, *deployment_certs: dict,
                    include_root: bool = True) -> None:
        (d / "certificates.json").write_text(json.dumps({
            "root_public_key_pem": self.root.public_key_pem if include_root else None,
            "issuing_certificates": [self.issuing_cert],
            "deployment_certificates": list(deployment_certs),
        }, sort_keys=True), encoding="utf-8")


@pytest.fixture()
def authority():
    if not _HAVE_CRYPTO:
        pytest.skip("cryptography not installed")
    return _CertAuthority()


def _signed_manifest(signer, first_seq, last_seq, leaf_count,
                     seal_count=None, leaves=None) -> dict:
    manifest = {"first_seq": first_seq, "last_seq": last_seq,
                "leaf_count": leaf_count, "tenant_user_id": 1}
    if seal_count is not None:
        manifest["seal_count"] = seal_count
    # A real (patched) export always commits a leaves_digest, and ATTESTED now
    # requires it. Passing ``leaves`` makes this a content-bound manifest;
    # omitting it models a pre-digest bundle (caps at SELF-ATTESTED).
    if leaves is not None:
        manifest["leaves_digest"] = _leaves_digest(leaves)
    h = hashlib.sha256(_canonical(manifest)).hexdigest()
    return {**manifest, "sig": signer.sign(h.encode("ascii")),
            "signer_key_id": signer.key_id}


def _certified_bundle(tmp_path, signer, authority, **cert_kw) -> Path:
    d = _build_bundle(tmp_path, signer)
    authority.write_chain(d, authority.deployment_cert(signer, **cert_kw))
    # A real export always ships a signed manifest committing the content
    # digest; ATTESTED requires one.
    (d / "manifest.json").write_text(
        json.dumps(_signed_manifest(signer, 1, 5, 5, leaves=_read_leaves(d))),
        encoding="utf-8")
    return d


def test_substituted_keypair_reports_self_attested_not_attested(
        tmp_path, signer, authority):
    """THE hole-closing test: an attacker who fabricates a chain and ships
    their own keypair gets a bundle that is internally consistent (ok=True)
    but must never claim ATTESTED."""
    d = _certified_bundle(tmp_path, signer, authority)
    # Attacker: fresh keypair, re-sign every leaf and seal, swap keys.json.
    evil = _Signer()
    leaves = _read_leaves(d)
    for leaf in leaves:
        leaf["target"] = "crm:fabricated"  # the tampering being laundered
    # Rebuild the hash chain over the tampered bodies and re-sign it all.
    prev = _GENESIS
    for leaf in leaves:
        leaf["prev_leaf_hash"] = prev
        body = {k: leaf[k] for k in _LEAF_BODY_FIELDS}
        leaf["leaf_hash"] = hashlib.sha256(_canonical(body)).hexdigest()
        leaf["sig"] = evil.sign(leaf["leaf_hash"].encode("ascii"))
        leaf["signer_key_id"] = evil.key_id
        prev = leaf["leaf_hash"]
    _write_leaves(d, leaves)
    root = _merkle_root([leaf["leaf_hash"] for leaf in leaves])
    seal_body = {
        "seal_id": "S0", "first_seq": 1, "last_seq": len(leaves),
        "merkle_root": root, "prev_seal_hash": _GENESIS,
        "sealed_at": "2026-06-17T19:01:00+00:00",
    }
    sh = hashlib.sha256(_canonical(seal_body)).hexdigest()
    seal = dict(seal_body)
    seal.update(seal_hash=sh, sig=evil.sign(sh.encode("ascii")),
                signer_key_id=evil.key_id)
    (d / "seals.jsonl").write_text(json.dumps(seal, sort_keys=True) + "\n",
                                   encoding="utf-8")
    (d / "keys.json").write_text(
        json.dumps([{"key_id": evil.key_id, "public_key_pem": evil.public_key_pem}]),
        encoding="utf-8",
    )
    # Attacker also re-signs a matching manifest with their key (with a digest
    # over their tampered leaves) so the custody + content cross-checks pass —
    # coverage against the certified key bytes is what must still cap this at
    # SELF-ATTESTED.
    (d / "manifest.json").write_text(
        json.dumps(_signed_manifest(evil, 1, len(leaves), len(leaves), leaves=leaves)),
        encoding="utf-8")

    r = verify_bundle(d, root_fingerprint=authority.root_fingerprint)
    assert r.ok, r.error  # internally consistent — that is the whole point
    assert r.attestation == "SELF-ATTESTED"
    assert r.attestation != "ATTESTED"
    assert any("not covered" in w or "no valid certificate" in w
               for w in r.attestation_reasons)


def test_key_id_label_spoof_reports_self_attested(tmp_path, signer, authority):
    """Variant: the attacker keeps the ORIGINAL signer_key_id label but puts
    their own PEM under it. Coverage must compare the actual key bytes, not
    the label."""
    d = _certified_bundle(tmp_path, signer, authority)
    evil = _Signer()
    leaves = _read_leaves(d)
    prev = _GENESIS
    for leaf in leaves:
        leaf["prev_leaf_hash"] = prev
        body = {k: leaf[k] for k in _LEAF_BODY_FIELDS}
        leaf["leaf_hash"] = hashlib.sha256(_canonical(body)).hexdigest()
        leaf["sig"] = evil.sign(leaf["leaf_hash"].encode("ascii"))
        # signer_key_id stays the genuine label
        prev = leaf["leaf_hash"]
    _write_leaves(d, leaves)
    seal_body = {
        "seal_id": "S0", "first_seq": 1, "last_seq": len(leaves),
        "merkle_root": _merkle_root([leaf["leaf_hash"] for leaf in leaves]),
        "prev_seal_hash": _GENESIS,
        "sealed_at": "2026-06-17T19:01:00+00:00",
    }
    sh = hashlib.sha256(_canonical(seal_body)).hexdigest()
    seal = dict(seal_body)
    seal.update(seal_hash=sh, sig=evil.sign(sh.encode("ascii")),
                signer_key_id=signer.key_id)
    (d / "seals.jsonl").write_text(json.dumps(seal, sort_keys=True) + "\n",
                                   encoding="utf-8")
    (d / "keys.json").write_text(
        json.dumps([{"key_id": signer.key_id,   # genuine label…
                     "public_key_pem": evil.public_key_pem}]),  # …attacker key
        encoding="utf-8",
    )
    # Manifest signed by the attacker's key but carrying the genuine label,
    # so it verifies against the swapped PEM and the cross-check passes.
    m = {"first_seq": 1, "last_seq": len(leaves), "leaf_count": len(leaves),
         "leaves_digest": _leaves_digest(leaves), "tenant_user_id": 1}
    mh = hashlib.sha256(_canonical(m)).hexdigest()
    m.update(sig=evil.sign(mh.encode("ascii")), signer_key_id=signer.key_id)
    (d / "manifest.json").write_text(json.dumps(m), encoding="utf-8")

    r = verify_bundle(d, root_fingerprint=authority.root_fingerprint)
    assert r.ok, r.error
    assert r.attestation == "SELF-ATTESTED"


def test_certified_bundle_reports_attested(tmp_path, signer, authority):
    d = _certified_bundle(tmp_path, signer, authority)
    r = verify_bundle(d, root_fingerprint=authority.root_fingerprint)
    assert r.ok, r.error
    assert r.attestation == "ATTESTED"
    assert r.certificates_checked >= 2  # issuing + deployment


def test_pre_certificate_bundle_stays_self_attested_and_does_not_fail(
        tmp_path, signer):
    """Migration guarantee: bundles exported before certificates exist keep
    verifying, reporting SELF-ATTESTED."""
    d = _build_bundle(tmp_path, signer)  # no certificates.json at all
    r = verify_bundle(d)
    assert r.ok, r.error
    assert r.attestation == "SELF-ATTESTED"
    assert any("no certificate chain" in w for w in r.attestation_reasons)


def test_no_pinned_root_stays_self_attested_even_with_chain(
        tmp_path, signer, authority):
    """Without a pinned fingerprint (the pre-ceremony state) a chain can
    never upgrade the claim — otherwise the bundle would be vouching for
    its own root."""
    d = _certified_bundle(tmp_path, signer, authority)
    r = verify_bundle(d)  # no pin argument, module default is None
    assert r.ok, r.error
    assert r.attestation == "SELF-ATTESTED"
    assert any("fingerprint" in w for w in r.attestation_reasons)


def test_wrong_root_fingerprint_reports_self_attested(tmp_path, signer, authority):
    d = _certified_bundle(tmp_path, signer, authority)
    r = verify_bundle(d, root_fingerprint="ab" * 32)
    assert r.ok, r.error
    assert r.attestation == "SELF-ATTESTED"
    assert any("fingerprint" in w for w in r.attestation_reasons)


def test_cert_expired_at_signing_time_reports_self_attested(
        tmp_path, signer, authority):
    """Leaves signed outside the deployment certificate's validity window
    are not attested — and never a hard failure."""
    d = _build_bundle(tmp_path, signer)  # leaves dated 2026-06-17
    authority.write_chain(d, authority.deployment_cert(
        signer, not_before="2026-01-01T00:00:00+00:00",
        not_after="2026-02-01T00:00:00+00:00"))
    (d / "manifest.json").write_text(
        json.dumps(_signed_manifest(signer, 1, 5, 5)), encoding="utf-8")
    r = verify_bundle(d, root_fingerprint=authority.root_fingerprint)
    assert r.ok, r.error
    assert r.attestation == "SELF-ATTESTED"
    assert any("signing time" in x for x in r.attestation_reasons)


def test_deployment_cert_issued_outside_issuer_window_not_attested(
        tmp_path, signer, authority):
    """A deployment certificate whose not_before falls outside its issuer's
    validity window was not validly issued."""
    d = _build_bundle(tmp_path, signer)
    authority.write_chain(d, authority.deployment_cert(
        signer, not_before="2027-06-01T00:00:00+00:00",
        not_after="2027-09-01T00:00:00+00:00"))
    (d / "manifest.json").write_text(
        json.dumps(_signed_manifest(signer, 1, 5, 5)), encoding="utf-8")
    r = verify_bundle(d, root_fingerprint=authority.root_fingerprint)
    assert r.ok, r.error
    assert r.attestation == "SELF-ATTESTED"


def test_attestation_degrades_without_cryptography(tmp_path, signer, authority,
                                                   monkeypatch):
    """cryptography stays optional: without it the verifier degrades and
    says so — it cannot claim ATTESTED because it cannot check the chain."""
    d = _certified_bundle(tmp_path, signer, authority)
    import artzain.audit_verify as av

    monkeypatch.setattr(av, "_load_public_keys", lambda keys: None)
    r = verify_bundle(d, root_fingerprint=authority.root_fingerprint)
    assert r.ok, r.error
    assert r.signatures_skipped
    assert r.attestation == "SELF-ATTESTED"
    assert any("cryptography" in w for w in r.attestation_reasons)


def test_tampered_chain_still_fails_regardless_of_certificates(
        tmp_path, signer, authority):
    """FAILED stays FAILED: a certificate chain never rescues a broken log."""
    d = _certified_bundle(tmp_path, signer, authority)
    leaves = _read_leaves(d)
    leaves[2]["target"] = "crm:999"
    _write_leaves(d, leaves)
    r = verify_bundle(d, root_fingerprint=authority.root_fingerprint)
    assert not r.ok
    assert r.attestation is None


def test_signed_manifest_tamper_fails(tmp_path, signer, authority):
    """A signed manifest that no longer verifies is a custody failure."""
    d = _certified_bundle(tmp_path, signer, authority)
    signed = _signed_manifest(signer, 1, 5, 5)
    (d / "manifest.json").write_text(json.dumps(signed), encoding="utf-8")
    assert verify_bundle(d, root_fingerprint=authority.root_fingerprint).ok

    signed["leaf_count"] = 500  # tamper after signing
    (d / "manifest.json").write_text(json.dumps(signed), encoding="utf-8")
    r = verify_bundle(d, root_fingerprint=authority.root_fingerprint)
    assert not r.ok
    assert "manifest" in r.error


def test_prefix_deletion_of_certified_bundle_fails_not_attested(
        tmp_path, signer, authority):
    """Leaf suppression: deleting the EARLIEST leaves of a certified bundle
    must FAIL — the signed manifest committed to seq 1, so a bundle that now
    starts at seq 2 has records removed. Without this the seal's
    'boundary of a filtered export' leniency would wave it through as
    ATTESTED. Reported by the WS-4 adversarial review."""
    d = _certified_bundle(tmp_path, signer, authority)
    # Sanity: intact certified bundle attests (its signed manifest commits the
    # content digest over seq 1..5).
    assert verify_bundle(d, root_fingerprint=authority.root_fingerprint).attestation \
        == "ATTESTED"

    leaves = _read_leaves(d)
    _write_leaves(d, leaves[1:])  # drop the earliest leaf (seq 1)
    r = verify_bundle(d, root_fingerprint=authority.root_fingerprint)
    assert not r.ok
    assert r.attestation is None
    assert "suppressed" in r.error


def test_whole_log_deletion_of_certified_bundle_fails(tmp_path, signer, authority):
    d = _certified_bundle(tmp_path, signer, authority)
    (d / "manifest.json").write_text(
        json.dumps(_signed_manifest(signer, 1, 5, 5)), encoding="utf-8")
    _write_leaves(d, [])  # keep the seal + signed manifest, drop every leaf
    r = verify_bundle(d, root_fingerprint=authority.root_fingerprint)
    assert not r.ok
    assert "suppressed" in r.error


def test_empty_bundle_with_unresolvable_manifest_key_does_not_fail(
        tmp_path, signer, authority):
    """Downgrade-never-fail: an intact EMPTY bundle whose signed manifest
    names a key absent from keys.json must not FAIL — it caps at
    SELF-ATTESTED. Reported by the WS-4 adversarial review."""
    d = tmp_path / "empty"
    d.mkdir()
    stranger = _Signer()
    (d / "leaves.jsonl").write_text("", encoding="utf-8")
    (d / "seals.jsonl").write_text("", encoding="utf-8")
    (d / "keys.json").write_text(json.dumps([]), encoding="utf-8")
    (d / "manifest.json").write_text(
        json.dumps(_signed_manifest(stranger, None, None, 0)), encoding="utf-8")
    r = verify_bundle(d, root_fingerprint=authority.root_fingerprint)
    assert r.ok, r.error
    assert r.attestation == "SELF-ATTESTED"
    assert any("not in the bundle" in w for w in r.warnings)


def test_wipe_all_leaves_and_strip_key_is_not_attested(tmp_path, signer, authority):
    """The forge the second-round review found: a certified bundle emptied of
    every leaf and seal, with the deployment key stripped from keys.json so
    the signed manifest can no longer be verified, must NOT attest — an
    unverifiable manifest caps at SELF-ATTESTED, it does not vacuously pass."""
    d = _certified_bundle(tmp_path, signer, authority)  # signed manifest, 5 leaves
    (d / "leaves.jsonl").write_text("", encoding="utf-8")
    (d / "seals.jsonl").write_text("", encoding="utf-8")
    (d / "keys.json").write_text(json.dumps([]), encoding="utf-8")  # strip the key
    r = verify_bundle(d, root_fingerprint=authority.root_fingerprint)
    assert r.ok, r.error
    assert r.attestation == "SELF-ATTESTED"
    assert any("verifiable signed manifest" in x for x in r.attestation_reasons)


def test_prefix_deletion_with_manifest_dropped_is_not_attested(
        tmp_path, signer, authority):
    """Companion to the suppression test: even if the attacker DROPS the
    signed manifest to dodge the range cross-check, the missing trusted
    manifest caps the claim at SELF-ATTESTED — never ATTESTED."""
    d = _certified_bundle(tmp_path, signer, authority)
    leaves = _read_leaves(d)
    _write_leaves(d, leaves[1:])                 # suppress the earliest leaf
    (d / "manifest.json").write_text(
        json.dumps({"leaf_count": 4}), encoding="utf-8")  # unsigned, attacker-set
    r = verify_bundle(d, root_fingerprint=authority.root_fingerprint)
    assert r.ok, r.error  # the remaining leaves are internally consistent
    assert r.attestation == "SELF-ATTESTED"
    assert r.attestation != "ATTESTED"


def test_prefix_deletion_with_attacker_resigned_manifest_is_not_attested(
        tmp_path, signer, authority):
    """THE forge this fix closes. The attacker keeps the GENUINE, cert-covered
    leaves (still signed by the deployment key), deletes the earliest one, and
    re-signs a NEW manifest committing the truncated range — with a self-minted
    key appended to keys.json so the manifest signature verifies. The leaf/seal
    coverage loops only see the genuine signer and pass, and the committed range
    matches the truncated set, so nothing but the manifest-signer binding stops
    this. It must cap at SELF-ATTESTED, never ATTESTED."""
    d = _certified_bundle(tmp_path, signer, authority)
    # Sanity: intact certified bundle attests.
    assert verify_bundle(d, root_fingerprint=authority.root_fingerprint).attestation \
        == "ATTESTED"

    evil = _Signer()
    leaves = _read_leaves(d)
    _write_leaves(d, leaves[1:])  # drop seq 1; keep the genuine, signed 2..5
    # keys.json keeps the genuine deployment key (so leaves/seal still verify)
    # AND carries the attacker key (so their manifest verifies).
    (d / "keys.json").write_text(json.dumps([
        {"key_id": signer.key_id, "public_key_pem": signer.public_key_pem,
         "scope": "audit"},
        {"key_id": evil.key_id, "public_key_pem": evil.public_key_pem},
    ]), encoding="utf-8")
    # Attacker re-signs a manifest matching the truncated set (first_seq now 2).
    (d / "manifest.json").write_text(
        json.dumps(_signed_manifest(evil, 2, 5, 4)), encoding="utf-8")

    r = verify_bundle(d, root_fingerprint=authority.root_fingerprint)
    assert r.ok, r.error  # the surviving leaves are internally consistent
    assert r.attestation == "SELF-ATTESTED"
    assert r.attestation != "ATTESTED"
    assert any("certified deployment key" in x for x in r.attestation_reasons)


def test_stripped_seals_with_committed_seal_count_fails(
        tmp_path, signer, authority):
    """The signed manifest commits seal_count; stripping every Merkle seal
    from a certified bundle (removing the tamper-evidence the seals provide)
    while leaving the leaves and manifest intact must FAIL on the count
    cross-check, not slip through as ATTESTED."""
    d = _certified_bundle(tmp_path, signer, authority)
    (d / "manifest.json").write_text(
        json.dumps(_signed_manifest(signer, 1, 5, 5, seal_count=1,
                                    leaves=_read_leaves(d))),
        encoding="utf-8")
    # Sanity: with the seal present, seal_count matches and it attests.
    assert verify_bundle(d, root_fingerprint=authority.root_fingerprint).attestation \
        == "ATTESTED"

    (d / "seals.jsonl").write_text("", encoding="utf-8")  # strip every seal
    r = verify_bundle(d, root_fingerprint=authority.root_fingerprint)
    assert not r.ok
    assert "seal_count" in r.error and "suppressed" in r.error


def test_noninteger_leaf_count_in_signed_manifest_fails_closed(
        tmp_path, signer, authority):
    """A verifiable signed manifest with a non-numeric leaf_count is hostile
    input: it must fail the cross-check closed (FAILED), never raise a
    ValueError out of verify_bundle."""
    d = _certified_bundle(tmp_path, signer, authority)
    (d / "manifest.json").write_text(
        json.dumps(_signed_manifest(signer, 1, 5, "five")), encoding="utf-8")
    r = verify_bundle(d, root_fingerprint=authority.root_fingerprint)  # must not raise
    assert not r.ok
    assert "leaf_count" in r.error


def test_root_fingerprint_override_is_flagged(tmp_path, signer, authority):
    """Machine-readable trust signal: a caller-supplied root that differs from
    the built-in pin is recorded on the result (and surfaced in --json), so a
    consumer gating on attestation can tell an override apart from the
    published root."""
    d = _certified_bundle(tmp_path, signer, authority)
    r = verify_bundle(d, root_fingerprint=authority.root_fingerprint)
    assert r.attestation == "ATTESTED"
    assert r.root_fingerprint_overridden is True
    assert r.evidence_root_fingerprint == authority.root_fingerprint


def test_no_override_is_not_flagged(tmp_path, signer):
    """The default pin (module EVIDENCE_ROOT_FINGERPRINT, None pre-ceremony)
    is not an override."""
    d = _build_bundle(tmp_path, signer)
    r = verify_bundle(d)
    assert r.root_fingerprint_overridden is False
    assert r.evidence_root_fingerprint is None


# ---------------------------------------------------------------------------
# WS-4 — record-suppression via duplicate-seq refill and malformed indices.
# These forges keep the GENUINE deployment-key-signed manifest and every
# genuine record signature, so the manifest-signer binding does not catch
# them — the record-set count must be bound to DISTINCT seqs, and hostile
# index fields must fail closed rather than crash. Found by adversarial review
# of the first-round fix.
# ---------------------------------------------------------------------------


def _windowed_certified_bundle(tmp_path, signer, authority, present, seal_range):
    """A range-filtered ("windowed") certified export: only ``present`` leaf
    seqs ship, with a boundary seal committing ``seal_range`` (which may extend
    past the present leaves) and a real-server-shaped signed manifest that
    commits first_seq/last_seq/leaf_count/seal_count."""
    base_ts = datetime(2026, 6, 17, 19, 0, 0, tzinfo=timezone.utc)
    leaves = []
    prev = _GENESIS
    for seq in present:
        body = {
            "leaf_id": f"L{seq:025d}", "decision_id": f"D{seq:025d}",
            "created_at": (base_ts + timedelta(seconds=seq)).isoformat(),
            "user_id": 1, "team_id": None, "agent_did": "agent-x",
            "action": "send_email", "target": "crm:1", "outcome": "allow",
            "payload_sha256": hashlib.sha256(str(seq).encode()).hexdigest(),
            "votes": [{"name": "pi", "verdict": "allow", "severity": "none"}],
            "bundle_version": "builtin:v0", "resolution": "builtin/strict-v0",
            "prev_leaf_hash": prev,
        }
        lh = hashlib.sha256(_canonical(body)).hexdigest()
        rec = dict(body)
        rec.update(seq=seq, leaf_hash=lh, sig=signer.sign(lh.encode("ascii")),
                   signer_key_id=signer.key_id, seal_id="S0")
        leaves.append(rec)
        prev = lh

    first, last = seal_range
    seal_body = {
        "seal_id": "S0", "first_seq": first, "last_seq": last,
        # boundary seal: the verifier does not recompute a partial seal's root
        "merkle_root": _merkle_root([leaf["leaf_hash"] for leaf in leaves]),
        "prev_seal_hash": _GENESIS,
        "sealed_at": (base_ts + timedelta(minutes=1)).isoformat(),
    }
    sh = hashlib.sha256(_canonical(seal_body)).hexdigest()
    seal = dict(seal_body)
    seal.update(seal_hash=sh, sig=signer.sign(sh.encode("ascii")),
                signer_key_id=signer.key_id)

    d = tmp_path / "windowed"
    d.mkdir()
    _write_leaves(d, leaves)
    (d / "seals.jsonl").write_text(json.dumps(seal, sort_keys=True) + "\n",
                                   encoding="utf-8")
    (d / "keys.json").write_text(json.dumps(
        [{"key_id": signer.key_id, "public_key_pem": signer.public_key_pem,
          "scope": "audit"}]), encoding="utf-8")
    authority.write_chain(d, authority.deployment_cert(signer))
    (d / "manifest.json").write_text(json.dumps(_signed_manifest(
        signer, min(present), max(present), len(present), seal_count=1,
        leaves=leaves)),
        encoding="utf-8")
    return d


def test_genuine_windowed_export_still_attests(tmp_path, signer, authority):
    """Guard against over-restriction: a legitimate range-filtered export
    (leaves 3..5, a boundary seal committing 1..5) must still reach ATTESTED —
    the anti-suppression checks must not break filtered exports."""
    d = _windowed_certified_bundle(tmp_path, signer, authority,
                                   present=[3, 4, 5], seal_range=(1, 5))
    r = verify_bundle(d, root_fingerprint=authority.root_fingerprint)
    assert r.ok, r.error
    assert r.attestation == "ATTESTED"


def test_interior_deletion_padded_with_duplicate_leaf_fails(
        tmp_path, signer, authority):
    """Duplicate-seq refill: delete a genuine interior leaf and pad the record
    count back with a copy of a surviving genuine leaf, so first_seq/last_seq/
    leaf_count all still match the GENUINE signed manifest. Must FAIL on the
    duplicate seq — not be laundered as ATTESTED. (Found by adversarial review.)"""
    d = _certified_bundle(tmp_path, signer, authority)  # leaves 1..5, seal, manifest by G
    # Sanity: the genuine bundle attests.
    assert verify_bundle(d, root_fingerprint=authority.root_fingerprint).attestation \
        == "ATTESTED"

    leaves = _read_leaves(d)
    survivors = [leaf for leaf in leaves if leaf["seq"] != 3]  # drop interior seq 3
    survivors.append(dict(survivors[-1]))             # pad with a duplicate of seq 5
    _write_leaves(d, survivors)                       # present seqs: 1,2,4,5,5
    (d / "seals.jsonl").write_text("", encoding="utf-8")  # drop the Merkle seal too
    # manifest.json is the GENUINE one (signed by the certified key), untouched.
    r = verify_bundle(d, root_fingerprint=authority.root_fingerprint)
    assert not r.ok
    assert r.attestation is None
    assert "duplicate leaf seq" in r.error


def test_windowed_interior_deletion_with_duplicate_fails(
        tmp_path, signer, authority):
    """The boundary-seal variant: in a windowed export, an interior leaf covered
    only by a boundary seal is deleted and the count padded with a duplicate.
    The boundary-seal leniency would wave the hole through, so the duplicate-seq
    rejection is what must catch it."""
    d = _windowed_certified_bundle(tmp_path, signer, authority,
                                   present=[3, 4, 5], seal_range=(1, 5))
    assert verify_bundle(d, root_fingerprint=authority.root_fingerprint).attestation \
        == "ATTESTED"

    leaves = _read_leaves(d)
    survivors = [leaf for leaf in leaves if leaf["seq"] != 4]  # suppress interior seq 4
    survivors.append(dict(survivors[-1]))             # pad with a duplicate of seq 5
    _write_leaves(d, survivors)                       # present seqs: 3,5,5
    r = verify_bundle(d, root_fingerprint=authority.root_fingerprint)
    assert not r.ok
    assert "duplicate leaf seq" in r.error


def test_content_substitution_into_deleted_slot_fails(tmp_path, signer, authority):
    """Boundary-seal content substitution (same-bundle variant): in a gapped
    windowed export whose boundary seal's Merkle root is not recomputed, an
    attacker deletes a genuine leaf and drops a COPY of another genuine leaf
    into the freed seq slot (relabelling seq, which is not in the signed body).
    seqs stay distinct and the count/manifest are untouched, so only the
    duplicate-leaf_hash invariant catches it. (Found by adversarial review;
    the general cross-bundle case still needs a server-side content digest.)"""
    d = _windowed_certified_bundle(tmp_path, signer, authority,
                                   present=[3, 5, 7], seal_range=(1, 9))
    # Sanity: the genuine gapped export attests.
    assert verify_bundle(d, root_fingerprint=authority.root_fingerprint).attestation \
        == "ATTESTED"

    leaves = _read_leaves(d)
    by_seq = {leaf["seq"]: leaf for leaf in leaves}
    substitute = dict(by_seq[3])   # byte-for-byte copy of the genuine seq-3 leaf
    substitute["seq"] = 5          # relabel into the deleted seq-5 slot
    rebuilt = [by_seq[3], substitute, by_seq[7]]  # genuine 5 replaced by copy-of-3
    _write_leaves(d, rebuilt)
    r = verify_bundle(d, root_fingerprint=authority.root_fingerprint)
    assert not r.ok
    assert "duplicate leaf_hash" in r.error


def test_malformed_leaf_seq_fails_closed_not_crash(tmp_path, signer, authority):
    """A non-integer leaf seq is hostile bundle input: verify_bundle must return
    a FAILED result, never raise a ValueError/TypeError out of verification."""
    d = _certified_bundle(tmp_path, signer, authority)
    leaves = _read_leaves(d)
    leaves[2]["seq"] = "five"
    _write_leaves(d, leaves)
    r = verify_bundle(d, root_fingerprint=authority.root_fingerprint)  # must not raise
    assert not r.ok
    assert "non-integer leaf seq" in r.error


def test_malformed_seal_range_fails_closed_not_crash(tmp_path, signer, authority):
    """A non-integer seal first_seq/last_seq behind a valid seal hash+signature
    must fail closed, not crash the sort or the range arithmetic."""
    d = _certified_bundle(tmp_path, signer, authority)
    seal = json.loads((d / "seals.jsonl").read_text().splitlines()[0])
    seal["first_seq"] = "five"
    # Re-hash and re-sign so it passes the seal_hash + signature checks and
    # reaches the integer coercion.
    body = {k: seal[k] for k in _SEAL_BODY_FIELDS}
    seal["seal_hash"] = hashlib.sha256(_canonical(body)).hexdigest()
    seal["sig"] = signer.sign(seal["seal_hash"].encode("ascii"))
    (d / "seals.jsonl").write_text(json.dumps(seal, sort_keys=True) + "\n",
                                   encoding="utf-8")
    r = verify_bundle(d, root_fingerprint=authority.root_fingerprint)  # must not raise
    assert not r.ok
    assert "non-integer seal range" in r.error


def test_non_object_leaf_record_fails_closed(tmp_path, signer, authority):
    """A leaves.jsonl line that is not a JSON object (a bare scalar/list) is
    malformed input; verify must return FAILED, not raise reaching .get()."""
    d = _certified_bundle(tmp_path, signer, authority)
    (d / "leaves.jsonl").write_text("123\n", encoding="utf-8")
    r = verify_bundle(d, root_fingerprint=authority.root_fingerprint)  # must not raise
    assert not r.ok


def test_non_object_manifest_degrades_not_crash(tmp_path, signer, authority):
    """A manifest.json that is a JSON array/scalar (not an object) must not
    crash; it is treated as no signed manifest → SELF-ATTESTED."""
    d = _certified_bundle(tmp_path, signer, authority)
    (d / "manifest.json").write_text(json.dumps([1, 2, 3]), encoding="utf-8")
    r = verify_bundle(d, root_fingerprint=authority.root_fingerprint)  # must not raise
    assert r.ok, r.error
    assert r.attestation == "SELF-ATTESTED"


def test_non_object_certificates_degrades_to_self_attested(
        tmp_path, signer, authority):
    """A certificates.json that is not an object must not crash; the chain is
    treated as absent → SELF-ATTESTED."""
    d = _certified_bundle(tmp_path, signer, authority)
    (d / "certificates.json").write_text(json.dumps("pwned"), encoding="utf-8")
    r = verify_bundle(d, root_fingerprint=authority.root_fingerprint)  # must not raise
    assert r.ok, r.error
    assert r.attestation == "SELF-ATTESTED"


def test_unhashable_signer_key_id_fails_closed(tmp_path, signer, authority):
    """A signer_key_id that is an unhashable JSON list would raise TypeError at
    the pubkeys dict lookup; the fail-closed backstop must return FAILED."""
    d = _certified_bundle(tmp_path, signer, authority)
    leaves = _read_leaves(d)
    leaves[0]["signer_key_id"] = ["not", "hashable"]
    _write_leaves(d, leaves)
    r = verify_bundle(d, root_fingerprint=authority.root_fingerprint)  # must not raise
    assert not r.ok


def test_huge_seal_range_does_not_hang(tmp_path, signer, authority):
    """A seal committing an enormous range (hostile last_seq) must not make the
    verifier iterate range(first_seq, last_seq); it resolves in bounded time.

    Uses an unsigned-manifest bundle so the density truncation heuristic still
    fires: a signed leaves_digest would (correctly) bind the present set and
    make the huge seal a legitimate boundary seal — see the windowed-export
    guards below."""
    d = _build_bundle(tmp_path, signer)  # dense leaves 1..5, unsigned manifest
    seal_body = {
        "seal_id": "S0", "first_seq": 1, "last_seq": 10 ** 15,
        "merkle_root": "00" * 32, "prev_seal_hash": _GENESIS,
        "sealed_at": "2026-06-17T19:01:00+00:00",
    }
    sh = hashlib.sha256(_canonical(seal_body)).hexdigest()
    seal = dict(seal_body)
    seal.update(seal_hash=sh, sig=signer.sign(sh.encode("ascii")),
                signer_key_id=signer.key_id)
    (d / "seals.jsonl").write_text(json.dumps(seal, sort_keys=True) + "\n",
                                   encoding="utf-8")
    r = verify_bundle(d, root_fingerprint=authority.root_fingerprint)  # must return
    assert not r.ok
    assert "truncated log" in r.error


def test_malformed_cert_internal_degrades_to_self_attested(
        tmp_path, signer, authority):
    """A structurally-broken certificate chain (e.g. a non-string root PEM)
    must degrade to SELF-ATTESTED, never crash or FAIL an intact bundle."""
    d = _certified_bundle(tmp_path, signer, authority)
    (d / "certificates.json").write_text(json.dumps({
        "root_public_key_pem": {"not": "a string"},
        "issuing_certificates": [{"garbage": True}],
        "deployment_certificates": "not-a-list",
    }), encoding="utf-8")
    r = verify_bundle(d, root_fingerprint=authority.root_fingerprint)  # must not raise
    assert r.ok, r.error
    assert r.attestation == "SELF-ATTESTED"


# ---------------------------------------------------------------------------
# WS-4 — server-committed content digest (leaves_digest). Closes the general
# cross-bundle content-substitution forge main's duplicate-leaf_hash check left
# open, requires the digest for ATTESTED, and keeps genuine windowed exports
# (sparse, dense-prefix, and real per-batch interior seals) attesting.
# ---------------------------------------------------------------------------


def _genuine_leaf(signer, seq, *, target="crm:1", action="send_email", tag="x"):
    """A standalone genuine leaf signed by `signer` (mirrors the windowed body)."""
    base_ts = datetime(2026, 6, 17, 19, 0, 0, tzinfo=timezone.utc)
    body = {
        "leaf_id": f"L{tag}{seq:024d}", "decision_id": f"D{tag}{seq:024d}",
        "created_at": (base_ts + timedelta(seconds=seq)).isoformat(),
        "user_id": 1, "team_id": None, "agent_did": "agent-x",
        "action": action, "target": target, "outcome": "allow",
        "payload_sha256": hashlib.sha256(f"{tag}{seq}".encode()).hexdigest(),
        "votes": [{"name": "pi", "verdict": "allow", "severity": "none"}],
        "bundle_version": "builtin:v0", "resolution": "builtin/strict-v0",
        "prev_leaf_hash": _GENESIS,
    }
    lh = hashlib.sha256(_canonical(body)).hexdigest()
    rec = dict(body)
    rec.update(seq=seq, leaf_hash=lh, sig=signer.sign(lh.encode("ascii")),
               signer_key_id=signer.key_id, seal_id="S0")
    return rec


def test_cross_bundle_distinct_leaf_splice_caught_by_leaves_digest(
        tmp_path, signer, authority):
    """The residual cross-bundle forge the duplicate-leaf_hash check does NOT
    catch: splice a genuine, certified-key-signed leaf from a SECOND export
    (distinct body → distinct leaf_hash) into a deleted interior slot of a
    windowed export. seqs stay distinct, leaf_hashes stay distinct, count and
    endpoints unchanged — only the manifest's signed leaves_digest catches that
    the (seq, leaf_hash) set changed. Must FAIL, not ATTEST."""
    d = _windowed_certified_bundle(tmp_path, signer, authority,
                                   present=[3, 5, 7], seal_range=(1, 9))
    assert verify_bundle(d, root_fingerprint=authority.root_fingerprint).attestation \
        == "ATTESTED"

    leaves = _read_leaves(d)
    by_seq = {leaf["seq"]: leaf for leaf in leaves}
    spliced = _genuine_leaf(signer, 5, target="bank:evil", action="wire_transfer",
                            tag="9")  # same certified key, DIFFERENT body
    assert spliced["leaf_hash"] != by_seq[5]["leaf_hash"]  # genuinely different record
    _write_leaves(d, [by_seq[3], spliced, by_seq[7]])
    # The genuine signed manifest is left in place (the attacker holds no
    # certified key to re-sign it); its leaves_digest still commits the real set.
    r = verify_bundle(d, root_fingerprint=authority.root_fingerprint)
    assert not r.ok
    assert r.attestation is None
    assert "leaves_digest" in r.error


def test_cross_bundle_splice_resigned_by_uncertified_key_is_not_attested(
        tmp_path, signer, authority):
    """Even if the attacker adds their own uncertified key and re-signs a manifest
    committing a digest over the spliced set, the manifest signer is not a
    certified deployment key → SELF-ATTESTED, never ATTESTED."""
    d = _windowed_certified_bundle(tmp_path, signer, authority,
                                   present=[3, 5, 7], seal_range=(1, 9))
    leaves = _read_leaves(d)
    by_seq = {leaf["seq"]: leaf for leaf in leaves}
    spliced = _genuine_leaf(signer, 5, target="bank:evil", tag="9")
    new_leaves = [by_seq[3], spliced, by_seq[7]]
    _write_leaves(d, new_leaves)
    evil = _Signer()
    (d / "keys.json").write_text(json.dumps([
        {"key_id": signer.key_id, "public_key_pem": signer.public_key_pem, "scope": "audit"},
        {"key_id": evil.key_id, "public_key_pem": evil.public_key_pem, "scope": "audit"},
    ]), encoding="utf-8")
    (d / "manifest.json").write_text(
        json.dumps(_signed_manifest(evil, 3, 7, 3, seal_count=1, leaves=new_leaves)),
        encoding="utf-8")
    r = verify_bundle(d, root_fingerprint=authority.root_fingerprint)
    assert r.ok, r.error
    assert r.attestation == "SELF-ATTESTED"
    assert any("certified deployment key" in x for x in r.attestation_reasons)


def test_certified_bundle_without_leaves_digest_is_self_attested(
        tmp_path, signer, authority):
    """Backward-compat gate (decision: REQUIRE the digest). A pre-digest
    certified bundle — signed manifest, but no leaves_digest — cannot reach
    ATTESTED; it still verifies as SELF-ATTESTED (never a hard failure)."""
    d = _build_bundle(tmp_path, signer)
    authority.write_chain(d, authority.deployment_cert(signer))
    (d / "manifest.json").write_text(
        json.dumps(_signed_manifest(signer, 1, 5, 5)),  # no leaves → no digest
        encoding="utf-8")
    r = verify_bundle(d, root_fingerprint=authority.root_fingerprint)
    assert r.ok, r.error
    assert r.attestation == "SELF-ATTESTED"
    assert any("leaves_digest" in x for x in r.attestation_reasons)


def test_dense_prefix_windowed_export_still_attests(tmp_path, signer, authority):
    """False-negative guard: a windowed export whose present seqs are a
    CONTIGUOUS prefix of a seal batch (leaves 1..3, boundary seal 1..9) must
    ATTEST. The density truncation heuristic must defer to the signed
    leaves_digest, which already binds the present set — otherwise an intact
    certified export is wrongly reported FAILED as 'truncated log'."""
    d = _windowed_certified_bundle(tmp_path, signer, authority,
                                   present=[1, 2, 3], seal_range=(1, 9))
    r = verify_bundle(d, root_fingerprint=authority.root_fingerprint)
    assert r.ok, r.error
    assert r.attestation == "ATTESTED"


def test_interior_per_batch_seals_windowed_export_attests(tmp_path, signer, authority):
    """False-negative guard: the server ships EVERY seal overlapping the window,
    so a sparse tenant export carries real per-batch INTERIOR seals sitting
    entirely inside [bundle_min, bundle_max] that cover other tenants' (absent)
    seqs. With a signed leaves_digest binding the present set, those must not read
    as 'deleted leaf' — the export must ATTEST."""
    d = tmp_path / "interior-seals"
    d.mkdir()
    present = [2, 5, 8, 11]  # sparse: other tenants own the gaps
    leaves = [_genuine_leaf(signer, s) for s in present]
    base_ts = datetime(2026, 6, 17, 19, 0, 0, tzinfo=timezone.utc)
    seals = []
    prev_seal = _GENESIS
    for i, (fs, ls) in enumerate([(1, 3), (4, 6), (7, 9), (10, 12)]):
        sb = {
            "seal_id": f"S{i}", "first_seq": fs, "last_seq": ls,
            "merkle_root": hashlib.sha256(f"batch-{fs}-{ls}".encode()).hexdigest(),
            "prev_seal_hash": prev_seal,
            "sealed_at": (base_ts + timedelta(minutes=i)).isoformat(),
        }
        sh = hashlib.sha256(_canonical(sb)).hexdigest()
        s = dict(sb)
        s.update(seal_hash=sh, sig=signer.sign(sh.encode("ascii")), signer_key_id=signer.key_id)
        seals.append(s)
        prev_seal = sh
    _write_leaves(d, leaves)
    (d / "seals.jsonl").write_text(
        "".join(json.dumps(s, sort_keys=True) + "\n" for s in seals), encoding="utf-8")
    (d / "keys.json").write_text(json.dumps(
        [{"key_id": signer.key_id, "public_key_pem": signer.public_key_pem, "scope": "audit"}]),
        encoding="utf-8")
    authority.write_chain(d, authority.deployment_cert(signer))
    (d / "manifest.json").write_text(
        json.dumps(_signed_manifest(signer, 2, 11, 4, seal_count=4, leaves=leaves)),
        encoding="utf-8")

    r = verify_bundle(d, root_fingerprint=authority.root_fingerprint)
    assert r.ok, r.error  # NOT a "deleted leaf" failure
    assert r.attestation == "ATTESTED"
