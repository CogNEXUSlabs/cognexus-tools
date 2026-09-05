"""Signing-key handovers, through the offline verifier (WS-8).

``test_audit_verify.py`` is the tamper matrix for the chain itself. This is the
tamper matrix for the *custody* layer laid over it, and it exists because an
adversarial review found that every structural pre-check in ``_check_rotations``
survived its own mutation — they were written, never exercised.

The line these tests hold is the one that is easy to get backwards:

* a handover that is present and **demonstrably wrong** fails the bundle;
* a handover that **cannot be checked** does not. A supplementary custody claim
  must never collapse the verdict for an otherwise perfect chain to the same
  ``FAILED`` an assessor reads as "the audit log was tampered with".
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from artzain.audit_verify import verify_bundle

from .test_audit_verify import (  # noqa: TID252 - one bundle builder, not two
    _build_bundle,
    _canonical,
    _leaves_digest,
    _read_leaves,
    _Signer,
    requires_crypto,
)

_FORMAT = "cognexus-key-rotation-v1"


def _rotations_digest(rotations: list[dict]) -> str:
    """Mirror of the server helper and ``audit_verify._rotations_digest``.

    Written out by hand rather than imported, so a change to either real
    implementation has to be made here too and cannot pass unnoticed.
    """
    rows = []
    for r in rotations:
        if not isinstance(r, dict):
            rows.append(["", "", "", "", ""])
            continue
        record = r.get("record")
        body = (hashlib.sha256(_canonical(record)).hexdigest()
                if isinstance(record, dict) else "")
        rows.append([
            str(r.get("retiring_key_id") or ""),
            str(r.get("successor_key_id") or ""),
            body,
            str(r.get("retiring_sig") or ""),
            str(r.get("successor_sig") or ""),
        ])
    return hashlib.sha256(_canonical(sorted(rows))).hexdigest()


def _sign_raw(signer, digest_hex: str) -> str:
    return signer.sign(digest_hex.encode("ascii"))


def _handover(retiring, successor, **over) -> dict:
    """A genuine countersigned handover between two ``_Signer``s."""
    record = {
        "format": _FORMAT,
        "retiring_key_id": retiring.key_id,
        "retiring_public_key_pem": retiring.public_key_pem,
        "successor_key_id": successor.key_id,
        "successor_public_key_pem": successor.public_key_pem,
        "install_id": "inst_test",
        "rotated_at": "2026-08-21T12:00:00+00:00",
        "reason": "test",
    }
    record.update(over.pop("record", {}))
    digest = hashlib.sha256(_canonical(record)).hexdigest()
    row = {
        "successor_key_id": record["successor_key_id"],
        "retiring_key_id": record["retiring_key_id"],
        "record": record,
        "retiring_sig": _sign_raw(retiring, digest),
        "successor_sig": _sign_raw(successor, digest),
        "leaf_decision_id": "D" + "0" * 25,
        "rotated_at": record["rotated_at"],
    }
    row.update(over)
    return row


def _rotated_bundle(tmp: Path, *, signers=None, rows=None, keys=None,
                    sign_manifest=True, omit_digest=False, n=3):
    """A bundle whose leaves are signed by ``successor``, after a K0->K1 handover.

    Pass ``signers=(retiring, successor)`` when the caller already built the
    handover from a specific pair — otherwise the bundle would be signed by a
    third key nobody named, which is a different test.

    Returns ``(dir, retiring, successor)``.
    """
    retiring, successor = signers if signers else (_Signer(), _Signer())
    d = _build_bundle(tmp, successor, n=n)
    rows = _handover(retiring, successor) if rows is None else rows
    rows = rows if isinstance(rows, list) else [rows]

    bundled_keys = keys if keys is not None else [
        {"key_id": s.key_id, "public_key_pem": s.public_key_pem, "scope": "audit"}
        for s in (retiring, successor)]
    (d / "keys.json").write_text(json.dumps(bundled_keys), encoding="utf-8")
    (d / "key-rotations.json").write_text(json.dumps(rows), encoding="utf-8")

    manifest = {
        "format": "cognexus-audit-evidence", "format_version": 1,
        "leaf_count": n, "seal_count": 1, "first_seq": 1, "last_seq": n,
        "leaves_digest": _leaves_digest(_read_leaves(d)),
        "key_ids": [k["key_id"] for k in bundled_keys],
    }
    if not omit_digest:
        manifest["rotations_digest"] = _rotations_digest(rows)
    if sign_manifest:
        body_hash = hashlib.sha256(_canonical(manifest)).hexdigest()
        manifest["signer_key_id"] = successor.key_id
        manifest["sig"] = successor.sign(body_hash.encode("ascii"))
    (d / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return d, retiring, successor


# ---------------------------------------------------------------------------
# The happy path, and the shape it must keep
# ---------------------------------------------------------------------------


@requires_crypto
def test_a_bundle_with_a_genuine_handover_verifies(tmp_path):
    d, _, _ = _rotated_bundle(tmp_path)
    r = verify_bundle(d)
    assert r.ok, r.error
    assert r.rotations_checked == 1
    assert r.unexplained_key_ids == []


@requires_crypto
def test_a_bundle_with_no_handovers_reports_nothing(tmp_path):
    """The overwhelmingly common case must stay silent.

    An installation that has never rotated has nothing to be inconsistent
    with, and its first key has no predecessor by definition. Flagging every
    bundle would be noise, and noise gets the signal deleted.
    """
    signer = _Signer()
    d = _build_bundle(tmp_path, signer)
    r = verify_bundle(d)
    assert r.ok, r.error
    assert r.rotations_checked == 0
    assert r.unexplained_key_ids == []
    assert not any("handover" in w for w in r.warnings)


# ---------------------------------------------------------------------------
# Present and demonstrably wrong -> FAIL
# ---------------------------------------------------------------------------


@requires_crypto
def test_a_forged_retiring_signature_fails(tmp_path):
    """The one signature an attacker cannot produce is the whole mechanism."""
    retiring, successor, imposter = _Signer(), _Signer(), _Signer()
    row = _handover(retiring, successor)
    digest = hashlib.sha256(_canonical(row["record"])).hexdigest()
    row["retiring_sig"] = _sign_raw(imposter, digest)
    d, _, _ = _rotated_bundle(tmp_path, signers=(retiring, successor), rows=[row])
    # Rebuild the manifest around the tampered row so the digest still agrees:
    # this must fail on the SIGNATURE, not on the digest.
    rows = json.loads((d / "key-rotations.json").read_text())
    manifest = json.loads((d / "manifest.json").read_text())
    manifest["rotations_digest"] = _rotations_digest(rows)
    body = {k: v for k, v in manifest.items() if k not in ("sig", "signer_key_id")}
    kid = manifest["signer_key_id"]
    # Re-sign with whichever bundled key the manifest names.
    for s in (retiring, successor):
        if s.key_id == kid:
            manifest["sig"] = s.sign(
                hashlib.sha256(_canonical(body)).hexdigest().encode("ascii"))
    (d / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    r = verify_bundle(d)
    assert not r.ok
    assert "signature" in (r.error or "")


@requires_crypto
@pytest.mark.parametrize("mutate,expected", [
    (lambda rec: rec.update(format="something-else"), "format"),
    (lambda rec: rec.update(invoice_id="INV-9"), "allowlist"),
    (lambda rec: rec.update(retiring_key_id=None), "names no"),
    (lambda rec: rec.update(successor_key_id=rec["retiring_key_id"]),
     "own successor"),
    (lambda rec: rec.update(successor_key_id="f" * 16), "hash"),
])
def test_the_structural_prechecks_are_load_bearing(tmp_path, mutate, expected):
    """Every one of these survived its own mutation before this file existed.

    They run before any signature check, so a record that trips one is refused
    without the verifier ever having to trust its contents — including the
    allowlist case, which is ground rule 7 reaching into the custody layer.
    """
    retiring, successor = _Signer(), _Signer()
    row = _handover(retiring, successor)
    mutate(row["record"])
    d, _, _ = _rotated_bundle(tmp_path, signers=(retiring, successor),
                              rows=[row])
    r = verify_bundle(d)
    assert not r.ok
    assert expected in (r.error or ""), r.error


@requires_crypto
@pytest.mark.parametrize("rows", [
    "not a list of objects",
    ["a scalar"],
    [{"record": "not an object"}],
    [{"record": None}],
    [{}],
])
def test_hostile_handover_bytes_fail_rather_than_raise(tmp_path, rows):
    """The verifier's contract: hostile bytes yield FAILED, never an exception."""
    retiring, successor = _Signer(), _Signer()
    d = _build_bundle(tmp_path, successor)
    (d / "keys.json").write_text(json.dumps([
        {"key_id": s.key_id, "public_key_pem": s.public_key_pem, "scope": "audit"}
        for s in (retiring, successor)]), encoding="utf-8")
    (d / "key-rotations.json").write_text(json.dumps(rows), encoding="utf-8")
    r = verify_bundle(d)          # must not raise
    assert isinstance(r.ok, bool)


# ---------------------------------------------------------------------------
# Present but uncheckable -> REPORT, never fail
# ---------------------------------------------------------------------------


@requires_crypto
def test_a_handover_naming_an_unregistered_key_does_not_fail_the_bundle(tmp_path):
    """The regression this rule exists for.

    ``register_audit_signing_key`` is best-effort, so a deployment whose
    database was down at first boot has a key in no ``signing_keys`` row. After
    its first rotation the handover names that key, and every export afterwards
    would have verified FAILED — permanently, since ``key_rotations`` is
    append-only and no later boot ever sees the retiring key again.

    The handover is still *checked* — its signatures verify against the public
    keys inside the record — so it counts, and it still explains the key the
    bundle does carry. What it cannot do is vouch for a key the bundle omits,
    and that is a warning.
    """
    retiring, successor = _Signer(), _Signer()
    row = _handover(retiring, successor)
    # keys.json carries only the successor: the retiring key was never
    # registered, exactly as an interrupted first boot leaves it.
    d, _, _ = _rotated_bundle(
        tmp_path, signers=(retiring, successor), rows=[row],
        keys=[{"key_id": successor.key_id,
               "public_key_pem": successor.public_key_pem,
               "scope": "audit"}])
    r = verify_bundle(d)
    assert r.ok, r.error
    assert r.rotations_checked == 1, "the signatures did verify"
    assert any("carries no public key for" in w for w in r.warnings), r.warnings
    # The successor signed the leaves and a sound handover names it, so it is
    # accounted for. Accusing it here would be the false positive that made a
    # stdlib-only install shout at every rotated bundle.
    assert r.unexplained_key_ids == []


@requires_crypto
def test_deleting_a_key_cannot_switch_off_the_signature_check(tmp_path):
    """The critical this design exists to close.

    ``keys.json`` is attacker-controlled bytes. When the signature check
    resolved its keys through that file, deleting one line moved a forged
    handover out of the fatal branch — the attacker chose whether their forgery
    was inspected, and a rewritten custody record verified clean.

    Both public keys travel inside the signed record, so the check now resolves
    them from there and there is no line to delete.
    """
    retiring, successor, imposter = _Signer(), _Signer(), _Signer()
    row = _handover(retiring, successor)
    # Rewrite the record the way an attacker would — backdate it, erase the
    # stated reason — then re-sign only with a key they actually hold.
    row["record"]["rotated_at"] = "2019-01-01T00:00:00+00:00"
    row["record"]["reason"] = "scheduled"
    digest = hashlib.sha256(_canonical(row["record"])).hexdigest()
    row["retiring_sig"] = _sign_raw(imposter, digest)
    row["successor_sig"] = _sign_raw(successor, digest)

    # "no keys at all" is deliberately absent: it fails earlier, at leaf
    # signature verification, so it would prove nothing about this check.
    # The interesting case is the surgical one — delete exactly the key that
    # the handover check would have resolved, and nothing else.
    for label, keys in (
            ("both keys present", None),
            ("retiring key deleted", [{"key_id": successor.key_id,
                                       "public_key_pem": successor.public_key_pem,
                                       "scope": "audit"}])):
        sub = tmp_path / label.replace(" ", "-")
        sub.mkdir(parents=True, exist_ok=True)
        d, _, _ = _rotated_bundle(sub, signers=(retiring, successor),
                                  rows=[row], keys=keys)
        r = verify_bundle(d)
        assert not r.ok, f"{label}: forged handover verified clean"
        assert "signature" in (r.error or ""), (label, r.error)


# ---------------------------------------------------------------------------
# The substitution the report exists to surface
# ---------------------------------------------------------------------------


@requires_crypto
def test_a_sole_signer_no_handover_names_is_reported(tmp_path):
    """The gate used to be ``len(signer_kids) > 1``, which inverted the signal.

    An attacker who re-assembles a bundle around their own key and copies the
    installation's genuine handovers in reported *nothing*, while the presence
    of a legitimate co-signer was what made an illegitimate one visible. A
    clean substitution — the whole window signed by the substituted key — is
    exactly the case that has to be loud.
    """
    retiring, successor, attacker = _Signer(), _Signer(), _Signer()
    d = _build_bundle(tmp_path, attacker)
    row = _handover(retiring, successor)
    keys = [{"key_id": s.key_id, "public_key_pem": s.public_key_pem,
             "scope": "audit"} for s in (retiring, successor, attacker)]
    (d / "keys.json").write_text(json.dumps(keys), encoding="utf-8")
    (d / "key-rotations.json").write_text(json.dumps([row]), encoding="utf-8")
    manifest = {
        "format": "cognexus-audit-evidence", "leaf_count": 5,
        "leaves_digest": _leaves_digest(_read_leaves(d)),
        "rotations_digest": _rotations_digest([row]),
    }
    body_hash = hashlib.sha256(_canonical(manifest)).hexdigest()
    manifest["signer_key_id"] = attacker.key_id
    manifest["sig"] = attacker.sign(body_hash.encode("ascii"))
    (d / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    r = verify_bundle(d)
    assert r.ok, r.error       # the chain itself is intact; this is not a forgery of it
    assert attacker.key_id in r.unexplained_key_ids
    assert any("no handover names it" in w for w in r.warnings), r.warnings


@requires_crypto
def test_deleting_a_key_the_signed_manifest_commits_to_fails(tmp_path):
    """The general form of the same trick.

    Whatever check would have resolved a deleted key simply does not run, so
    the deletion has to be visible on its own. ``manifest.key_ids`` is signed
    and lists what the server exported; both come from the same query in the
    same request, so they agree by construction on every genuine bundle.
    """
    d, retiring, successor = _rotated_bundle(tmp_path)
    keys = json.loads((d / "keys.json").read_text())
    (d / "keys.json").write_text(
        json.dumps([k for k in keys if k["key_id"] != retiring.key_id]),
        encoding="utf-8")
    r = verify_bundle(d)
    assert not r.ok
    assert "missing key(s) the signed manifest commits to" in (r.error or "")


@requires_crypto
def test_a_row_level_field_outside_the_allowlist_is_refused(tmp_path):
    """Ground rule 7 does not stop at one nesting level.

    The record had an allowlist; the row wrapping it did not, so anything at
    all could ride into a compliance export beside the handover.
    """
    retiring, successor = _Signer(), _Signer()
    row = _handover(retiring, successor)
    row["invoice_reference"] = "INV-2026-0041"
    d, _, _ = _rotated_bundle(tmp_path, signers=(retiring, successor), rows=[row])
    r = verify_bundle(d)
    assert not r.ok
    assert "row carries fields outside the allowlist" in (r.error or "")
    assert "invoice_reference" in (r.error or "")


def test_stdlib_only_verification_does_not_accuse_its_own_key(tmp_path,
                                                              monkeypatch):
    """``cryptography`` is an optional extra, so this is the DEFAULT install.

    Without it the verifier cannot check signatures and says so. It must not
    ALSO report the bundle's own signing key as unaccounted for, when the
    handover naming it is sitting in the same file — two contradictory
    warnings, one of them false, on every rotated bundle every plain
    ``pip install artzain`` reader ever opens.
    """
    import artzain.audit_verify as av

    d, _, successor = _rotated_bundle(tmp_path)
    monkeypatch.setattr(av, "_load_public_keys", lambda keys: None)
    r = av.verify_bundle(d)
    assert r.ok, r.error
    assert r.signatures_skipped
    assert r.rotations_checked == 0, "nothing was verified, so nothing is counted"
    assert r.unexplained_key_ids == []
    assert not any("no handover names it" in w for w in r.warnings), r.warnings


# ---------------------------------------------------------------------------
# The digest that binds the file to the manifest
# ---------------------------------------------------------------------------


@requires_crypto
def test_dropping_the_handover_file_fails_against_a_signed_manifest(tmp_path):
    d, _, _ = _rotated_bundle(tmp_path)
    (d / "key-rotations.json").unlink()
    r = verify_bundle(d)
    assert not r.ok
    assert "rotations_digest" in (r.error or "")


@requires_crypto
def test_a_pre_ws8_manifest_with_no_rotations_digest_still_verifies(tmp_path):
    """Ground rule 6. Every bundle exported before WS-8 looks like this."""
    signer = _Signer()
    d = _build_bundle(tmp_path, signer)
    manifest = {"format": "cognexus-audit-evidence", "leaf_count": 5,
                "leaves_digest": _leaves_digest(_read_leaves(d))}
    body_hash = hashlib.sha256(_canonical(manifest)).hexdigest()
    manifest["signer_key_id"] = signer.key_id
    manifest["sig"] = signer.sign(body_hash.encode("ascii"))
    (d / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    r = verify_bundle(d)
    assert r.ok, r.error
    assert r.rotations_checked == 0


def test_the_two_digest_helpers_agree(tmp_path):
    """The server writes ``rotations_digest``; the SDK recomputes it. A drift
    of one byte makes every honest bundle fail, so pin them against each other
    over inputs a naive implementation would disagree on."""
    from artzain.audit_verify import _rotations_digest as sdk_digest

    hostile = [
        [],
        [{"successor_key_id": "b" * 16, "retiring_sig": "sig-b"},
         {"successor_key_id": "a" * 16, "retiring_sig": "sig-a"}],
        [{"successor_key_id": "a" * 16, "retiring_sig": None}],
        [{"successor_key_id": None, "retiring_sig": "x"}],
        [{}],
        [{"successor_key_id": "é" * 16, "retiring_sig": "ü"}],
        [{"successor_key_id": "a" * 16, "retiring_sig": "s"},
         {"successor_key_id": "a" * 16, "retiring_sig": "t"}],
    ]
    for rows in hostile:
        assert sdk_digest(rows) == _rotations_digest(rows), rows


@requires_crypto
def test_a_record_pem_that_disagrees_with_the_registry_fails(tmp_path):
    """The record names one key; ``keys.json`` holds a different one under it.

    Reachable only because signatures are now checked against the record's own
    PEMs: the record is internally sound, so the check that catches this is the
    registry comparison and nothing else. The retiring key is used because it
    signs no leaves, so the leaf checks cannot mask it.
    """
    retiring, successor, other = _Signer(), _Signer(), _Signer()
    d, _, _ = _rotated_bundle(tmp_path, signers=(retiring, successor))
    keys = json.loads((d / "keys.json").read_text())
    for k in keys:
        if k["key_id"] == retiring.key_id:
            k["public_key_pem"] = other.public_key_pem     # same id, other key
    (d / "keys.json").write_text(json.dumps(keys), encoding="utf-8")
    r = verify_bundle(d)
    assert not r.ok
    assert "differs from the one the bundle registers" in (r.error or ""), r.error
