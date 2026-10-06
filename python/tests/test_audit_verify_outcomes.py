"""Every verdict of the offline verifier, pinned whole (survey row 71).

``verify_bundle`` is a security verifier: what it accepts and rejects, the
order its checks run in, and every word ``artzain audit verify`` prints are
its contract. The tamper-matrix tests (``test_audit_verify.py``,
``test_audit_verify_rotations.py``) assert the fact each one is about. This
file builds the bundles they build, one fault at a time, plus bundles with two
faults that show which check speaks first, and compares the *whole* outcome
with the one captured from the verifier before ``_verify_bundle_body`` was
split into steps:

* every field of the ``VerifyResult``. The counters record how far
  verification got before it stopped, so a check that moved before or after
  another shows up here even when the error message does not change;
* the report the command prints, line by line, and its exit status.

Key ids, the root fingerprint and the bundle's path differ on every run and
are replaced by placeholders (``<signer>``, ``<root-fp>``, ``<bundle>``).

The captured outcomes are in ``golden/audit-verify-outcomes.json``. After a
deliberate change of verdict or wording, recapture them with
``cd pypi-package && PYTHONPATH=src python -m tests.test_audit_verify_outcomes``
and review the diff.
"""

from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import io
import json
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Callable, Optional
from unittest import mock

import pytest

import artzain.audit_verify as av
import artzain.cli as cli
from artzain.audit_verify import _LEAF_BODY_FIELDS, _SEAL_BODY_FIELDS, _merkle_root

from .test_audit_verify import (  # noqa: TID252 - the tamper matrix's own builders
    _GENESIS,
    _HAVE_CRYPTO,
    _build_bundle,
    _canonical,
    _CertAuthority,
    _genuine_leaf,
    _leaves_digest,
    _read_leaves,
    _signed_manifest,
    _Signer,
    _windowed_certified_bundle,
    _write_leaves,
)
from .test_audit_verify_rotations import (  # noqa: TID252
    _handover,
    _rotated_bundle,
    _rotations_digest,
    _sign_raw,
)

pytestmark = pytest.mark.skipif(not _HAVE_CRYPTO, reason="cryptography not installed")

GOLDEN = Path(__file__).resolve().parent / "golden" / "audit-verify-outcomes.json"
RECAPTURE = "cd pypi-package && PYTHONPATH=src python -m tests.test_audit_verify_outcomes"


@dataclasses.dataclass
class _Case:
    path: Path
    #: Run-specific text (key ids, fingerprints) -> placeholder.
    labels: dict[str, str]
    #: Passed as ``root_fingerprint=`` and ``--root-fingerprint``.
    root: Optional[str] = None
    #: Patched in as the module's ``EVIDENCE_ROOT_FINGERPRINT``.
    pinned: Optional[str] = None
    #: Run as if ``cryptography`` were not installed.
    stdlib_only: bool = False


def _case(path: Path, *, root: Optional[str] = None, pinned: Optional[str] = None,
          stdlib_only: bool = False, authority: Optional[_CertAuthority] = None,
          **signers: _Signer) -> _Case:
    labels = {s.key_id: f"<{name}>" for name, s in signers.items()}
    if authority is not None:
        labels[authority.root_fingerprint] = "<root-fp>"
        labels[authority.root.key_id] = "<root>"
        labels[authority.issuing.key_id] = "<issuing>"
    return _Case(path, labels, root, pinned, stdlib_only)


_SCENARIOS: dict[str, Callable[[Path], _Case]] = {}


def _scenario(fn: Callable[[Path], _Case]) -> Callable[[Path], _Case]:
    _SCENARIOS[fn.__name__.lstrip("_")] = fn
    return fn


# -- building blocks -----------------------------------------------------------


def _keys(*signers: _Signer) -> list[dict]:
    return [{"key_id": s.key_id, "public_key_pem": s.public_key_pem, "scope": "audit"}
            for s in signers]


def _write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj), encoding="utf-8")


def _read_seals(d: Path) -> list[dict]:
    return [json.loads(line) for line in (d / "seals.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()]


def _write_seals(d: Path, seals: list[dict]) -> None:
    (d / "seals.jsonl").write_text(
        "".join(json.dumps(s, sort_keys=True) + "\n" for s in seals), encoding="utf-8")


def _sealed(body: dict, signer: _Signer) -> dict:
    """A seal over *body*, hashed and signed as the server does."""
    assert set(body) == set(_SEAL_BODY_FIELDS)
    sh = hashlib.sha256(_canonical(body)).hexdigest()
    seal = dict(body)
    seal.update(seal_hash=sh, sig=signer.sign(sh.encode("ascii")), signer_key_id=signer.key_id)
    return seal


def _resealed(seal: dict, signer: _Signer, **changes: Any) -> dict:
    body = {k: seal[k] for k in _SEAL_BODY_FIELDS}
    body.update(changes)
    return _sealed(body, signer)


def _rechained(leaves: list[dict], signer: _Signer, *, keep_label: bool = False) -> list[dict]:
    """Rebuild the hash chain over *leaves* and sign every one with *signer*."""
    prev = _GENESIS
    for leaf in leaves:
        leaf["prev_leaf_hash"] = prev
        body = {k: leaf[k] for k in _LEAF_BODY_FIELDS}
        leaf["leaf_hash"] = hashlib.sha256(_canonical(body)).hexdigest()
        leaf["sig"] = signer.sign(leaf["leaf_hash"].encode("ascii"))
        if not keep_label:
            leaf["signer_key_id"] = signer.key_id
        prev = leaf["leaf_hash"]
    return leaves


def _certified(tmp: Path, signer: _Signer, authority: _CertAuthority, **manifest: Any) -> Path:
    """``_build_bundle`` with a certificate chain and a signed, content-bound
    manifest (``seal_count`` included unless *manifest* says otherwise)."""
    d = _build_bundle(tmp, signer)
    authority.write_chain(d, authority.deployment_cert(signer))
    kw = {"seal_count": 1, "leaves": _read_leaves(d)}
    kw.update(manifest)
    first, last, count = kw.pop("first", 1), kw.pop("last", 5), kw.pop("count", 5)
    _write_json(d / "manifest.json", _signed_manifest(signer, first, last, count, **kw))
    return d


def _resign_manifest(d: Path, signer: _Signer, **changes: Any) -> None:
    manifest = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
    manifest.update(changes)
    body = {k: v for k, v in manifest.items() if k not in ("sig", "signer_key_id")}
    manifest["sig"] = signer.sign(hashlib.sha256(_canonical(body)).hexdigest().encode("ascii"))
    manifest["signer_key_id"] = signer.key_id
    _write_json(d / "manifest.json", manifest)


# -- reading the bundle --------------------------------------------------------


@_scenario
def _path_not_found(tmp: Path) -> _Case:
    return _case(tmp / "no-such-bundle")


@_scenario
def _leaf_record_not_an_object(tmp: Path) -> _Case:
    s = _Signer()
    d = _build_bundle(tmp, s)
    (d / "leaves.jsonl").write_text("123\n", encoding="utf-8")
    return _case(d, signer=s)


@_scenario
def _keys_json_unparseable(tmp: Path) -> _Case:
    s = _Signer()
    d = _build_bundle(tmp, s)
    (d / "keys.json").write_text("nope", encoding="utf-8")
    return _case(d, signer=s)


@_scenario
def _zip_bundle(tmp: Path) -> _Case:
    s = _Signer()
    d = _build_bundle(tmp, s)
    z = tmp / "bundle.zip"
    with zipfile.ZipFile(z, "w") as zf:
        for name in ("leaves.jsonl", "seals.jsonl", "keys.json", "manifest.json"):
            zf.write(d / name, name)
    return _case(z, signer=s)


# -- leaves ----------------------------------------------------------------------


@_scenario
def _clean(tmp: Path) -> _Case:
    s = _Signer()
    return _case(_build_bundle(tmp, s), signer=s)


@_scenario
def _clean_stdlib_only(tmp: Path) -> _Case:
    s = _Signer()
    return _case(_build_bundle(tmp, s), signer=s, stdlib_only=True)


@_scenario
def _leaf_seq_not_an_integer(tmp: Path) -> _Case:
    s, a = _Signer(), _CertAuthority()
    d = _certified(tmp, s, a)
    leaves = _read_leaves(d)
    leaves[2]["seq"] = "five"
    _write_leaves(d, leaves)
    return _case(d, root=a.root_fingerprint, authority=a, signer=s)


@_scenario
def _duplicate_leaf_seq(tmp: Path) -> _Case:
    s, a = _Signer(), _CertAuthority()
    d = _certified(tmp, s, a)
    survivors = [leaf for leaf in _read_leaves(d) if leaf["seq"] != 3]
    survivors.append(dict(survivors[-1]))
    _write_leaves(d, survivors)
    return _case(d, root=a.root_fingerprint, authority=a, signer=s)


@_scenario
def _leaf_hash_mismatch(tmp: Path) -> _Case:
    s = _Signer()
    d = _build_bundle(tmp, s)
    leaves = _read_leaves(d)
    leaves[2]["target"] = "crm:999"
    _write_leaves(d, leaves)
    return _case(d, signer=s)


@_scenario
def _duplicate_leaf_hash(tmp: Path) -> _Case:
    s, a = _Signer(), _CertAuthority()
    d = _windowed_certified_bundle(tmp, s, a, present=[3, 5, 7], seal_range=(1, 9))
    by_seq = {leaf["seq"]: leaf for leaf in _read_leaves(d)}
    copy = dict(by_seq[3])
    copy["seq"] = 5
    _write_leaves(d, [by_seq[3], copy, by_seq[7]])
    return _case(d, root=a.root_fingerprint, authority=a, signer=s)


@_scenario
def _chain_linkage_broken(tmp: Path) -> _Case:
    s = _Signer()
    d = _build_bundle(tmp, s)
    leaves = _read_leaves(d)
    leaves[1]["seq"], leaves[3]["seq"] = leaves[3]["seq"], leaves[1]["seq"]
    _write_leaves(d, leaves)
    return _case(d, signer=s)


@_scenario
def _seq_gap_then_deleted_leaf(tmp: Path) -> _Case:
    s = _Signer()
    d = _build_bundle(tmp, s)
    leaves = _read_leaves(d)
    del leaves[2]
    _write_leaves(d, leaves)
    return _case(d, signer=s)


@_scenario
def _no_public_key_for_leaf(tmp: Path) -> _Case:
    s = _Signer()
    d = _build_bundle(tmp, s)
    _write_json(d / "keys.json", [])
    return _case(d, signer=s)


@_scenario
def _bad_leaf_signature(tmp: Path) -> _Case:
    s = _Signer()
    d = _build_bundle(tmp, s)
    leaves = _read_leaves(d)
    leaves[1]["sig"] = _Signer().sign(leaves[1]["leaf_hash"].encode("ascii"))
    _write_leaves(d, leaves)
    return _case(d, signer=s)


@_scenario
def _wrong_key_for_leaf(tmp: Path) -> _Case:
    s, other = _Signer(), _Signer()
    d = _build_bundle(tmp, s)
    _write_json(d / "keys.json", [{"key_id": s.key_id, "public_key_pem": other.public_key_pem}])
    return _case(d, signer=s, other=other)


@_scenario
def _unhashable_leaf_signer(tmp: Path) -> _Case:
    s, a = _Signer(), _CertAuthority()
    d = _certified(tmp, s, a)
    leaves = _read_leaves(d)
    leaves[0]["signer_key_id"] = ["not", "hashable"]
    _write_leaves(d, leaves)
    return _case(d, root=a.root_fingerprint, authority=a, signer=s)


@_scenario
def _unhashable_leaf_signer_stdlib_only(tmp: Path) -> _Case:
    # The leaf checks never read the signer without cryptography; the set of
    # signers handed to the handover check is what trips over it, before any
    # seal is read.
    s = _Signer()
    d = _build_bundle(tmp, s)
    leaves = _read_leaves(d)
    leaves[0]["signer_key_id"] = ["not", "hashable"]
    _write_leaves(d, leaves)
    return _case(d, signer=s, stdlib_only=True)


# -- the signed manifest ---------------------------------------------------------


@_scenario
def _signed_manifest_stdlib_only(tmp: Path) -> _Case:
    s, a = _Signer(), _CertAuthority()
    d = _certified(tmp, s, a)
    return _case(d, root=a.root_fingerprint, stdlib_only=True, authority=a, signer=s)


@_scenario
def _signed_manifest_key_absent(tmp: Path) -> _Case:
    stranger, a = _Signer(), _CertAuthority()
    d = tmp / "empty"
    d.mkdir()
    (d / "leaves.jsonl").write_text("", encoding="utf-8")
    (d / "seals.jsonl").write_text("", encoding="utf-8")
    _write_json(d / "keys.json", [])
    _write_json(d / "manifest.json", _signed_manifest(stranger, None, None, 0))
    return _case(d, root=a.root_fingerprint, authority=a, stranger=stranger)


@_scenario
def _manifest_signature_invalid(tmp: Path) -> _Case:
    s, a = _Signer(), _CertAuthority()
    d = _certified(tmp, s, a)
    manifest = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
    manifest["leaf_count"] = 500
    _write_json(d / "manifest.json", manifest)
    return _case(d, root=a.root_fingerprint, authority=a, signer=s)


@_scenario
def _certified_without_signed_manifest(tmp: Path) -> _Case:
    s, a = _Signer(), _CertAuthority()
    d = _build_bundle(tmp, s)
    a.write_chain(d, a.deployment_cert(s))
    return _case(d, root=a.root_fingerprint, authority=a, signer=s)


@_scenario
def _unsigned_manifest_counts_unchecked(tmp: Path) -> _Case:
    # What an unsigned manifest claims binds nothing, so it is not compared
    # with the records present.
    s = _Signer()
    d = _build_bundle(tmp, s)
    _write_json(d / "manifest.json", {"first_seq": 9, "last_seq": 99, "leaf_count": 500,
                                      "seal_count": 7, "leaves_digest": "00" * 32})
    return _case(d, signer=s)


@_scenario
def _unhashable_manifest_signer(tmp: Path) -> _Case:
    s, a = _Signer(), _CertAuthority()
    d = _certified(tmp, s, a)
    manifest = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
    manifest["signer_key_id"] = ["not", "hashable"]
    _write_json(d / "manifest.json", manifest)
    return _case(d, root=a.root_fingerprint, authority=a, signer=s)


# -- the keys the manifest commits, and the handovers ------------------------------


@_scenario
def _committed_key_missing(tmp: Path) -> _Case:
    d, retiring, successor = _rotated_bundle(tmp)
    _write_json(d / "keys.json", _keys(successor))
    return _case(d, retiring=retiring, successor=successor)


@_scenario
def _committed_key_ids_not_a_list(tmp: Path) -> _Case:
    s = _Signer()
    d = _build_bundle(tmp, s)
    _write_json(d / "manifest.json", {"leaf_count": 5, "key_ids": "not-a-list",
                                      "leaves_digest": _leaves_digest(_read_leaves(d))})
    _resign_manifest(d, s)
    return _case(d, signer=s)


@_scenario
def _rotations_digest_mismatch(tmp: Path) -> _Case:
    d, retiring, successor = _rotated_bundle(tmp)
    (d / "key-rotations.json").unlink()
    return _case(d, retiring=retiring, successor=successor)


@_scenario
def _handovers_with_untrusted_manifest(tmp: Path) -> _Case:
    d, retiring, successor = _rotated_bundle(tmp, sign_manifest=False)
    return _case(d, retiring=retiring, successor=successor)


@_scenario
def _handover_row_outside_allowlist(tmp: Path) -> _Case:
    retiring, successor = _Signer(), _Signer()
    row = _handover(retiring, successor)
    row["invoice_reference"] = "INV-2026-0041"
    d, _, _ = _rotated_bundle(tmp, signers=(retiring, successor), rows=[row])
    return _case(d, retiring=retiring, successor=successor)


@_scenario
def _handover_forged_retiring_signature(tmp: Path) -> _Case:
    retiring, successor, imposter = _Signer(), _Signer(), _Signer()
    row = _handover(retiring, successor)
    digest = hashlib.sha256(_canonical(row["record"])).hexdigest()
    row["retiring_sig"] = _sign_raw(imposter, digest)
    d, _, _ = _rotated_bundle(tmp, signers=(retiring, successor), rows=[row])
    return _case(d, retiring=retiring, successor=successor, imposter=imposter)


@_scenario
def _handover_names_unregistered_key(tmp: Path) -> _Case:
    retiring, successor = _Signer(), _Signer()
    row = _handover(retiring, successor)
    d, _, _ = _rotated_bundle(tmp, signers=(retiring, successor), rows=[row],
                              keys=_keys(successor))
    return _case(d, retiring=retiring, successor=successor)


@_scenario
def _sole_signer_no_handover_names(tmp: Path) -> _Case:
    retiring, successor, attacker = _Signer(), _Signer(), _Signer()
    d = _build_bundle(tmp, attacker)
    row = _handover(retiring, successor)
    _write_json(d / "keys.json", _keys(retiring, successor, attacker))
    _write_json(d / "key-rotations.json", [row])
    _write_json(d / "manifest.json", {
        "format": "cognexus-audit-evidence", "leaf_count": 5,
        "leaves_digest": _leaves_digest(_read_leaves(d)),
        "rotations_digest": _rotations_digest([row]),
    })
    _resign_manifest(d, attacker)
    return _case(d, retiring=retiring, successor=successor, attacker=attacker)


@_scenario
def _genuine_handover(tmp: Path) -> _Case:
    d, retiring, successor = _rotated_bundle(tmp)
    return _case(d, retiring=retiring, successor=successor)


@_scenario
def _genuine_handover_stdlib_only(tmp: Path) -> _Case:
    d, retiring, successor = _rotated_bundle(tmp)
    return _case(d, stdlib_only=True, retiring=retiring, successor=successor)


@_scenario
def _handover_pem_differs_from_registry(tmp: Path) -> _Case:
    retiring, successor, other = _Signer(), _Signer(), _Signer()
    d, _, _ = _rotated_bundle(tmp, signers=(retiring, successor))
    keys = json.loads((d / "keys.json").read_text(encoding="utf-8"))
    for k in keys:
        if k["key_id"] == retiring.key_id:
            k["public_key_pem"] = other.public_key_pem
    _write_json(d / "keys.json", keys)
    return _case(d, retiring=retiring, successor=successor, other=other)


@_scenario
def _handovers_without_committed_digest(tmp: Path) -> _Case:
    # A trusted manifest that commits no rotations_digest: no mismatch to
    # find, no "not trusted" warning, and the handovers are still checked.
    d, retiring, successor = _rotated_bundle(tmp, omit_digest=True)
    return _case(d, retiring=retiring, successor=successor)


def _rotated_with_third_key(tmp: Path) -> tuple[Path, _Signer, _Signer, _Signer]:
    """A rotated bundle whose keys.json (and the manifest's key_ids) also
    carry a third key no handover names."""
    d, retiring, successor = _rotated_bundle(tmp)
    third = _Signer()
    _write_json(d / "keys.json", _keys(retiring, successor, third))
    _resign_manifest(d, successor, key_ids=[retiring.key_id, successor.key_id, third.key_id])
    return d, retiring, successor, third


@_scenario
def _manifest_signer_no_handover_names(tmp: Path) -> _Case:
    d, retiring, successor, notary = _rotated_with_third_key(tmp)
    _resign_manifest(d, notary)
    return _case(d, retiring=retiring, successor=successor, notary=notary)


@_scenario
def _seal_signer_no_handover_names(tmp: Path) -> _Case:
    d, retiring, successor, sealer = _rotated_with_third_key(tmp)
    _write_seals(d, [_resealed(_read_seals(d)[0], sealer)])
    return _case(d, retiring=retiring, successor=successor, sealer=sealer)


# -- seals -------------------------------------------------------------------------


@_scenario
def _seal_hash_mismatch(tmp: Path) -> _Case:
    s = _Signer()
    d = _build_bundle(tmp, s)
    seals = _read_seals(d)
    seals[0]["merkle_root"] = "00" * 32
    _write_seals(d, seals)
    return _case(d, signer=s)


@_scenario
def _no_public_key_for_seal(tmp: Path) -> _Case:
    s, other = _Signer(), _Signer()
    d = _build_bundle(tmp, s)
    seals = _read_seals(d)
    seals[0]["signer_key_id"] = other.key_id
    _write_seals(d, seals)
    return _case(d, signer=s, other=other)


@_scenario
def _bad_seal_signature(tmp: Path) -> _Case:
    s = _Signer()
    d = _build_bundle(tmp, s)
    seals = _read_seals(d)
    seals[0]["sig"] = _Signer().sign(seals[0]["seal_hash"].encode("ascii"))
    _write_seals(d, seals)
    return _case(d, signer=s)


@_scenario
def _seal_chain_gap(tmp: Path) -> _Case:
    s = _Signer()
    d = _build_bundle(tmp, s)
    leaves = _read_leaves(d)
    first = _sealed({
        "seal_id": "S0", "first_seq": 1, "last_seq": 3,
        "merkle_root": _merkle_root([leaf["leaf_hash"] for leaf in leaves[:3]]),
        "prev_seal_hash": _GENESIS, "sealed_at": "2026-06-17T19:01:00+00:00"}, s)
    second = _sealed({
        "seal_id": "S1", "first_seq": 4, "last_seq": 5,
        "merkle_root": _merkle_root([leaf["leaf_hash"] for leaf in leaves[3:]]),
        "prev_seal_hash": "ab" * 32, "sealed_at": "2026-06-17T19:02:00+00:00"}, s)
    _write_seals(d, [second, first])
    return _case(d, signer=s)


@_scenario
def _seal_range_not_an_integer(tmp: Path) -> _Case:
    s, a = _Signer(), _CertAuthority()
    d = _certified(tmp, s, a)
    _write_seals(d, [_resealed(_read_seals(d)[0], s, first_seq="five")])
    return _case(d, root=a.root_fingerprint, authority=a, signer=s)


@_scenario
def _merkle_root_mismatch(tmp: Path) -> _Case:
    s = _Signer()
    d = _build_bundle(tmp, s)
    _write_seals(d, [_resealed(_read_seals(d)[0], s, merkle_root="00" * 32)])
    return _case(d, signer=s)


@_scenario
def _truncated_log(tmp: Path) -> _Case:
    s = _Signer()
    d = _build_bundle(tmp, s)
    _write_leaves(d, _read_leaves(d)[:-2])
    return _case(d, signer=s)


def _truncated_under_a_digest(tmp: Path, *, signed: bool) -> tuple[Path, _Signer]:
    """A truncated log whose manifest commits a leaves_digest over what is
    left: unsigned, or signed (and then read without cryptography)."""
    s = _Signer()
    d = _build_bundle(tmp, s)
    leaves = _read_leaves(d)[:-2]
    _write_leaves(d, leaves)
    _write_json(d / "manifest.json", {"leaf_count": 3, "leaves_digest": _leaves_digest(leaves)})
    if signed:
        _resign_manifest(d, s)
    return d, s


@_scenario
def _truncated_log_under_an_unsigned_digest(tmp: Path) -> _Case:
    # Only a *trusted* manifest's digest makes a seal past the leaves a
    # boundary seal; an unsigned one leaves the truncation check on.
    d, s = _truncated_under_a_digest(tmp, signed=False)
    return _case(d, signer=s)


@_scenario
def _truncated_log_under_an_unverified_digest(tmp: Path) -> _Case:
    d, s = _truncated_under_a_digest(tmp, signed=True)
    return _case(d, signer=s, stdlib_only=True)


@_scenario
def _deleted_leaf_at_the_seal_tail(tmp: Path) -> _Case:
    # The seal covers 1..4 and leaf 4 is gone; leaf 5 keeps the window wide
    # enough that the seal lies inside it. The missing seq is the one past
    # the last present leaf in the seal's range.
    s = _Signer()
    d = _build_bundle(tmp, s)
    leaves = _read_leaves(d)
    _write_seals(d, [_resealed(_read_seals(d)[0], s, last_seq=4,
                               merkle_root=_merkle_root([x["leaf_hash"] for x in leaves[:4]]))])
    _write_leaves(d, [leaf for leaf in leaves if leaf["seq"] != 4])
    return _case(d, signer=s)


@_scenario
def _huge_seal_range(tmp: Path) -> _Case:
    s = _Signer()
    d = _build_bundle(tmp, s)
    _write_seals(d, [_resealed(_read_seals(d)[0], s, last_seq=10 ** 15, merkle_root="00" * 32)])
    return _case(d, signer=s)


@_scenario
def _windowed_export_attests(tmp: Path) -> _Case:
    s, a = _Signer(), _CertAuthority()
    d = _windowed_certified_bundle(tmp, s, a, present=[3, 4, 5], seal_range=(1, 5))
    return _case(d, root=a.root_fingerprint, authority=a, signer=s)


@_scenario
def _dense_prefix_window_attests(tmp: Path) -> _Case:
    s, a = _Signer(), _CertAuthority()
    d = _windowed_certified_bundle(tmp, s, a, present=[1, 2, 3], seal_range=(1, 9))
    return _case(d, root=a.root_fingerprint, authority=a, signer=s)


@_scenario
def _gapped_window_without_digest(tmp: Path) -> _Case:
    s, a = _Signer(), _CertAuthority()
    d = _windowed_certified_bundle(tmp, s, a, present=[3, 5, 7], seal_range=(1, 9))
    _write_json(d / "manifest.json", _signed_manifest(s, 3, 7, 3, seal_count=1))
    return _case(d, root=a.root_fingerprint, authority=a, signer=s)


@_scenario
def _dense_window_truncated_without_digest(tmp: Path) -> _Case:
    s, a = _Signer(), _CertAuthority()
    d = _windowed_certified_bundle(tmp, s, a, present=[1, 2, 3], seal_range=(1, 9))
    _write_json(d / "manifest.json", _signed_manifest(s, 1, 3, 3, seal_count=1))
    return _case(d, root=a.root_fingerprint, authority=a, signer=s)


@_scenario
def _interior_per_batch_seals_attest(tmp: Path) -> _Case:
    s, a = _Signer(), _CertAuthority()
    d = tmp / "interior-seals"
    d.mkdir()
    present = [2, 5, 8, 11]
    leaves = [_genuine_leaf(s, seq) for seq in present]
    seals, prev = [], _GENESIS
    for i, (fs, ls) in enumerate([(1, 3), (4, 6), (7, 9), (10, 12)]):
        seal = _sealed({
            "seal_id": f"S{i}", "first_seq": fs, "last_seq": ls,
            "merkle_root": hashlib.sha256(f"batch-{fs}-{ls}".encode()).hexdigest(),
            "prev_seal_hash": prev, "sealed_at": f"2026-06-17T19:0{i}:00+00:00"}, s)
        seals.append(seal)
        prev = seal["seal_hash"]
    _write_leaves(d, leaves)
    _write_seals(d, seals)
    _write_json(d / "keys.json", _keys(s))
    a.write_chain(d, a.deployment_cert(s))
    _write_json(d / "manifest.json",
                _signed_manifest(s, 2, 11, 4, seal_count=4, leaves=leaves))
    return _case(d, root=a.root_fingerprint, authority=a, signer=s)


@_scenario
def _interior_per_batch_seals_without_digest(tmp: Path) -> _Case:
    s = _Signer()
    d = tmp / "interior-seals"
    d.mkdir()
    leaves = [_genuine_leaf(s, seq) for seq in (2, 5, 8, 11)]
    seal = _sealed({
        "seal_id": "S1", "first_seq": 4, "last_seq": 6,
        "merkle_root": hashlib.sha256(b"batch-4-6").hexdigest(),
        "prev_seal_hash": _GENESIS, "sealed_at": "2026-06-17T19:01:00+00:00"}, s)
    _write_leaves(d, leaves)
    _write_seals(d, [seal])
    _write_json(d / "keys.json", _keys(s))
    _write_json(d / "manifest.json", _signed_manifest(s, 2, 11, 4, seal_count=1))
    return _case(d, signer=s)


# -- the record set the signed manifest commits ---------------------------------------


@_scenario
def _prefix_deletion_suppressed(tmp: Path) -> _Case:
    s, a = _Signer(), _CertAuthority()
    d = _certified(tmp, s, a)
    _write_leaves(d, _read_leaves(d)[1:])
    return _case(d, root=a.root_fingerprint, authority=a, signer=s)


@_scenario
def _whole_log_deleted(tmp: Path) -> _Case:
    s, a = _Signer(), _CertAuthority()
    d = _certified(tmp, s, a, seal_count=None, leaves=None)
    _write_leaves(d, [])
    return _case(d, root=a.root_fingerprint, authority=a, signer=s)


@_scenario
def _seals_stripped(tmp: Path) -> _Case:
    s, a = _Signer(), _CertAuthority()
    d = _certified(tmp, s, a)
    (d / "seals.jsonl").write_text("", encoding="utf-8")
    return _case(d, root=a.root_fingerprint, authority=a, signer=s)


@_scenario
def _leaf_count_not_an_integer(tmp: Path) -> _Case:
    s, a = _Signer(), _CertAuthority()
    d = _certified(tmp, s, a, count="five", seal_count=None, leaves=None)
    return _case(d, root=a.root_fingerprint, authority=a, signer=s)


@_scenario
def _last_seq_mismatch(tmp: Path) -> _Case:
    s, a = _Signer(), _CertAuthority()
    d = _certified(tmp, s, a, last=6)
    return _case(d, root=a.root_fingerprint, authority=a, signer=s)


@_scenario
def _cross_bundle_splice(tmp: Path) -> _Case:
    s, a = _Signer(), _CertAuthority()
    d = _windowed_certified_bundle(tmp, s, a, present=[3, 5, 7], seal_range=(1, 9))
    by_seq = {leaf["seq"]: leaf for leaf in _read_leaves(d)}
    spliced = _genuine_leaf(s, 5, target="bank:evil", action="wire_transfer", tag="9")
    _write_leaves(d, [by_seq[3], spliced, by_seq[7]])
    return _case(d, root=a.root_fingerprint, authority=a, signer=s)


# -- provenance --------------------------------------------------------------------


@_scenario
def _certified_attested(tmp: Path) -> _Case:
    s, a = _Signer(), _CertAuthority()
    return _case(_certified(tmp, s, a), root=a.root_fingerprint, authority=a, signer=s)


@_scenario
def _certified_no_pinned_root(tmp: Path) -> _Case:
    s, a = _Signer(), _CertAuthority()
    return _case(_certified(tmp, s, a), authority=a, signer=s)


@_scenario
def _certified_against_the_pinned_root(tmp: Path) -> _Case:
    s, a = _Signer(), _CertAuthority()
    return _case(_certified(tmp, s, a), pinned=a.root_fingerprint, authority=a, signer=s)


@_scenario
def _wrong_root_fingerprint(tmp: Path) -> _Case:
    s, a = _Signer(), _CertAuthority()
    return _case(_certified(tmp, s, a), root="ab" * 32, authority=a, signer=s)


@_scenario
def _cert_expired_at_signing_time(tmp: Path) -> _Case:
    s, a = _Signer(), _CertAuthority()
    d = _certified(tmp, s, a)
    a.write_chain(d, a.deployment_cert(s, not_before="2026-01-01T00:00:00+00:00",
                                       not_after="2026-02-01T00:00:00+00:00"))
    return _case(d, root=a.root_fingerprint, authority=a, signer=s)


@_scenario
def _certificate_chain_malformed(tmp: Path) -> _Case:
    s, a = _Signer(), _CertAuthority()
    d = _certified(tmp, s, a)
    _write_json(d / "certificates.json", {
        "root_public_key_pem": {"not": "a string"},
        "issuing_certificates": [{"garbage": True}],
        "deployment_certificates": "not-a-list",
    })
    return _case(d, root=a.root_fingerprint, authority=a, signer=s)


@_scenario
def _certificates_not_an_object(tmp: Path) -> _Case:
    s, a = _Signer(), _CertAuthority()
    d = _certified(tmp, s, a)
    _write_json(d / "certificates.json", "pwned")
    return _case(d, root=a.root_fingerprint, authority=a, signer=s)


@_scenario
def _manifest_not_an_object(tmp: Path) -> _Case:
    s, a = _Signer(), _CertAuthority()
    d = _certified(tmp, s, a)
    _write_json(d / "manifest.json", [1, 2, 3])
    return _case(d, root=a.root_fingerprint, authority=a, signer=s)


@_scenario
def _without_leaves_digest(tmp: Path) -> _Case:
    s, a = _Signer(), _CertAuthority()
    d = _certified(tmp, s, a, seal_count=None, leaves=None)
    return _case(d, root=a.root_fingerprint, authority=a, signer=s)


@_scenario
def _substituted_keypair(tmp: Path) -> _Case:
    s, a, evil = _Signer(), _CertAuthority(), _Signer()
    d = _certified(tmp, s, a)
    leaves = _read_leaves(d)
    for leaf in leaves:
        leaf["target"] = "crm:fabricated"
    _write_leaves(d, _rechained(leaves, evil))
    _write_seals(d, [_resealed(_read_seals(d)[0], evil,
                               merkle_root=_merkle_root([x["leaf_hash"] for x in leaves]))])
    _write_json(d / "keys.json", _keys(evil))
    _write_json(d / "manifest.json", _signed_manifest(evil, 1, 5, 5, seal_count=1, leaves=leaves))
    return _case(d, root=a.root_fingerprint, authority=a, signer=s, evil=evil)


@_scenario
def _key_label_spoof(tmp: Path) -> _Case:
    s, a, evil = _Signer(), _CertAuthority(), _Signer()
    d = _certified(tmp, s, a)
    leaves = _rechained(_read_leaves(d), evil, keep_label=True)
    _write_leaves(d, leaves)
    seal = _resealed(_read_seals(d)[0], evil,
                     merkle_root=_merkle_root([x["leaf_hash"] for x in leaves]))
    seal["signer_key_id"] = s.key_id
    _write_seals(d, [seal])
    _write_json(d / "keys.json", [{"key_id": s.key_id, "public_key_pem": evil.public_key_pem}])
    manifest = {"first_seq": 1, "last_seq": 5, "leaf_count": 5,
                "leaves_digest": _leaves_digest(leaves), "tenant_user_id": 1}
    mh = hashlib.sha256(_canonical(manifest)).hexdigest()
    manifest.update(sig=evil.sign(mh.encode("ascii")), signer_key_id=s.key_id)
    _write_json(d / "manifest.json", manifest)
    return _case(d, root=a.root_fingerprint, authority=a, signer=s, evil=evil)


@_scenario
def _resigned_by_uncertified_key(tmp: Path) -> _Case:
    s, a, evil = _Signer(), _CertAuthority(), _Signer()
    d = _certified(tmp, s, a)
    _write_leaves(d, _read_leaves(d)[1:])
    _write_json(d / "keys.json", _keys(s, evil))
    _write_json(d / "manifest.json", _signed_manifest(evil, 2, 5, 4))
    return _case(d, root=a.root_fingerprint, authority=a, signer=s, evil=evil)


@_scenario
def _tampered_issuing_certificate_noted(tmp: Path) -> _Case:
    s, a = _Signer(), _CertAuthority()
    d = _certified(tmp, s, a)
    certs = json.loads((d / "certificates.json").read_text(encoding="utf-8"))
    tampered = dict(certs["issuing_certificates"][0])
    tampered["cert_id"] = "ISS-TAMPERED"
    certs["issuing_certificates"].append(tampered)
    _write_json(d / "certificates.json", certs)
    return _case(d, root=a.root_fingerprint, authority=a, signer=s)


# -- two faults: which check speaks first ----------------------------------------------


@_scenario
def _edited_leaf_and_forged_seal(tmp: Path) -> _Case:
    s = _Signer()
    d = _build_bundle(tmp, s)
    leaves = _read_leaves(d)
    leaves[4]["target"] = "crm:999"
    _write_leaves(d, leaves)
    seals = _read_seals(d)
    seals[0]["sig"] = _Signer().sign(seals[0]["seal_hash"].encode("ascii"))
    _write_seals(d, seals)
    return _case(d, signer=s)


@_scenario
def _forged_manifest_and_forged_seal(tmp: Path) -> _Case:
    s, a = _Signer(), _CertAuthority()
    d = _certified(tmp, s, a)
    manifest = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
    manifest["leaf_count"] = 500
    _write_json(d / "manifest.json", manifest)
    seals = _read_seals(d)
    seals[0]["sig"] = _Signer().sign(seals[0]["seal_hash"].encode("ascii"))
    _write_seals(d, seals)
    return _case(d, root=a.root_fingerprint, authority=a, signer=s)


@_scenario
def _committed_key_missing_and_handovers_dropped(tmp: Path) -> _Case:
    d, retiring, successor = _rotated_bundle(tmp)
    _write_json(d / "keys.json", _keys(successor))
    (d / "key-rotations.json").unlink()
    return _case(d, retiring=retiring, successor=successor)


@_scenario
def _handovers_dropped_and_seal_edited(tmp: Path) -> _Case:
    d, retiring, successor = _rotated_bundle(tmp)
    (d / "key-rotations.json").unlink()
    seals = _read_seals(d)
    seals[0]["merkle_root"] = "00" * 32
    _write_seals(d, seals)
    return _case(d, retiring=retiring, successor=successor)


@_scenario
def _bad_handover_and_edited_seal(tmp: Path) -> _Case:
    retiring, successor = _Signer(), _Signer()
    row = _handover(retiring, successor)
    row["invoice_reference"] = "INV-2026-0041"
    d, _, _ = _rotated_bundle(tmp, signers=(retiring, successor), rows=[row])
    seals = _read_seals(d)
    seals[0]["merkle_root"] = "00" * 32
    _write_seals(d, seals)
    return _case(d, retiring=retiring, successor=successor)


@_scenario
def _deleted_leaf_and_record_set_mismatch(tmp: Path) -> _Case:
    # Without a committed leaves_digest the seal's deletion check runs, and it
    # runs before the manifest's record-set cross-check.
    s = _Signer()
    d = _build_bundle(tmp, s)
    _write_json(d / "manifest.json", _signed_manifest(s, 1, 5, 5, seal_count=1))
    _write_leaves(d, [leaf for leaf in _read_leaves(d) if leaf["seq"] != 3])
    return _case(d, signer=s)


@_scenario
def _partial_seal_then_record_set_mismatch(tmp: Path) -> _Case:
    s, a = _Signer(), _CertAuthority()
    d = _windowed_certified_bundle(tmp, s, a, present=[3, 4, 5], seal_range=(1, 5))
    _resign_manifest(d, s, leaf_count=4)
    return _case(d, root=a.root_fingerprint, authority=a, signer=s)


# -- running a scenario ----------------------------------------------------------------


def _normalise(value: Any, case: _Case) -> Any:
    if isinstance(value, dict):
        return {k: _normalise(v, case) for k, v in value.items()}
    if isinstance(value, list):
        return [_normalise(v, case) for v in value]
    if isinstance(value, str):
        value = value.replace(str(case.path), "<bundle>")
        # Longest first: a key id is the first 16 hex of its fingerprint.
        for raw in sorted(case.labels, key=len, reverse=True):
            value = value.replace(raw, case.labels[raw])
    return value


def _outcome(build: Callable[[Path], _Case], tmp: Path) -> dict[str, Any]:
    """Verify the scenario's bundle directly and through ``artzain audit
    verify``; the whole result, the exit status and the printed report."""
    case = build(tmp)
    patches = contextlib.ExitStack()
    with patches:
        if case.stdlib_only:
            patches.enter_context(mock.patch.object(av, "_load_public_keys", lambda keys: None))
        if case.pinned is not None:
            patches.enter_context(mock.patch.object(av, "EVIDENCE_ROOT_FINGERPRINT", case.pinned))
        result = av.verify_bundle(case.path, root_fingerprint=case.root)
        argv = ["audit", "verify", str(case.path)]
        if case.root is not None:
            argv += ["--root-fingerprint", case.root]
        out = io.StringIO()
        with contextlib.redirect_stdout(out), pytest.raises(SystemExit) as exit_:
            cli.main(argv)
    return _normalise({"result": dataclasses.asdict(result), "exit": exit_.value.code,
                       "report": out.getvalue().splitlines()}, case)


def _golden() -> dict[str, Any]:
    return json.loads(GOLDEN.read_text(encoding="utf-8"))


@pytest.mark.parametrize("name", sorted(_SCENARIOS))
def test_the_verdict_and_the_report_are_the_captured_ones(name, tmp_path):
    golden = _golden()
    assert name in golden, f"no captured outcome for {name}: {RECAPTURE}"
    assert _outcome(_SCENARIOS[name], tmp_path) == golden[name]


def test_every_captured_outcome_has_its_scenario():
    assert sorted(_golden()) == sorted(_SCENARIOS)


def test_the_scenarios_reach_every_verdict():
    """The captured set is not all one shape: failures, intact bundles at
    both attestation levels, and the stdlib-only path are all in it."""
    golden = _golden().values()
    verdicts = {(o["result"]["ok"], o["result"]["attestation"]) for o in golden}
    assert verdicts == {(False, None), (True, "SELF-ATTESTED"), (True, "ATTESTED")}
    assert any(o["result"]["signatures_skipped"] for o in golden)
    assert {o["exit"] for o in golden} == {0, 1}


def _recapture() -> None:
    outcomes = {}
    with tempfile.TemporaryDirectory() as root:
        for name in sorted(_SCENARIOS):
            tmp = Path(root) / name
            tmp.mkdir()
            outcomes[name] = _outcome(_SCENARIOS[name], tmp)
    GOLDEN.write_text(json.dumps(outcomes, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {len(outcomes)} outcomes to {GOLDEN}")


if __name__ == "__main__":
    _recapture()
