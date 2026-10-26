"""Offline verification of a CogNexus audit evidence bundle (FR-3, WS2 §2.4).

Zero network.  Given a bundle directory (or ``.zip``) produced by
``GET /api/v1/audit/export``, this recomputes every leaf hash, checks the
hash-chain linkage and Merkle roots, and verifies Ed25519 signatures against the
bundled public keys.  It is the Art. 12 "offline reconstruction" artifact.
Because those keys come from the bundle, trust in the producing server drops
out only at ``VERIFIED, ATTESTED``, once the Evidence Root is pinned
(:data:`EVIDENCE_ROOT_FINGERPRINT`).  While that pin is ``None`` and the caller
supplies no root, an intact bundle verifies ``SELF-ATTESTED``.  A re-root
(ceremony runbook §14) appends to :data:`EVIDENCE_ROOT_FINGERPRINTS` instead
of replacing the pin, so a bundle certified under the earlier root keeps
verifying ATTESTED under it, and the result says which root it reached.

Bundle layout::

    leaves.jsonl        one JSON leaf record per line (canonical body + chain meta)
    seals.jsonl         one JSON seal record per line
    keys.json           [{key_id, public_key_pem, ...}]  (keys.pem is the same, PEM-only)
    manifest.json       range / counts / key ids (optionally Ed25519-signed)
    certificates.json   optional certificate chain to the CogNEXUS Evidence Root
    key-rotations.json  optional countersigned signing-key handovers (WS-8)
    proofs.jsonl        optional, one per sealed leaf present: its Merkle
                        inclusion proof {seq, seal_id, index, path} through
                        the seal's full tree

Leaf-hash, chain, and Merkle integrity verify with the standard library alone.
A seal whose leaves are only partly present (a range- or tenant-filtered
export) has its root recomputed when it can be; otherwise every present leaf
is proved against that root through its inclusion proof, when the bundle
carries them, and a proof that does not reach the root is a failure. A bundle
without ``proofs.jsonl`` reads as before: such a seal is reported as a
boundary of a filtered export, root not recomputed.
A tenant-filtered export has a seq gap between nearly every pair of leaves and
a partly present seal under nearly every leaf. Each of those kinds of warning
is one line in ``warnings`` carrying its count; the counts are fields of the
result, and the per-record lines are kept in ``warning_details``.
**Signature** verification needs the ``cryptography`` package; install the extra::

    pip install 'artzain[verify]'

Without it, signatures are reported as ``skipped`` (everything else still runs).
A manifest signed by a key the bundle carries is still read: the bundle is
compared with the record set it commits to, and its ``leaves_digest`` decides
whether a partly present seal is a boundary of the export or a deleted leaf,
as when its signature verifies. Only the signature goes unchecked, and the
report says so. A bundle whose signatures hold gets the same verdict on either
install.

Three-state result (WS-4).  Integrity (``ok``) and provenance
(``attestation``) are separate axes:

* ``FAILED`` (``ok=False``) — chain broken, signature invalid, Merkle root
  mismatch, an inclusion proof that does not reach its seal's root, or a
  signed manifest that no longer verifies.
* ``VERIFIED, ATTESTED`` — intact; the signed manifest commits a
  ``leaves_digest`` binding the exact exported ``(seq, leaf_hash)`` set, and its
  signer plus every leaf/seal signer is covered by a deployment certificate that
  chains to the pinned **CogNEXUS Evidence Root** and was valid at signing time.
  A pre-``leaves_digest`` manifest cannot attest — its content set is unbound, so
  a windowed export cannot exclude a spliced-in certified leaf — and caps at
  SELF-ATTESTED (re-export to attest).
* ``VERIFIED, SELF-ATTESTED`` — intact and internally consistent, but the
  provenance claim rests on the bundle's own keys (no chain, no pinned
  root, chain invalid, or signers not covered).  Pre-certificate bundles
  land here by design and **never fail** for lacking a chain.

The trusted keys for leaf/seal signatures still come from the bundle itself
(backwards compatible); the certificate layer is an *additional* binding of
those keys to the Evidence Root.  Certificate problems therefore never turn
an intact bundle into a failure — they cap the claim at SELF-ATTESTED.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional, Union

_GENESIS_HASH = "0" * 64

#: Full SHA-256 hex fingerprint of the CogNEXUS Evidence Root public key
#: (canonical SubjectPublicKeyInfo PEM): the CURRENT pin, always the last
#: entry of :data:`EVIDENCE_ROOT_FINGERPRINTS`.  ``None`` until the root
#: ceremony publishes it (docs/runbooks/evidence-root-ceremony.md); while
#: ``None`` the verifier reports SELF-ATTESTED only.  Overriding at call time
#: exists for test roots — the CLI states loudly when a non-default root is
#: in use.
EVIDENCE_ROOT_FINGERPRINT: Optional[str] = None

#: Every Evidence Root fingerprint this verifier pins, oldest first, the
#: current one last.  A re-root (runbook §14) APPENDS the new fingerprint and
#: moves :data:`EVIDENCE_ROOT_FINGERPRINT` onto it; it never replaces the
#: tuple, because a bundle certified under the earlier root must keep
#: verifying ATTESTED under that root.  An entry may be dropped only once no
#: customer bundle was ever certified under it.  Empty until the ceremony.
EVIDENCE_ROOT_FINGERPRINTS: tuple[str, ...] = ()

_ISSUING_CERT_FORMAT = "cognexus-issuing-certificate"
_DEPLOYMENT_CERT_FORMAT = "cognexus-licence-certificate"

# Canonical body fields (must match the server's audit_scribe._leaf_body order-
# independently; sort_keys makes order irrelevant).
_LEAF_BODY_FIELDS = (
    "leaf_id", "decision_id", "created_at", "user_id", "team_id", "agent_did",
    "action", "target", "outcome", "payload_sha256", "votes", "bundle_version",
    "resolution", "prev_leaf_hash",
)
_SEAL_BODY_FIELDS = (
    "seal_id", "first_seq", "last_seq", "merkle_root", "prev_seal_hash", "sealed_at",
)


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass
class VerifyResult:
    ok: bool = True
    leaves_checked: int = 0
    seals_checked: int = 0
    signatures_checked: int = 0
    signatures_skipped: bool = False
    first_bad_seq: Optional[int] = None
    error: Optional[str] = None
    warnings: list[str] = field(default_factory=list)
    #: The warnings a tenant- or range-filtered export repeats once per
    #: record, counted: gaps in the leaves' seq, seals whose predecessor is not
    #: in the bundle, and seals only partly present, either with the root not
    #: recomputed (``partial_seals``) or with every present leaf proved
    #: included under it (``partial_seals_proved``; the two never count the
    #: same seal). Each kind found more than once is ONE line in ``warnings``
    #: carrying its count, and its per-record lines are in
    #: ``warning_details``, in the order they were found. A kind found once
    #: keeps its own line in ``warnings`` and adds nothing to the details, so
    #: the two lists together still hold every per-record line.
    seq_gaps: int = 0
    seal_chain_gaps: int = 0
    partial_seals: int = 0
    partial_seals_proved: int = 0
    warning_details: list[str] = field(default_factory=list)
    #: "ATTESTED" | "SELF-ATTESTED" when ``ok``; ``None`` when FAILED.
    attestation: Optional[str] = None
    attestation_reasons: list[str] = field(default_factory=list)
    certificates_checked: int = 0
    #: Signing-key handovers whose signatures were verified and held (WS-8).
    #: Zero when ``cryptography`` is absent, whatever the bundle carries, so
    #: this number never implies more checking than happened. A handover that
    #: is cryptographically sound but names a key the bundle does not carry
    #: still counts — its signatures *were* checked — and says so in
    #: ``warnings``.
    rotations_checked: int = 0
    #: Keys that signed records in this bundle without a sound handover naming
    #: them. Populated only when the bundle carries at least one handover whose
    #: signatures checked out: an installation that has never rotated has
    #: nothing to be inconsistent with, and its original key has no predecessor
    #: by definition. Empty when signature verification was skipped, because a
    #: reader already told "signatures NOT verified" must not also be handed an
    #: accusation the verifier had no means to make.
    #: Reported, not fatal — a second process legitimately signs with its own
    #: key — but it is also the shape a substitution takes, and the reader
    #: should be the one to decide which it is.
    unexplained_key_ids: list[str] = field(default_factory=list)
    #: The Evidence Root fingerprint this run pinned against, in comparison
    #: form (stripped, lower case): the caller override when one was supplied,
    #: otherwise the current module pin — and, once the certificate chain was
    #: read, the pinned root that chain actually reached, which after a
    #: re-root may be a retired one.  ``None`` when nothing is pinned.
    #: ``root_fingerprint_overridden`` is ``True`` when the caller passed a
    #: fingerprint that is in none of the pinned set after that normalisation
    #: — an ATTESTED result then attests to *that* root, not a published
    #: CogNEXUS Evidence Root.  Case and surrounding whitespace alone are not
    #: an override, and neither is naming a retired pin.
    #: Machine consumers must read this flag: the loud human-readable warning
    #: is on the text path only.
    evidence_root_fingerprint: Optional[str] = None
    root_fingerprint_overridden: bool = False
    #: ``True`` when the chain reached a root this verifier still pins but a
    #: later re-root replaced (runbook §14).  An ATTESTED verdict under it is
    #: still ATTESTED — the bundle was certified before the re-root, which is
    #: why the pin is kept — and ``attestation_reasons`` then carries
    #: "attested under retired root <16 hex>".  ``False`` when the chain was
    #: not evaluated, reached the current pin, or reached an override.
    evidence_root_retired: bool = False

    def _fail(self, seq: Optional[int], msg: str) -> "VerifyResult":
        self.ok = False
        self.attestation = None
        if self.first_bad_seq is None:
            self.first_bad_seq = seq
        if self.error is None:
            self.error = msg
        return self


#: What one line says for every warning of a kind a filtered export repeats
#: once per record, keyed by the ``VerifyResult`` counter of that kind.
_PER_RECORD_SUMMARIES = {
    "seq_gaps": "{n} seq gaps (tenant- or range-filtered export; chain linkage "
                "across the gaps not checkable offline)",
    "seal_chain_gaps": "{n} seal chain gaps (earlier seals not in this bundle)",
    "partial_seals": "{n} seals only partially present — boundaries of a "
                     "filtered export, roots not recomputed",
    "partial_seals_proved": "{n} seals only partially present — boundaries of a "
                            "filtered export; every present leaf proved included "
                            "under its seal's merkle_root",
}


class _PerRecord:
    """The warnings of :data:`_PER_RECORD_SUMMARIES`, one line per kind.

    One line per record buried the verdict on a hosted export under about
    10,800 of them. The first of a kind takes its place in ``warnings`` when
    it is found, so the report keeps its order; :meth:`report` sets the
    counts and, for a kind found more than once, puts the summary in that
    place and every line of the kind in ``warning_details``.
    """

    def __init__(self, res: VerifyResult) -> None:
        self._res = res
        self._found: list[tuple[str, str]] = []
        self._slot: dict[str, int] = {}

    def add(self, kind: str, line: str) -> None:
        if kind not in self._slot:
            self._slot[kind] = len(self._res.warnings)
            self._res.warnings.append(line)
        self._found.append((kind, line))

    def report(self) -> None:
        counts = Counter(kind for kind, _ in self._found)
        for kind, summary in _PER_RECORD_SUMMARIES.items():
            setattr(self._res, kind, counts[kind])
            if counts[kind] > 1:
                self._res.warnings[self._slot[kind]] = summary.format(n=f"{counts[kind]:,}")
        self._res.warning_details = [line for kind, line in self._found if counts[kind] > 1]


# ---------------------------------------------------------------------------
# Canonicalisation + hashing (mirrors server)
# ---------------------------------------------------------------------------


def _canonical(obj: dict[str, Any]) -> bytes:
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _leaf_hash(record: dict[str, Any]) -> str:
    body = {k: record.get(k) for k in _LEAF_BODY_FIELDS}
    return hashlib.sha256(_canonical(body)).hexdigest()


def _seal_hash(record: dict[str, Any]) -> str:
    body = {k: record.get(k) for k in _SEAL_BODY_FIELDS}
    return hashlib.sha256(_canonical(body)).hexdigest()


def _leaves_digest(leaves: list[dict[str, Any]]) -> str:
    """SHA-256 over the canonical sorted ``[seq, leaf_hash]`` list of the
    present leaves.

    This binds the *exact exported record set* — content, not just the counts
    and range endpoints — to the signed manifest.  ``seq`` is deliberately not
    part of the signed leaf body (``_LEAF_BODY_FIELDS``), so a genuine
    certified-key-signed leaf can be relabelled into any seq slot without
    breaking its ``leaf_hash`` or signature.  On a range/tenant-filtered export
    the boundary seal's Merkle root cannot be recomputed offline (leaves outside
    the window are absent) and chain linkage across seq gaps is only a warning,
    so an attacker holding a *second* genuine export from the same deployment
    could delete a real interior leaf and splice in a genuine, distinct-hash
    certified leaf relabelled into the freed slot with the count and endpoints
    unchanged.  ``leaves_digest`` is what catches that substitution.  Must match
    ``application/api/audit.py:_leaves_digest`` byte for byte.
    """
    pairs = sorted(
        ([int(leaf.get("seq", 0)), leaf.get("leaf_hash")] for leaf in leaves),
        key=lambda p: p[0],
    )
    return hashlib.sha256(_canonical(pairs)).hexdigest()


# ---------------------------------------------------------------------------
# RFC 6962 Merkle (stdlib mirror of services/merkle.py)
# ---------------------------------------------------------------------------


#: Every key a countersigned handover may carry. Closed: the digest is over the
#: whole record, so an unexpected field is either a silent signature break or a
#: channel into the evidence bundle for something that has no business there.
_HANDOVER_FIELDS = frozenset({
    "format", "retiring_key_id", "successor_key_id",
    "successor_public_key_pem", "retiring_public_key_pem",
    "install_id", "rotated_at", "reason",
})
#: And the wrapper around it. Ground rule 7 does not stop at one nesting level:
#: the row travels in the export exactly as the record does, and an allowlist
#: with a level missing is not an allowlist.
_HANDOVER_ROW_FIELDS = frozenset({
    "successor_key_id", "retiring_key_id", "record",
    "retiring_sig", "successor_sig", "leaf_decision_id", "rotated_at",
})
_ROTATION_FORMAT = "cognexus-key-rotation-v1"


def _rotations_digest(rotations: list[dict[str, Any]]) -> str:
    """SHA-256 over a canonical per-row commitment list.

    Commits the **record**, not just its successor id and one signature. The
    first cut committed ``[successor_key_id, retiring_sig]``, and a review
    showed that leaves the entire signed body — ``rotated_at``, ``reason``,
    ``install_id``, both public keys — bound by nothing the manifest covers.
    An attacker could backdate a handover and erase a stated compromise while
    the server-signed digest still matched byte for byte.

    Must match ``application/api/audit.py::_rotations_digest`` byte for byte.
    """
    rows: list[Any] = []
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
    return hashlib.sha256(_canonical_list(sorted(rows))).hexdigest()


def _canonical_list(obj: list[Any]) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _proofs_digest(proofs: list[dict[str, Any]]) -> str:
    """SHA-256 over the canonical sorted ``[seq, seal_id, index, path]`` rows
    of the inclusion proofs present.

    Binds ``proofs.jsonl`` to the signed manifest the way ``leaves_digest``
    binds the leaves. A proof cannot be forged (a path that reaches a signed
    root for a leaf outside the tree is a hash collision), so what the digest
    guards is the set: a proof dropped so that its seal falls back to the
    weaker "root not recomputed" reading, added, or relabelled. Step 4 has
    checked every record's shape before this runs. Must match
    ``application/api/audit.py::_proofs_digest`` byte for byte.
    """
    rows = sorted(
        ([int(p["seq"]), str(p["seal_id"]), int(p["index"]),
          [[str(sibling), str(side)] for sibling, side in p["path"]]] for p in proofs),
        key=lambda r: (r[0], r[1]),
    )
    return hashlib.sha256(_canonical_list(rows)).hexdigest()


def _mk_leaf(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def _mk_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _merkle_root(leaf_hashes_hex: list[str]) -> str:
    if not leaf_hashes_hex:
        return hashlib.sha256(b"").hexdigest()
    level = [_mk_leaf(bytes.fromhex(h)) for h in leaf_hashes_hex]
    while len(level) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(_mk_node(level[i], level[i + 1]))
            else:
                nxt.append(level[i])
        level = nxt
    return level[0].hex()


def _proof_path(value: Any) -> Optional[list[tuple[bytes, str]]]:
    """The audit path a ``proofs.jsonl`` record carries, as ``(sibling, side)``
    steps, or ``None`` when it is not one: a list of ``[64-hex, side]`` pairs
    with ``side`` ``"left"`` or ``"right"``. Attacker-shaped input; nothing
    here raises."""
    if not isinstance(value, list):
        return None
    path: list[tuple[bytes, str]] = []
    for step in value:
        if not (isinstance(step, list) and len(step) == 2):
            return None
        sibling, side = step
        if (not isinstance(sibling, str) or len(sibling) != 64
                or side not in ("left", "right")):
            return None
        try:
            raw = bytes.fromhex(sibling)
        except ValueError:
            return None
        path.append((raw, side))
    return path


def _verify_inclusion(leaf_hash_hex: Any, path: list[tuple[bytes, str]], root_hex: Any) -> bool:
    """``True`` when the leaf with *path* reconstructs *root_hex*: the mirror
    of ``services/merkle.py::verify_inclusion`` (leaf prefix ``0x00``, node
    prefix ``0x01``, the sibling on the side each step names)."""
    try:
        running = _mk_leaf(bytes.fromhex(leaf_hash_hex))
    except (TypeError, ValueError):
        return False
    for sibling, side in path:
        running = _mk_node(sibling, running) if side == "left" else _mk_node(running, sibling)
    return running.hex() == root_hex


# ---------------------------------------------------------------------------
# Signatures (optional cryptography)
# ---------------------------------------------------------------------------


def _load_public_keys(keys: list[dict[str, Any]]):
    """Return ``{key_id: Ed25519PublicKey}`` or ``None`` if cryptography missing."""
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
    except Exception:
        return None
    out: dict[str, Any] = {}
    for k in keys:
        if not isinstance(k, dict):
            continue
        kid = k.get("key_id")
        pem = k.get("public_key_pem")
        if not kid or not pem:
            continue
        try:
            out[kid] = load_pem_public_key(pem.encode("ascii"))
        except Exception:
            continue
    return out


def _verify_sig(pubkey, signed_hash_hex: str, sig_b64: str) -> bool:
    from cryptography.exceptions import InvalidSignature

    try:
        sig = base64.urlsafe_b64decode(sig_b64 + "==")
        pubkey.verify(sig, signed_hash_hex.encode("ascii"))
        return True
    except (InvalidSignature, Exception):
        return False


# ---------------------------------------------------------------------------
# Certificate chain (WS-4) — stdlib except for the signature checks
# ---------------------------------------------------------------------------


def _canonical_pem(pem: Optional[str]) -> str:
    """Normalise a PEM to the fingerprint byte form: LF endings, one
    trailing newline (the form ``cryptography`` emits and the server
    stores)."""
    if not pem:
        return ""
    return pem.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n") + "\n"


def _pem_key_id(pem: str) -> str:
    return hashlib.sha256(_canonical_pem(pem).encode("ascii")).hexdigest()[:16]


def _pem_fingerprint(pem: str) -> str:
    return hashlib.sha256(_canonical_pem(pem).encode("ascii")).hexdigest()


def _normalised_root_fingerprint(value: Optional[str]) -> Optional[str]:
    """Evidence Root fingerprint in the form the chain check compares.

    Case and surrounding whitespace are not part of the fingerprint. A blank
    value is no fingerprint.
    """
    if value is None:
        return None
    text = value.strip().lower()
    return text or None


def pinned_root_fingerprints() -> tuple[str, ...]:
    """The Evidence Root fingerprints this verifier pins, in comparison form.

    Retired roots first, in :data:`EVIDENCE_ROOT_FINGERPRINTS` order, and the
    current pin (:data:`EVIDENCE_ROOT_FINGERPRINT`) last; blanks and repeats
    dropped.  Read at call time, so a test that sets the single name alone
    pins exactly that root.  Empty before the ceremony.
    """
    current = _normalised_root_fingerprint(EVIDENCE_ROOT_FINGERPRINT)
    pins: list[str] = []
    for value in EVIDENCE_ROOT_FINGERPRINTS:
        fp = _normalised_root_fingerprint(value) if isinstance(value, str) else None
        if fp and fp != current and fp not in pins:
            pins.append(fp)
    if current:
        pins.append(current)
    return tuple(pins)


def _root_pin_set(value: Union[str, Iterable[str], None]) -> tuple[str, ...]:
    """*value* as the set of fingerprints the chain check compares against:
    one string is a set of one, a blank value is no fingerprint."""
    if value is None:
        return ()
    if isinstance(value, str):
        fp = _normalised_root_fingerprint(value)
        return (fp,) if fp else ()
    pins: list[str] = []
    for item in value:
        fp = _normalised_root_fingerprint(item) if isinstance(item, str) else None
        if fp and fp not in pins:
            pins.append(fp)
    return tuple(pins)


def matched_root_fingerprint(certs: dict[str, Any],
                             root_fingerprint: Union[str, Iterable[str], None],
                             ) -> Optional[str]:
    """The pinned fingerprint the chain's root public key has, or ``None``.

    After a re-root the pinned set holds more than one root; this names the
    one a chain :func:`validated_deployment_certificates` accepted reached.
    """
    root_pem = certs.get("root_public_key_pem") if isinstance(certs, dict) else None
    pins = _root_pin_set(root_fingerprint)
    if not root_pem or not pins:
        return None
    actual = _pem_fingerprint(root_pem)
    return actual if actual in pins else None


def _retired_root_note(fingerprint: str) -> str:
    """The note an ATTESTED result carries when the root it reached is a pin
    a later re-root replaced.  Shared with ``artzain.licence``."""
    return (f"attested under retired root {fingerprint[:16]} — pinned before the "
            "current Evidence Root; this bundle was certified before the re-root")


def _parse_ts(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        ts = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def _as_int(value: Any) -> Optional[int]:
    """Coerce a manifest count / seq to ``int``, or ``None`` if it is not a
    whole number.  A signed manifest is attacker-shaped input; a non-numeric
    count must fail the cross-check closed, never raise out of verification.

    Also rejects the shapes that survive ``json.loads`` but are not honest
    integers: booleans (``int(True) == 1`` would silently pass) and the
    non-finite floats ``Infinity`` / ``-Infinity`` / ``NaN`` (``json`` accepts
    those tokens by default; ``int(inf)`` raises ``OverflowError``)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _cert_signed_hash(record: dict[str, Any]) -> str:
    body = {k: v for k, v in record.items() if k not in ("sig", "signer_key_id")}
    return hashlib.sha256(_canonical(body)).hexdigest()


def _load_one_key(pem: str):
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        return load_pem_public_key(_canonical_pem(pem).encode("ascii"))
    except Exception:
        return None


def _cert_sig_ok(record: dict[str, Any], issuer_pem: str) -> bool:
    pub = _load_one_key(issuer_pem)
    if pub is None:
        return False
    return _verify_sig(pub, _cert_signed_hash(record), record.get("sig") or "")


def validated_deployment_certificates(
    certs: dict[str, Any], root_fingerprint: Union[str, Iterable[str], None],
) -> tuple[list[dict[str, Any]], Optional[str], int, list[str]]:
    """Deployment certificates that chain to a pinned Evidence Root.

    *root_fingerprint* is one fingerprint or the whole pinned set (see
    :func:`pinned_root_fingerprints`); the chain's root may be any of them,
    and :func:`matched_root_fingerprint` says which one it was.

    Returns ``(certificates, blocking_reason, checked, notes)`` —
    ``blocking_reason`` is ``None`` when at least one certificate chains, and
    otherwise says why none did, in the caller's own words ("no certificate
    chain in bundle" versus "the attestation names no certificate").

    Shared with ``artzain.licence`` on purpose. The *wire formats* are
    deliberately implemented twice so the cross-package tests catch drift, but
    trust evaluation is not a format: two copies of it would drift into two
    different answers to "does this chain to the root", and only one of them
    would be right.
    """
    checked = 0
    notes: list[str] = []
    root_pem = certs.get("root_public_key_pem")
    if not root_pem:
        return [], "no Evidence Root public key supplied", checked, notes
    pins = _root_pin_set(root_fingerprint)
    if not pins:
        return [], ("no Evidence Root fingerprint pinned (pre-ceremony "
                    "verifier)"), checked, notes
    if _pem_fingerprint(root_pem) not in pins:
        return [], ("root public key fingerprint mismatch — does not chain to "
                    "the pinned Evidence Root"), checked, notes
    root_key_id = _pem_key_id(root_pem)

    # Issuing certificates: root-signed, well-formed.
    issuers: list[dict[str, Any]] = []
    for cert in certs.get("issuing_certificates") or []:
        if not isinstance(cert, dict):
            continue
        if cert.get("format") != _ISSUING_CERT_FORMAT:
            continue
        if cert.get("issuer_key_id") != root_key_id:
            continue
        if not _cert_sig_ok(cert, root_pem):
            notes.append(
                f"issuing certificate {cert.get('cert_id')} signature invalid")
            continue
        checked += 1
        issuers.append(cert)
    if not issuers:
        return [], "no valid issuing certificate chains to the root", checked, notes

    # Deployment certificates: signed by an issuer that was valid when the
    # certificate was issued (its not_before) — the issuing window bounds
    # issuance, not later leaf-signing (air-gapped certs never go stale
    # because the online issuer rotated).
    deploy: list[dict[str, Any]] = []
    for cert in certs.get("deployment_certificates") or []:
        if not isinstance(cert, dict):
            continue
        if cert.get("format") != _DEPLOYMENT_CERT_FORMAT:
            continue
        nb = _parse_ts(cert.get("not_before"))
        na = _parse_ts(cert.get("not_after"))
        if nb is None or na is None:
            continue
        for issuer in issuers:
            inb = _parse_ts(issuer.get("not_before"))
            ina = _parse_ts(issuer.get("not_after"))
            if (cert.get("issuer_key_id") == _pem_key_id(issuer.get("public_key") or "")
                    and inb is not None and ina is not None
                    and inb <= nb <= ina
                    and _cert_sig_ok(cert, issuer.get("public_key") or "")):
                checked += 1
                deploy.append(cert)
                break
    if not deploy:
        return [], ("no valid certificate for any deployment key (invalid "
                    "signature, or issued outside the issuing certificate's "
                    "validity)"), checked, notes
    return deploy, None, checked, notes


def _check_rotations(res: VerifyResult, rotations: list[dict[str, Any]],
                     keys: list[dict[str, Any]], pubkeys,
                     signer_kids: set) -> Optional[str]:
    """Verify signing-key handovers (WS-8). Returns a failure message or ``None``.

    ``signing_keys`` records which keys exist; only a handover records which of
    them this installation *authorised*, and by whose signature. Anyone who can
    write a public key into a bundle can claim a key is legitimate; only the
    holder of the retiring private key can produce the countersignature.

    Two independent questions, and keeping them apart is the whole design:

    **1. Is the record internally consistent?** Both public keys travel inside
    the record, so this is answerable from the record alone, always. Each PEM
    must hash to the key id it is filed under, and each signature must verify
    against the PEM the record itself carries. **Failure here is fatal, and a
    bundle has no way to opt out of the check.**

    That last clause is the point, and it was got wrong once. An earlier cut
    resolved the signing keys through ``keys.json`` and treated "key not in
    keys.json" as *not checkable* -- a warning. But ``keys.json`` is
    attacker-controlled bytes; that is the premise of an offline verifier
    handed to an assessor over an untrusted path. Deleting one line therefore
    moved a forged handover out of the fatal branch, turning ``FAILED`` into
    ``VERIFIED``: the attacker chose whether their forgery was inspected.
    Checking the record against its own contents removes that choice. It is an
    *integrity* check, not an authorisation one, and integrity is checkable
    without trusting anything outside the record.

    **2. Does it describe keys this bundle actually uses?** Only askable for a
    key present in ``keys.json``. Present and equal: the handover explains that
    key. Present and different: the record describes a key other than the one
    the bundle signs with -- fatal. Absent: the handover cannot vouch for a key
    the bundle does not carry, which is a warning and never a failure, because
    ``register_audit_signing_key`` is best-effort and a deployment whose
    database was down at first boot legitimately has an unregistered key.
    """
    pem_by_kid = {k.get("key_id"): k.get("public_key_pem") for k in keys
                  if isinstance(k, dict)}
    explained: set = set()
    saw_sound = False

    for row in rotations:
        if not isinstance(row, dict):
            return "malformed key handover record"
        extra_row = set(row) - _HANDOVER_ROW_FIELDS
        if extra_row:
            return ("key handover row carries fields outside the allowlist: "
                    + ", ".join(sorted(str(k) for k in extra_row)))
        record = row.get("record")
        if not isinstance(record, dict):
            return "key handover carries no record"
        if record.get("format") != _ROTATION_FORMAT:
            return f"unknown key handover format {record.get('format')!r}"
        extra = set(record) - _HANDOVER_FIELDS
        if extra:
            return ("key handover carries fields outside the allowlist: "
                    + ", ".join(sorted(str(k) for k in extra)))
        retiring = record.get("retiring_key_id")
        successor = record.get("successor_key_id")
        if not isinstance(retiring, str) or not isinstance(successor, str) \
                or not retiring or not successor:
            return "key handover names no retiring or successor key"
        if retiring == successor:
            return "key handover nominates the retiring key as its own successor"

        # -- 1. Internal consistency, always checkable ---------------------
        pems = {retiring: record.get("retiring_public_key_pem"),
                successor: record.get("successor_public_key_pem")}
        for label, kid in (("retiring", retiring), ("successor", successor)):
            pem = pems[kid]
            if not isinstance(pem, str) or not pem:
                return f"key handover carries no {label} public key"
            if _pem_key_id(pem) != kid:
                return (f"a key handover's {label} public key does not hash to "
                        "the key id it is filed under")

        if pubkeys is None:
            # stdlib-only. The structural checks above ran; the signatures did
            # not. Explain the keys anyway: a reader already told "signatures
            # NOT verified" must not ALSO be told this bundle's own signing key
            # is unaccounted for, when the handover naming it is sitting in the
            # same file. Two contradictory warnings are worse than one honest
            # limitation, and this is the DEFAULT install -- cryptography is an
            # optional extra.
            explained.add(retiring)
            explained.add(successor)
            res.warnings.append(
                f"key handover {retiring}->{successor} not verified "
                "(cryptography missing)")
            continue

        digest = hashlib.sha256(_canonical(record)).hexdigest()
        for label, kid, sig in (
                ("retiring", retiring, row.get("retiring_sig") or ""),
                ("successor", successor, row.get("successor_sig") or "")):
            pk = _load_one_key(pems[kid])
            if pk is None:
                return f"a key handover's {label} public key will not parse"
            if not _verify_sig(pk, digest, sig):
                return f"invalid {label} signature on a key handover"
            res.signatures_checked += 1
        saw_sound = True
        res.rotations_checked += 1

        # -- 2. Agreement with the keys the bundle carries ------------------
        mismatched = [kid for kid in (retiring, successor)
                      if kid in pem_by_kid
                      and _canonical_pem(pems[kid]) != _canonical_pem(pem_by_kid[kid])]
        if mismatched:
            return ("a key handover's public key differs from the one the "
                    f"bundle registers for {', '.join(sorted(mismatched))}")
        unregistered = [kid for kid in (retiring, successor)
                        if kid not in pem_by_kid]
        if unregistered:
            res.warnings.append(
                f"key handover {retiring}->{successor} is internally sound but "
                "the bundle carries no public key for "
                f"{', '.join(sorted(unregistered))}, so it cannot be tied to a "
                "key this bundle uses")
        # A sound handover explains whichever of its keys the bundle carries.
        # Explaining one is not weakened by the other being absent.
        for kid in (retiring, successor):
            if kid in pem_by_kid:
                explained.add(kid)

    # Keys that signed records here that no sound handover accounts for.
    #
    # Only reported once the bundle carries at least one handover whose
    # signatures checked out. On an installation that has never rotated there
    # is nothing to be inconsistent with -- its first key has no predecessor by
    # definition -- and flagging every bundle would be noise that gets the
    # signal deleted.
    #
    # Deliberately NOT gated on the number of distinct signers. It was, and
    # that inverted the signal: a bundle whose *sole* signer no handover named
    # -- the exact shape of a clean substitution -- reported nothing, while the
    # presence of a legitimate co-signer was what made the illegitimate one
    # visible.
    if saw_sound:
        res.unexplained_key_ids = sorted(
            k for k in signer_kids if k and k not in explained)
    return None


def _evaluate_attestation(
    res: VerifyResult,
    *,
    certs: dict[str, Any],
    keys: list[dict[str, Any]],
    leaves: list[dict[str, Any]],
    seals: list[dict[str, Any]],
    root_fingerprints: tuple[str, ...],
    manifest_trusted: bool,
    manifest_signer_kid: Optional[str] = None,
    manifest_binds_content: bool = False,
    retired_roots: frozenset[str] = frozenset(),
) -> None:
    """Set ``res.attestation`` for an intact bundle.

    Never fails the bundle: every problem here caps the claim at
    SELF-ATTESTED and is named in ``attestation_reasons``.  The chain may
    reach any of *root_fingerprints*; the one it reached is recorded on the
    result, flagged when it is in *retired_roots* (a pin a re-root replaced).
    """
    def self_attested(reason: str) -> None:
        res.attestation = "SELF-ATTESTED"
        res.attestation_reasons.append(reason)

    if not certs or not (certs.get("deployment_certificates")
                         or certs.get("issuing_certificates")):
        return self_attested("no certificate chain in bundle")
    if res.signatures_skipped:
        return self_attested(
            "cryptography not installed — certificate chain not evaluated")
    # ATTESTED requires a signed manifest we could verify: it is the only
    # thing that bounds the record set (its committed first_seq/last_seq/
    # leaf_count, cross-checked in verify_bundle). Without it the coverage
    # loops below run vacuously over whatever leaves happen to be present, so
    # an emptied or prefix-truncated bundle would attest to a record set an
    # attacker chose. No trusted manifest → cap at SELF-ATTESTED.
    if not manifest_trusted:
        return self_attested(
            "no verifiable signed manifest — the exported record set is not "
            "bound to the certified key, so its completeness cannot be attested")
    if not root_fingerprints:
        return self_attested(
            "no Evidence Root fingerprint pinned (pre-ceremony verifier)")

    deploy, reason, checked, notes = validated_deployment_certificates(
        certs, root_fingerprints)
    res.certificates_checked += checked
    res.attestation_reasons.extend(notes)
    if reason is not None:
        return self_attested(reason)
    # The pinned root this chain reached is the one the result names from
    # here on, whatever the verdict below.
    matched = matched_root_fingerprint(certs, root_fingerprints)
    if matched is not None:
        res.evidence_root_fingerprint = matched
        res.evidence_root_retired = matched in retired_roots

    # Coverage: every leaf and seal must be signed by a certified key, valid
    # at the record's signing time.  Compare the actual key bytes the
    # signatures verified against (keys.json), not the key_id label — a
    # label under an attacker's PEM must not inherit the genuine key's
    # certificate.
    pem_by_kid = {k.get("key_id"): _canonical_pem(k.get("public_key_pem") or "")
                  for k in keys if isinstance(k, dict)}

    def covered(kid: Optional[str], ts: Optional[datetime]) -> bool:
        actual_pem = pem_by_kid.get(kid)
        if not actual_pem or ts is None:
            return False
        for cert in deploy:
            if _canonical_pem(cert.get("public_key") or "") != actual_pem:
                continue
            nb = _parse_ts(cert.get("not_before"))
            na = _parse_ts(cert.get("not_after"))
            if nb is not None and na is not None and nb <= ts <= na:
                return True
        return False

    for leaf in leaves:
        if not covered(leaf.get("signer_key_id"), _parse_ts(leaf.get("created_at"))):
            return self_attested(
                f"leaf seq {leaf.get('seq')} not covered by a certificate "
                "valid at signing time")
    for seal in seals:
        if not covered(seal.get("signer_key_id"), _parse_ts(seal.get("sealed_at"))):
            return self_attested(
                f"seal {seal.get('seal_id')} not covered by a certificate "
                "valid at signing time")

    # The signed manifest is the only thing that binds the record SET (its
    # committed first_seq/last_seq/leaf_count/seal_count, cross-checked in
    # verify_bundle).  For that binding to mean anything the manifest must be
    # signed by a CERTIFIED deployment key — not merely any key the bundle
    # happens to carry.  Otherwise an attacker keeps the genuine, cert-covered
    # leaves, deletes the earliest ones, and re-signs a manifest with a
    # self-minted key appended to keys.json: the leaf/seal coverage loops
    # above only see the genuine signers and pass, and the committed range
    # matches the truncated set.  Bind by the actual key bytes (as coverage
    # does), but without a time window — the manifest is generated at export,
    # not at leaf-signing time, so it legitimately post-dates the window.
    signer_pem = pem_by_kid.get(manifest_signer_kid)
    if not signer_pem or not any(
            _canonical_pem(c.get("public_key") or "") == signer_pem
            for c in deploy):
        return self_attested(
            "signed manifest is not signed by a certified deployment key — "
            "the committed record set is not bound to the Evidence Root")

    # WS-4 content-substitution fix (decision: REQUIRE the digest). The manifest
    # signer's committed range/counts bind only the endpoints and totals; on a
    # windowed export whose boundary seal cannot be recomputed offline that is
    # not enough to exclude a genuine certified leaf spliced into a deleted
    # interior slot. Only a signed ``leaves_digest`` binds the exact
    # (seq, leaf_hash) set. Its absence (pre-digest / in-flight bundles) caps the
    # claim at SELF-ATTESTED; re-export from an updated deployment to attest.
    if not manifest_binds_content:
        return self_attested(
            "signed manifest carries no leaves_digest — the exact exported leaf "
            "set is not bound to the certified key, so content substitution "
            "within a windowed export cannot be ruled out (re-export to attest)")

    res.attestation = "ATTESTED"
    if res.evidence_root_retired and res.evidence_root_fingerprint:
        res.attestation_reasons.append(_retired_root_note(res.evidence_root_fingerprint))


# ---------------------------------------------------------------------------
# Bundle loading
# ---------------------------------------------------------------------------


def _read_jsonl(text: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            rec = json.loads(line)
            if not isinstance(rec, dict):
                # A record that is not a JSON object (a bare scalar/list/null)
                # is malformed bundle input; fail closed rather than let it
                # reach a .get() call and raise mid-verification.
                raise ValueError("audit record is not a JSON object")
            out.append(rec)
    return out


def _load_bundle(path: Path) -> dict[str, Any]:
    """Load leaves/seals/keys/manifest from a directory or a .zip bundle."""
    def _read(name: str) -> str:
        if path.is_dir():
            p = path / name
            return p.read_text(encoding="utf-8") if p.exists() else ""
        with zipfile.ZipFile(path) as zf:
            try:
                return zf.read(name).decode("utf-8")
            except KeyError:
                return ""

    leaves = _read_jsonl(_read("leaves.jsonl"))
    seals = _read_jsonl(_read("seals.jsonl"))
    keys_raw = _read("keys.json")
    keys = json.loads(keys_raw) if keys_raw.strip() else []
    manifest_raw = _read("manifest.json")
    manifest = json.loads(manifest_raw) if manifest_raw.strip() else {}
    certs_raw = _read("certificates.json")
    certificates = json.loads(certs_raw) if certs_raw.strip() else {}
    rotations_raw = _read("key-rotations.json")
    rotations = json.loads(rotations_raw) if rotations_raw.strip() else []
    proofs = _read_jsonl(_read("proofs.jsonl"))
    # Optional top-level structures degrade to their empty form when malformed
    # (a non-object manifest/chain, a non-list key set) so hostile bytes can
    # never reach a .get()/iteration and raise; a missing manifest/chain is
    # already a legitimate (pre-certificate) state, so this only weakens the
    # claim, never crashes.
    if not isinstance(keys, list):
        keys = []
    if not isinstance(manifest, dict):
        manifest = {}
    if not isinstance(certificates, dict):
        certificates = {}
    if not isinstance(rotations, list):
        rotations = []
    return {"leaves": leaves, "seals": seals, "keys": keys,
            "manifest": manifest, "certificates": certificates,
            "rotations": rotations, "proofs": proofs}


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def verify_bundle(bundle_path: str | Path,
                  root_fingerprint: Optional[str] = None) -> VerifyResult:
    """Verify a bundle directory or .zip. Returns a :class:`VerifyResult`.

    *root_fingerprint* replaces the pinned set (:func:`pinned_root_fingerprints`)
    with that one root (test roots only). Comparison ignores case and
    surrounding whitespace, the same way the certificate check does, and
    ``evidence_root_fingerprint`` is that normalised value — or, once the chain
    was read, the pinned root it reached.
    """
    path = Path(bundle_path)
    res = VerifyResult()
    # Record which root this run actually pinned against, before any early
    # return, so even a FAILED result carries it. A caller-supplied
    # fingerprint that is in none of the pinned set once both sides are
    # stripped and lower cased is an override: an ATTESTED verdict then
    # attests to that root, not a published one. ``None`` and ``""`` use the
    # module pins, as before. A value that is blank once stripped is not a
    # fingerprint, and replaces the set with nothing.
    pins = pinned_root_fingerprints()
    if root_fingerprint:
        supplied = _normalised_root_fingerprint(root_fingerprint)
        effective = (supplied,) if supplied else ()
        overridden = supplied not in pins if supplied else bool(pins)
    else:
        effective = pins
        overridden = False
    res.evidence_root_fingerprint = effective[-1] if effective else None
    res.root_fingerprint_overridden = overridden
    per_record = _PerRecord(res)
    try:
        return _verify_bundle_body(res, path, effective, frozenset(pins[:-1]), per_record)
    except Exception as exc:  # noqa: BLE001
        # Absolute fail-closed backstop: the verifier's contract is that
        # hostile bundle bytes yield a FAILED result, never a raised
        # exception. The targeted guards below handle the known malformed-
        # input vectors with precise messages; this catches anything
        # unforeseen (e.g. an unhashable signer_key_id reaching a dict lookup).
        return res._fail(None, f"malformed bundle ({type(exc).__name__})")
    finally:
        # Every path, a failure included: what was found before it stays
        # reported.
        per_record.report()


def _verify_bundle_body(res: VerifyResult, path: Path,
                        root_fingerprints: tuple[str, ...],
                        retired_roots: frozenset[str],
                        per_record: _PerRecord) -> VerifyResult:
    if not path.exists():
        return res._fail(None, f"bundle path not found: {path}")

    try:
        bundle = _load_bundle(path)
    except Exception as exc:
        return res._fail(None, f"could not read bundle: {exc}")

    leaves = sorted(bundle["leaves"], key=lambda r: _as_int(r.get("seq")) or 0)
    seals = bundle["seals"]
    pubkeys = _load_public_keys(bundle["keys"])
    if pubkeys is None:
        res.signatures_skipped = True
        res.warnings.append(
            "cryptography not installed — signatures NOT verified. "
            "Install with: pip install 'artzain[verify]'"
        )

    # 1) Per-leaf hash + signature + 2) chain linkage on contiguous seq runs.
    leaf_by_seq: dict[int, dict[str, Any]] = {}
    failed = _verify_leaves(res, leaves, pubkeys, leaf_by_seq, per_record)
    if failed is not None:
        return failed

    # 3) Verify the signed manifest's custody signature UP FRONT (the record-set
    #    cross-check itself stays after the seals). The seal truncation/deletion
    #    heuristics below defer to a trusted, content-committing manifest: when a
    #    signed leaves_digest binds the exact present set, a seal that reaches
    #    past the present leaves is a legitimate boundary seal of a windowed
    #    export, not evidence of a deletion. Without cryptography, a manifest
    #    signed by a key the bundle carries is read the same way, its signature
    #    unchecked (see _verify_manifest_signature).
    manifest = bundle.get("manifest") or {}
    failed, manifest_trusted, manifest_signer_kid, manifest_unverified = \
        _verify_manifest_signature(res, manifest, bundle, pubkeys)
    if failed is not None:
        return failed
    # A trusted manifest that commits a content digest binds the exact present
    # (seq, leaf_hash) set — the flag the attestation gate below keys off.
    manifest_binds_content = manifest_trusted and manifest.get("leaves_digest") is not None
    # The seal heuristics key off it too, and without cryptography off the
    # digest of a manifest signed by a key the bundle carries (step 3): a
    # bundle whose signatures hold then gets the same verdict on either
    # install. Its record set is checked in step 5 all the same.
    seals_defer_to_manifest = (
        (manifest_trusted or manifest_unverified)
        and manifest.get("leaves_digest") is not None)

    # 3a) The keys the signed manifest commits to, and 3b) the signing-key
    #     handovers (WS-8) it binds.
    failed = _verify_key_custody(res, bundle, manifest, leaves, seals, pubkeys,
                                 manifest_trusted=manifest_trusted,
                                 manifest_signer_kid=manifest_signer_kid)
    if failed is not None:
        return failed

    # 4) Seals, and the inclusion proofs of the leaves under them.
    proofs = bundle.get("proofs") or []
    failed = _verify_seals(res, seals, leaf_by_seq, pubkeys, seals_defer_to_manifest, proofs,
                           per_record)
    if failed is not None:
        return failed

    # 5) The record set a trusted signed manifest commits to, or one signed by
    #    a bundle key and read without cryptography (step 3).
    if manifest_trusted or manifest_unverified:
        failed = _verify_manifest_record_set(res, manifest, leaf_by_seq, leaves, seals, proofs,
                                             verified=manifest_trusted)
        if failed is not None:
            return failed

    # 5) Provenance (WS-4): does the intact chain also chain to a pinned
    #    Evidence Root?  Never fails the bundle — caps the claim instead.
    try:
        _evaluate_attestation(
            res,
            certs=bundle.get("certificates") or {},
            keys=bundle.get("keys") or [],
            leaves=leaves,
            seals=seals,
            root_fingerprints=root_fingerprints,
            manifest_trusted=manifest_trusted,
            manifest_signer_kid=manifest_signer_kid,
            manifest_binds_content=manifest_binds_content,
            retired_roots=retired_roots,
        )
    except Exception:  # noqa: BLE001
        # Provenance is a *cap*, never a failure (see module docstring): a
        # malformed certificate structure degrades to SELF-ATTESTED, it does
        # not crash or fail an otherwise-intact bundle.
        res.attestation = "SELF-ATTESTED"
        res.attestation_reasons.append(
            "certificate chain malformed — provenance not evaluated")
    return res


def _verify_leaves(res: VerifyResult, leaves: list[dict[str, Any]], pubkeys,
                   leaf_by_seq: dict[int, dict[str, Any]],
                   per_record: _PerRecord) -> Optional[VerifyResult]:
    """Steps 1 and 2: every leaf's hash and signature, and the chain linkage
    on contiguous seq runs. Fills *leaf_by_seq* (seq -> leaf) as it goes, and
    gives each seq gap to *per_record*.

    Returns the failed result, or ``None`` when every leaf holds.
    """
    prev_hash: Optional[str] = None
    prev_seq: Optional[int] = None
    seen_leaf_hashes: set[str] = set()
    for leaf in leaves:
        seq = _as_int(leaf.get("seq"))
        if seq is None:
            return res._fail(None, "non-integer leaf seq (malformed record)")
        if seq in leaf_by_seq:
            # A well-formed log has exactly one leaf per seq. A duplicate lets
            # an attacker delete a genuine interior leaf and pad the record
            # count back with a copy of another, so first_seq/last_seq/
            # leaf_count still match while a record is suppressed.
            return res._fail(seq, f"duplicate leaf seq {seq} (record set padded)")
        leaf_by_seq[seq] = leaf

        recomputed = _leaf_hash(leaf)
        if recomputed != leaf.get("leaf_hash"):
            return res._fail(seq, f"leaf_hash mismatch at seq {seq} (record tampered)")

        # ``seq`` is not part of the signed leaf body, so a genuine,
        # certified-key-signed leaf can be relabelled into another seq slot
        # without breaking its hash or signature. Two leaves sharing a
        # leaf_hash therefore means one is a copy dropped into a deleted
        # record's slot — decision_id/leaf_id are unique, so a genuine log
        # never repeats a leaf_hash. (This closes the same-bundle copy of the
        # boundary-seal content-substitution forge; the general case also
        # needs a server-committed content digest in the signed manifest.)
        lh = leaf.get("leaf_hash")
        if lh in seen_leaf_hashes:
            return res._fail(
                seq, f"duplicate leaf_hash at seq {seq} "
                "(a record was copied into another's slot)")
        seen_leaf_hashes.add(lh)

        if prev_seq is not None and seq == prev_seq + 1:
            if leaf.get("prev_leaf_hash") != prev_hash:
                return res._fail(seq, f"chain linkage broken at seq {seq}")
        elif prev_seq is not None and seq != prev_seq + 1:
            per_record.add(
                "seq_gaps",
                f"seq gap {prev_seq}->{seq} (range/tenant-filtered export; "
                "linkage across the gap not checkable offline)"
            )

        if pubkeys is not None:
            kid = leaf.get("signer_key_id")
            pk = pubkeys.get(kid)
            if pk is None:
                return res._fail(seq, f"no public key {kid} for leaf seq {seq}")
            if not _verify_sig(pk, leaf["leaf_hash"], leaf.get("sig", "")):
                return res._fail(seq, f"bad leaf signature at seq {seq}")
            res.signatures_checked += 1

        prev_hash = leaf.get("leaf_hash")
        prev_seq = seq
        res.leaves_checked += 1
    return None


def _verify_manifest_signature(
    res: VerifyResult, manifest: dict[str, Any], bundle: dict[str, Any], pubkeys,
) -> tuple[Optional[VerifyResult], bool, Optional[str], bool]:
    """Step 3: the signed manifest's custody signature.

    Returns ``(failed, manifest_trusted, manifest_signer_kid,
    manifest_unverified)``: the failed result when the signature does not
    verify, else ``None`` with whether the manifest verified, the key that
    signed it, and whether it is signed by a key the bundle carries but was
    read without ``cryptography``, so its signature could not be checked.
    """
    manifest_trusted = False
    manifest_signer_kid: Optional[str] = None
    manifest_unverified = False
    if manifest.get("sig"):
        kid = manifest.get("signer_key_id")
        pk = pubkeys.get(kid) if pubkeys is not None else None
        if pubkeys is None and _names_a_bundle_key(kid, bundle):
            # Nothing is signature-checked on this install. A manifest signed
            # by a key the bundle carries is read as a verifier with
            # cryptography reads it when the signature holds: the bundle is
            # compared with the records it commits to (step 5), and the seal
            # checks defer to its leaves_digest (step 4). Not reading it
            # FAILED every intact tenant export, whose interior seals are
            # shared with other tenants' absent leaves. The signature is the
            # one thing left unchecked, as every other one is here.
            manifest_unverified = True
            res.warnings.append(
                "signed manifest present but not verified (cryptography missing): "
                "the records it commits to are compared with the bundle, but "
                "nothing proves the server signed them")
        elif pubkeys is None:
            # Its key is not in the bundle: a verifier with cryptography
            # would not trust it either (custody not verified).
            res.warnings.append(
                "signed manifest present but not verified (cryptography missing)")
        elif pk is None:
            res.warnings.append(
                f"signed manifest key {kid} not in the bundle — custody not verified")
        else:
            body = {k: v for k, v in manifest.items()
                    if k not in ("sig", "signer_key_id")}
            signed_hash = hashlib.sha256(_canonical(body)).hexdigest()
            if not _verify_sig(pk, signed_hash, manifest.get("sig") or ""):
                return (res._fail(None, "manifest signature invalid (custody broken)"),
                        False, None, False)
            res.signatures_checked += 1
            manifest_trusted = True
            manifest_signer_kid = kid
    elif (bundle.get("certificates") or {}).get("deployment_certificates"):
        res.warnings.append("certified bundle without a signed manifest")
    return None, manifest_trusted, manifest_signer_kid, manifest_unverified


def _names_a_bundle_key(kid: Any, bundle: dict[str, Any]) -> bool:
    """Whether ``keys.json`` carries a key filed under *kid*. Compared, never
    hashed: *kid* is bundle bytes and may be any JSON value."""
    return isinstance(kid, str) and bool(kid) and any(
        isinstance(k, dict) and k.get("key_id") == kid for k in bundle["keys"])


def _verify_key_custody(
    res: VerifyResult, bundle: dict[str, Any], manifest: dict[str, Any],
    leaves: list[dict[str, Any]], seals: list[dict[str, Any]], pubkeys, *,
    manifest_trusted: bool, manifest_signer_kid: Optional[str],
) -> Optional[VerifyResult]:
    """Steps 3a and 3b: the key ids the signed manifest commits to, and the
    signing-key handovers.

    Returns the failed result, or ``None`` to go on.
    """
    # 3a) The signed manifest lists the keys the server exported. Nothing read
    #     that list until WS-8's review found why it matters: deleting an entry
    #     from keys.json is otherwise invisible, and it is a general tool —
    #     whatever check would have resolved that key simply does not run.
    #     Both come from the same query in the same request on the server, so
    #     they agree by construction on every bundle ever exported; a
    #     disagreement means the bundle was edited in transit.
    if manifest_trusted:
        committed_key_ids = manifest.get("key_ids")
        if isinstance(committed_key_ids, list):
            present = {k.get("key_id") for k in bundle["keys"]
                       if isinstance(k, dict)}
            missing = sorted(str(k) for k in committed_key_ids
                             if k not in present)
            if missing:
                return res._fail(
                    None, "keys.json is missing key(s) the signed manifest "
                          "commits to: " + ", ".join(missing))

    # 3b) Signing-key handovers (WS-8). Checked here because the digest that
    #     binds them lives in the manifest just verified above.
    rotations = bundle.get("rotations") or []
    committed_rotations = manifest.get("rotations_digest")
    if manifest_trusted and committed_rotations is not None:
        if _rotations_digest(rotations) != committed_rotations:
            # Covers both directions: a handover added on the way here, and one
            # removed to hide that the signing key ever changed.
            return res._fail(
                None, "key handover set does not match the signed manifest "
                      "(rotations_digest mismatch)")
    elif rotations and not manifest_trusted:
        res.warnings.append(
            "key handovers present but the manifest is not trusted — they are "
            "checked for self-consistency only")
    signer_kids = {leaf.get("signer_key_id") for leaf in leaves}
    signer_kids |= {seal.get("signer_key_id") for seal in seals}
    if manifest_signer_kid:
        signer_kids.add(manifest_signer_kid)
    failure = _check_rotations(res, rotations, bundle["keys"], pubkeys,
                               {k for k in signer_kids if k})
    if failure:
        return res._fail(None, failure)
    for kid in res.unexplained_key_ids:
        res.warnings.append(
            f"key {kid} signed records here and no handover names it — either "
            "a second signing process, or a key that was never authorised")
    return None


def _index_proofs(
    res: VerifyResult, proofs: list[dict[str, Any]], leaf_by_seq: dict[int, dict[str, Any]],
    seals: list[dict[str, Any]],
) -> tuple[Optional[VerifyResult], dict[str, dict[int, list[tuple[bytes, str]]]]]:
    """The inclusion proofs by seal and seq, each checked for shape, for
    naming a seal and a leaf the bundle carries, and for being the only proof
    of its leaf under that seal. ``proofs.jsonl`` is attacker-shaped input
    like the rest of the bundle: a record that is not a proof fails closed
    with its seq named, never raises.

    Returns ``(failed, by_seal)``: the failed result, or ``None`` with the
    index.
    """
    known = {seal.get("seal_id") for seal in seals if isinstance(seal.get("seal_id"), str)}
    by_seal: dict[str, dict[int, list[tuple[bytes, str]]]] = {}
    for proof in proofs:
        seq = _as_int(proof.get("seq"))
        if seq is None:
            return res._fail(None, "non-integer inclusion proof seq (malformed record)"), {}
        path = _proof_path(proof.get("path"))
        if path is None or _as_int(proof.get("index")) is None:
            return res._fail(seq, f"malformed inclusion proof for seq {seq}"), {}
        seal_id = proof.get("seal_id")
        if not isinstance(seal_id, str) or seal_id not in known:
            return res._fail(
                seq, f"inclusion proof for seq {seq} names seal {seal_id}, "
                     "which is not in the bundle"), {}
        if seq not in leaf_by_seq:
            return res._fail(
                seq, f"inclusion proof for seq {seq}, but no such leaf is in the bundle"), {}
        if seq in by_seal.setdefault(seal_id, {}):
            return res._fail(
                seq, f"duplicate inclusion proof for seq {seq} under seal {seal_id}"), {}
        by_seal[seal_id][seq] = path
    return None, by_seal


def _verify_seals(res: VerifyResult, seals: list[dict[str, Any]],
                  leaf_by_seq: dict[int, dict[str, Any]], pubkeys,
                  manifest_binds_content: bool,
                  proofs: list[dict[str, Any]],
                  per_record: _PerRecord) -> Optional[VerifyResult]:
    """Step 4: every seal's hash, signature and Merkle root, and the inclusion
    proof of every present leaf that has one. Seal chain gaps and partly
    present seals go to *per_record*.

    *manifest_binds_content*: a manifest's leaves_digest binds the present
    leaves and step 5 checks its record set, so the deletion and truncation
    heuristics below defer to it. The manifest is trusted, or, without
    cryptography, signed by a key the bundle carries.

    Returns the failed result, or ``None`` when every seal holds.
    """
    # 4) Seals: hash + signature + Merkle root over covered leaves.
    #    A seal commits to *exactly* its [first_seq, last_seq] range.  When that
    #    range lies entirely within the leaves we have (a full / contiguous
    #    export window), every leaf must be present — a hole means a deleted leaf,
    #    which is a FAILURE.  Seals that extend past the export window (boundary
    #    seals of a range-filtered bundle) are reported as partial warnings.
    bundle_min = min(leaf_by_seq) if leaf_by_seq else None
    bundle_max = max(leaf_by_seq) if leaf_by_seq else None
    # "Dense" = the present leaves are perfectly contiguous (no interior gaps),
    # i.e. this looks like a full/complete export rather than a tenant-filtered
    # one.  In a dense bundle a seal that reaches past the last leaf means the
    # tail was truncated.
    dense = (
        bundle_min is not None
        and len(leaf_by_seq) == (bundle_max - bundle_min + 1)
    )
    # Present seqs, ascending. Used to collect a seal's covered leaves by
    # scanning the leaves we HAVE, never range(first_seq, last_seq) — a seal
    # may commit a range far larger than the export (a boundary seal, or a
    # hostile last_seq like 10**15), and iterating that range would hang.
    present_sorted = sorted(leaf_by_seq)
    failed, proofs_by_seal = _index_proofs(res, proofs, leaf_by_seq, seals)
    if failed is not None:
        return failed
    prev_seal_hash: Optional[str] = None
    for seal in sorted(seals, key=lambda r: _as_int(r.get("first_seq")) or 0):
        if _seal_hash(seal) != seal.get("seal_hash"):
            return res._fail(None, f"seal_hash mismatch for seal {seal.get('seal_id')}")

        if pubkeys is not None:
            kid = seal.get("signer_key_id")
            pk = pubkeys.get(kid)
            if pk is None:
                return res._fail(None, f"no public key {kid} for seal {seal.get('seal_id')}")
            if not _verify_sig(pk, seal["seal_hash"], seal.get("sig", "")):
                return res._fail(None, f"bad seal signature for {seal.get('seal_id')}")
            res.signatures_checked += 1

        if prev_seal_hash is not None and seal.get("prev_seal_hash") != prev_seal_hash:
            per_record.add(
                "seal_chain_gaps",
                f"seal chain gap before {seal.get('seal_id')} "
                "(earlier seal not in this bundle)"
            )
        prev_seal_hash = seal.get("seal_hash")

        first_seq = _as_int(seal.get("first_seq"))
        last_seq = _as_int(seal.get("last_seq"))
        if first_seq is None or last_seq is None:
            return res._fail(
                None,
                f"non-integer seal range for seal {seal.get('seal_id')} "
                "(malformed record)")
        expected = last_seq - first_seq + 1
        covered_seqs = [s for s in present_sorted if first_seq <= s <= last_seq]
        covered = [leaf_by_seq[s] for s in covered_seqs]
        # Inclusion proofs (proofs.jsonl): each present leaf's path through
        # the seal's full tree, checked against the seal's root. They prove
        # what a partial seal's root recompute cannot — that the leaves here
        # are the ones the sealer signed — without the absent leaves. A proof
        # that does not reach the root is a failure whatever the seal's
        # shape; the bundle carried it as evidence of this leaf.
        seal_id = seal.get("seal_id")
        seal_proofs = proofs_by_seal.get(seal_id, {}) if isinstance(seal_id, str) else {}
        for seq in sorted(seal_proofs):
            if not first_seq <= seq <= last_seq:
                return res._fail(
                    seq, f"inclusion proof for seq {seq} names seal {seal_id}, which "
                         f"commits seq {first_seq}..{last_seq}")
            if not _verify_inclusion(leaf_by_seq[seq].get("leaf_hash"), seal_proofs[seq],
                                     seal.get("merkle_root")):
                return res._fail(
                    seq, f"inclusion proof for seq {seq} does not reach the merkle_root "
                         f"of seal {seal_id} (the leaf is not in the sealed tree, or "
                         "the proof was altered)")
        within_window = (
            bundle_min is not None and bundle_max is not None
            and first_seq >= bundle_min and last_seq <= bundle_max
        )
        seal_starts_inside = (
            bundle_min is not None and bundle_min <= first_seq <= bundle_max
        )
        if len(covered) == expected:
            root = _merkle_root([c["leaf_hash"] for c in covered])
            if root != seal.get("merkle_root"):
                return res._fail(first_seq, f"merkle root mismatch for seal {seal.get('seal_id')}")
        elif within_window and not manifest_binds_content:
            # The bundle spans this seal's range but leaves are missing → looks
            # like a deletion.  Only a sound signal WITHOUT a trusted content
            # manifest: a genuine sparse tenant export ships every overlapping
            # seal, and a per-batch interior seal legitimately covers seqs owned
            # by other tenants (absent here) while sitting inside the window.
            # When a signed leaves_digest already binds the present set, such a
            # seal is a partial/boundary seal, and a real deletion is caught by
            # the manifest cross-check (unspoofable without the certified key).
            # Find the first missing seq by walking the present leaves in range
            # (bounded by leaf count) — never materialise range(first_seq,
            # last_seq+1), which a hostile last_seq could blow up.
            in_range = covered_seqs
            missing_seq = first_seq + len(in_range)  # default: short tail
            for i, s in enumerate(in_range):
                if s != first_seq + i:
                    missing_seq = first_seq + i
                    break
            return res._fail(
                missing_seq,
                f"deleted leaf — seal {seal.get('seal_id')} expects {expected} leaves "
                f"in seq {first_seq}..{last_seq}, found {len(covered)} "
                f"(missing seq {missing_seq})",
            )
        elif dense and seal_starts_inside and not manifest_binds_content:
            # Contiguous export whose seal commits to leaves past the last one
            # present → looks like tail truncation.  Same as the deletion branch:
            # only sound without a trusted content manifest.  A tenant's owned
            # seqs can be contiguous yet sealed together with later tenants', so
            # with a signed leaves_digest binding the present set this is a
            # boundary seal; real truncation changes last_seq + leaves_digest,
            # caught by the manifest cross-check.
            return res._fail(
                bundle_max + 1 if bundle_max is not None else first_seq,
                f"truncated log — seal {seal.get('seal_id')} commits to seq "
                f"{first_seq}..{last_seq} but leaves end at {bundle_max}",
            )
        elif covered and all(s in seal_proofs for s in covered_seqs):
            # Every present leaf under this boundary seal proved above. The
            # root itself is still not recomputed (the other leaves are not
            # here), and the seal is still only partly present, so this stays
            # in the warnings; what changed is what is known about the leaves.
            per_record.add(
                "partial_seals_proved",
                f"seal {seal_id} only partially present "
                f"({len(covered)}/{expected} leaves) — boundary of a filtered export; "
                "every present leaf proved included under its merkle_root"
            )
        else:
            per_record.add(
                "partial_seals",
                f"seal {seal.get('seal_id')} only partially present "
                f"({len(covered)}/{expected} leaves) — boundary of a filtered export, "
                "root not recomputed"
            )
        res.seals_checked += 1
    return None


def _verify_manifest_record_set(res: VerifyResult, manifest: dict[str, Any],
                                leaf_by_seq: dict[int, dict[str, Any]],
                                leaves: list[dict[str, Any]],
                                seals: list[dict[str, Any]],
                                proofs: list[dict[str, Any]], *,
                                verified: bool = True) -> Optional[VerifyResult]:
    """Step 5, for a trusted manifest: the record set it commits to against
    the leaves, seals and inclusion proofs present. ``verified=False`` is a
    manifest signed by a bundle key and read without cryptography: the same
    check, and a mismatch may then also be the manifest edited, which the
    failure says.

    Returns the failed result, or ``None`` when they match.
    """
    # 5) Signed manifest record-set cross-check (WS-4 chain of custody).  The
    #    signature was already verified in step 3; here the committed range /
    #    counts / content digest are checked against the leaves present.  A valid
    #    signature whose committed set no longer matches is record suppression or
    #    substitution (FAILURE).  An unverifiable / absent manifest only *caps*
    #    the claim — a non-empty bundle whose signer key is absent already failed
    #    at leaf verification above.
    present = list(leaf_by_seq)  # validated int seqs, duplicates rejected above
    exp_first = min(present) if present else None
    exp_last = max(present) if present else None
    mism: list[str] = []
    # Only fields the signed body actually carries — the signature makes
    # it impossible to strip one to dodge the check.  A count that will
    # not parse to an int is treated as a mismatch (fail closed), never
    # a crash: the manifest is attacker-shaped input.
    if "first_seq" in manifest and manifest.get("first_seq") != exp_first:
        mism.append(f"first_seq {manifest.get('first_seq')}≠{exp_first}")
    if "last_seq" in manifest and manifest.get("last_seq") != exp_last:
        mism.append(f"last_seq {manifest.get('last_seq')}≠{exp_last}")
    mc = manifest.get("leaf_count")
    if mc is not None and _as_int(mc) != len(leaves):
        mism.append(f"leaf_count {mc}≠{len(leaves)}")
    # seal_count is committed by the server manifest too (api/audit.py):
    # without this check every Merkle seal could be stripped from a
    # certified bundle while the signed manifest still matched the leaves,
    # removing the tamper-evidence the seals provide.
    sc = manifest.get("seal_count")
    if sc is not None and _as_int(sc) != len(seals):
        mism.append(f"seal_count {sc}≠{len(seals)}")
    # Content digest: first_seq/last_seq/leaf_count/seal_count bind only the
    # counts and endpoints, so a substitution that swaps an interior leaf for
    # another (freed seq re-used, count unchanged) slips past them.
    # ``leaves_digest`` commits the exact (seq, leaf_hash) set; a mismatch is
    # record substitution or suppression → FAIL.  (Its presence is also what
    # lets an intact bundle claim ATTESTED — see _evaluate_attestation.)
    md = manifest.get("leaves_digest")
    if md is not None and md != _leaves_digest(leaves):
        mism.append("leaves_digest mismatch (exported leaf set altered)")
    if mism:
        if verified:
            what = ("signed manifest commits to records that are not present — "
                    "records suppressed or substituted")
        else:
            what = ("the manifest (signature not verified) commits to records that "
                    "are not present — records suppressed or substituted, or the "
                    "manifest edited")
        return res._fail(exp_first, what + " (" + ", ".join(mism) + ")")
    # ``proofs_digest`` commits the exact inclusion proof set. Each proof was
    # checked in step 4 (so an altered one has already failed with its seq);
    # what is left to catch is a proof dropped, so that its seal reads as
    # "root not recomputed" instead of proved, added, or relabelled. An
    # export from before proofs existed commits none, and is read as before.
    pd = manifest.get("proofs_digest")
    if pd is not None and pd != _proofs_digest(proofs):
        manifest_named = ("the signed manifest" if verified
                          else "the manifest, whose signature was not verified")
        return res._fail(
            None, f"inclusion proof set does not match {manifest_named} "
                  "(proofs_digest mismatch)")
    return None
