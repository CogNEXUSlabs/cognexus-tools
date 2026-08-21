"""Offline verification of a CogNexus audit evidence bundle (FR-3, WS2 §2.4).

Zero network, zero server trust.  Given a bundle directory (or ``.zip``) produced
by ``GET /api/v1/audit/export``, this recomputes every leaf hash, checks the
hash-chain linkage and Merkle roots, and verifies Ed25519 signatures against the
bundled public keys.  It is the Art. 12 "offline reconstruction" artifact.

Bundle layout::

    leaves.jsonl        one JSON leaf record per line (canonical body + chain meta)
    seals.jsonl         one JSON seal record per line
    keys.json           [{key_id, public_key_pem, ...}]  (keys.pem is the same, PEM-only)
    manifest.json       range / counts / key ids (optionally Ed25519-signed)
    certificates.json   optional certificate chain to the CogNEXUS Evidence Root
    key-rotations.json  optional countersigned signing-key handovers (WS-8)

Leaf-hash, chain, and Merkle integrity verify with the standard library alone.
**Signature** verification needs the ``cryptography`` package; install the extra::

    pip install 'artzain[verify]'

Without it, signatures are reported as ``skipped`` (everything else still runs).

Three-state result (WS-4).  Integrity (``ok``) and provenance
(``attestation``) are separate axes:

* ``FAILED`` (``ok=False``) — chain broken, signature invalid, Merkle root
  mismatch, or a signed manifest that no longer verifies.
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
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

_GENESIS_HASH = "0" * 64

#: Full SHA-256 hex fingerprint of the CogNEXUS Evidence Root public key
#: (canonical SubjectPublicKeyInfo PEM).  ``None`` until the root ceremony
#: publishes it (docs/runbooks/evidence-root-ceremony.md); while ``None`` the
#: verifier reports SELF-ATTESTED only.  Overriding at call time exists for
#: test roots — the CLI states loudly when a non-default root is in use.
EVIDENCE_ROOT_FINGERPRINT: Optional[str] = None

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
    #: The Evidence Root fingerprint the run actually pinned against (the
    #: caller override if supplied, else the module default; ``None``
    #: pre-ceremony).  ``root_fingerprint_overridden`` is ``True`` when the
    #: caller passed a fingerprint that differs from the built-in pin — an
    #: ATTESTED result then attests to *that* root, not the published
    #: CogNEXUS Evidence Root.  Machine consumers must read this flag: the
    #: loud human-readable warning is on the text path only.
    evidence_root_fingerprint: Optional[str] = None
    root_fingerprint_overridden: bool = False

    def _fail(self, seq: Optional[int], msg: str) -> "VerifyResult":
        self.ok = False
        self.attestation = None
        if self.first_bad_seq is None:
            self.first_bad_seq = seq
        if self.error is None:
            self.error = msg
        return self


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
        ([int(l.get("seq", 0)), l.get("leaf_hash")] for l in leaves),
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
    certs: dict[str, Any], root_fingerprint: Optional[str],
) -> tuple[list[dict[str, Any]], Optional[str], int, list[str]]:
    """Deployment certificates that chain to the pinned Evidence Root.

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
    if not root_fingerprint:
        return [], ("no Evidence Root fingerprint pinned (pre-ceremony "
                    "verifier)"), checked, notes
    if _pem_fingerprint(root_pem) != root_fingerprint.strip().lower():
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
    root_fingerprint: Optional[str],
    manifest_trusted: bool,
    manifest_signer_kid: Optional[str] = None,
    manifest_binds_content: bool = False,
) -> None:
    """Set ``res.attestation`` for an intact bundle.

    Never fails the bundle: every problem here caps the claim at
    SELF-ATTESTED and is named in ``attestation_reasons``.
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
    if not root_fingerprint:
        return self_attested(
            "no Evidence Root fingerprint pinned (pre-ceremony verifier)")

    deploy, reason, checked, notes = validated_deployment_certificates(
        certs, root_fingerprint)
    res.certificates_checked += checked
    res.attestation_reasons.extend(notes)
    if reason is not None:
        return self_attested(reason)

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
            "rotations": rotations}


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def verify_bundle(bundle_path: str | Path,
                  root_fingerprint: Optional[str] = None) -> VerifyResult:
    """Verify a bundle directory or .zip. Returns a :class:`VerifyResult`.

    *root_fingerprint* overrides the module-level
    :data:`EVIDENCE_ROOT_FINGERPRINT` pin (test roots only).
    """
    path = Path(bundle_path)
    res = VerifyResult()
    # Record which root this run actually pinned against, before any early
    # return, so even a FAILED result carries it. A caller-supplied
    # fingerprint that differs from the built-in pin is an override: an
    # ATTESTED verdict then attests to that root, not the published one.
    effective_root = root_fingerprint or EVIDENCE_ROOT_FINGERPRINT
    res.evidence_root_fingerprint = effective_root
    res.root_fingerprint_overridden = bool(
        root_fingerprint and root_fingerprint != EVIDENCE_ROOT_FINGERPRINT)
    try:
        return _verify_bundle_body(res, path, effective_root)
    except Exception as exc:  # noqa: BLE001
        # Absolute fail-closed backstop: the verifier's contract is that
        # hostile bundle bytes yield a FAILED result, never a raised
        # exception. The targeted guards below handle the known malformed-
        # input vectors with precise messages; this catches anything
        # unforeseen (e.g. an unhashable signer_key_id reaching a dict lookup).
        return res._fail(None, f"malformed bundle ({type(exc).__name__})")


def _verify_bundle_body(res: VerifyResult, path: Path,
                        effective_root: Optional[str]) -> VerifyResult:
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
    prev_hash: Optional[str] = None
    prev_seq: Optional[int] = None
    leaf_by_seq: dict[int, dict[str, Any]] = {}
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
            res.warnings.append(
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

    # 3) Verify the signed manifest's custody signature UP FRONT (the record-set
    #    cross-check itself stays after the seals). The seal truncation/deletion
    #    heuristics below defer to a trusted, content-committing manifest: when a
    #    signed leaves_digest binds the exact present set, a seal that reaches
    #    past the present leaves is a legitimate boundary seal of a windowed
    #    export, not evidence of a deletion.
    manifest = bundle.get("manifest") or {}
    manifest_trusted = False
    manifest_signer_kid: Optional[str] = None
    if manifest.get("sig"):
        kid = manifest.get("signer_key_id")
        pk = pubkeys.get(kid) if pubkeys is not None else None
        if pubkeys is None:
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
                return res._fail(None, "manifest signature invalid (custody broken)")
            res.signatures_checked += 1
            manifest_trusted = True
            manifest_signer_kid = kid
    elif (bundle.get("certificates") or {}).get("deployment_certificates"):
        res.warnings.append("certified bundle without a signed manifest")
    # A trusted manifest that commits a content digest binds the exact present
    # (seq, leaf_hash) set — the flag the seal heuristics and the attestation
    # gate below both key off.
    manifest_binds_content = manifest_trusted and manifest.get("leaves_digest") is not None

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
            res.warnings.append(
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
        covered = [leaf_by_seq[s] for s in present_sorted
                   if first_seq <= s <= last_seq]
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
            in_range = [s for s in present_sorted if first_seq <= s <= last_seq]
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
        else:
            res.warnings.append(
                f"seal {seal.get('seal_id')} only partially present "
                f"({len(covered)}/{expected} leaves) — boundary of a filtered export, "
                "root not recomputed"
            )
        res.seals_checked += 1

    # 5) Signed manifest record-set cross-check (WS-4 chain of custody).  The
    #    signature was already verified in step 3; here the committed range /
    #    counts / content digest are checked against the leaves present.  A valid
    #    signature whose committed set no longer matches is record suppression or
    #    substitution (FAILURE).  An unverifiable / absent manifest only *caps*
    #    the claim — a non-empty bundle whose signer key is absent already failed
    #    at leaf verification above.
    if manifest_trusted:
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
            return res._fail(
                exp_first,
                "signed manifest commits to records that are not present — "
                "records suppressed or substituted (" + ", ".join(mism) + ")",
            )

    # 5) Provenance (WS-4): does the intact chain also chain to the pinned
    #    Evidence Root?  Never fails the bundle — caps the claim instead.
    try:
        _evaluate_attestation(
            res,
            certs=bundle.get("certificates") or {},
            keys=bundle.get("keys") or [],
            leaves=leaves,
            seals=seals,
            root_fingerprint=effective_root,
            manifest_trusted=manifest_trusted,
            manifest_signer_kid=manifest_signer_kid,
            manifest_binds_content=manifest_binds_content,
        )
    except Exception:  # noqa: BLE001
        # Provenance is a *cap*, never a failure (see module docstring): a
        # malformed certificate structure degrades to SELF-ATTESTED, it does
        # not crash or fail an otherwise-intact bundle.
        res.attestation = "SELF-ATTESTED"
        res.attestation_reasons.append(
            "certificate chain malformed — provenance not evaluated")
    return res
