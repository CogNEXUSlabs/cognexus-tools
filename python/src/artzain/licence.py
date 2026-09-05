"""Offline licence artifacts: CSR, anchors, Sealed Usage Attestations (WS-6).

The client half of the licence flow. Everything here works on **files**, with
no network at any point — that is the requirement, not an optimisation: a
Sovereign or air-gapped install exports an attestation, a human carries it out
on whatever medium they already use, and it is verified on the other side.

Mirrors ``application/security/attestation.py`` byte for byte. The two are
deliberately separate implementations of one wire format rather than shared
code (the SDK is stdlib-first and must not import the server), so the
cross-package tests are what keep them honest. Trust *evaluation* is the
exception and is imported from :mod:`artzain.audit_verify`: "does this chain
to the Evidence Root" must have exactly one answer.

Three verdicts, the same three the audit verifier uses:

* ``VERIFIED, ATTESTED`` — intact, and signed by a key certified under the
  pinned Evidence Root for a certificate whose licence and install match the
  attestation and whose validity covers the period.
* ``VERIFIED, SELF-ATTESTED`` — intact and internally consistent, but nothing
  ties the signing key to CogNEXUS. A key the reporting party generated
  themselves says only that the file was not edited after they signed it.
* ``FAILED`` — a check the artifact must pass did not.

Signature checks need ``cryptography``; without it hashes and structure still
verify, signatures report as skipped, and the verdict is capped at
SELF-ATTESTED — an unchecked anchor is never reported as a passed anchor.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from artzain import audit_verify as _av
from artzain.audit_verify import _canonical_pem, validated_deployment_certificates


def _root_pin() -> Optional[str]:
    """The pinned Evidence Root fingerprint, read at call time.

    Read through the module rather than bound at import, so a caller (or a
    test root) that sets ``audit_verify.EVIDENCE_ROOT_FINGERPRINT`` changes
    what this verifier pins against, exactly as it does for bundles.
    """
    return _av.EVIDENCE_ROOT_FINGERPRINT


ANCHOR_FORMAT = "cognexus-chain-anchor"
ANCHOR_REQUEST_FORMAT = "cognexus-anchor-request"
ATTESTATION_FORMAT = "cognexus-usage-attestation"
CSR_FORMAT = "cognexus-licence-csr"
DEPLOYMENT_CERT_FORMAT = "cognexus-licence-certificate"

#: Mirrors ``security.attestation.ATTESTATION_FIELDS``. Enforced here too:
#: the verifier is where the "counts and hashes only" boundary can actually be
#: held, because it is the one step that runs on artifacts nobody in this
#: process constructed.
ATTESTATION_FIELDS = frozenset({
    "format", "format_version", "licence_id", "install_id",
    "period_start", "period_end", "billable_decisions",
    "merkle_root_open", "merkle_root_close", "first_seq", "last_seq",
    "continuity", "sig", "signer_key_id",
})

ANCHOR_FIELDS = frozenset({
    "format", "format_version", "install_id", "anchored_at", "merkle_root",
    "leaf_count", "last_seq", "billable_through", "sig", "signer_key_id",
})

#: Every key the continuity proof object may carry.
CONTINUITY_FIELDS = frozenset({"format_version", "seals", "digest"})

SEAL_BODY_FIELDS = (
    "seal_id", "first_seq", "last_seq", "merkle_root", "prev_seal_hash",
    "sealed_at",
)


CERTIFICATE_BUNDLE_FORMAT = "cognexus-licence-certificate-bundle"


def as_certificate_chain(doc: Any) -> dict[str, Any]:
    """Normalise whatever the operator was handed into a certificate chain.

    Three shapes arrive at the same commands and all three are legitimate: the
    bundle ``issue_deployment_cert.py --csr`` writes, the ``certificates.json``
    inside an audit evidence bundle, and a bare certificate. They differ only
    in where the deployment certificate sits, and a verifier that understands
    one of them reports "no certificate chain" for the other two — a correct
    chain silently downgraded to SELF-ATTESTED, which is the failure mode
    hardest for an operator to diagnose.
    """
    if not isinstance(doc, dict):
        return {}
    chain: dict[str, Any] = {}
    if doc.get("root_public_key_pem"):
        chain["root_public_key_pem"] = doc["root_public_key_pem"]
    if isinstance(doc.get("issuing_certificates"), list):
        chain["issuing_certificates"] = list(doc["issuing_certificates"])
    deployment = []
    if isinstance(doc.get("deployment_certificates"), list):
        deployment.extend(doc["deployment_certificates"])
    if isinstance(doc.get("certificate"), dict):
        deployment.append(doc["certificate"])
    if doc.get("format") == DEPLOYMENT_CERT_FORMAT:
        deployment.append(doc)
    if deployment:
        chain["deployment_certificates"] = deployment
    return chain


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _signed_hash(body: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(body)).hexdigest()


def _crypto_available() -> bool:
    try:
        from cryptography.hazmat.primitives.serialization import (  # noqa: F401
            load_pem_public_key,
        )
    except Exception:
        return False
    return True


def _verify_sig(record: dict[str, Any], public_key_pem: str) -> Optional[bool]:
    """``True``/``False``, or ``None`` when cryptography is unavailable."""
    try:
        import base64

        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
    except Exception:
        return None
    body = {k: v for k, v in record.items() if k not in ("sig", "signer_key_id")}
    try:
        pub = load_pem_public_key(public_key_pem.encode("ascii"))
        sig = base64.urlsafe_b64decode((record.get("sig") or "") + "==")
        pub.verify(sig, _signed_hash(body).encode("ascii"))
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def _parse_ts(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        ts = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def _as_int(value: Any) -> Optional[int]:
    """Whole numbers only — ``true`` and ``NaN`` survive ``json.loads``."""
    if isinstance(value, bool):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


@dataclass
class AttestationResult:
    ok: bool = True
    error: Optional[str] = None
    signature_checked: bool = False
    billable_decisions: Optional[int] = None
    period: Optional[str] = None
    anchors_checked: int = 0
    #: Anchors that were supplied but could not be checked (no
    #: ``cryptography``). Never folded into ``anchors_checked``: "I could not
    #: look" and "I looked and it was fine" are different statements.
    anchors_unverifiable: int = 0
    warnings: list[str] = field(default_factory=list)
    #: Whether any pair of anchors actually bracketed this period's usage.
    #: False means the count rests on the seal chain's arithmetic alone.
    usage_bounded: bool = False
    #: Leaves between the newest anchor before the period and the period's
    #: own opening seq. They belong in an adjacent report; a single artifact
    #: cannot tell whether they got one.
    opening_gap: Optional[int] = None
    #: How far the chain ran past its newest anchor, when the caller supplied
    #: anchors. Reported rather than hidden, and never clamped at zero.
    tail_leaves: Optional[int] = None
    seconds_since_anchor: Optional[int] = None
    #: "ATTESTED" | "SELF-ATTESTED" when ``ok``; ``None`` when FAILED.
    attestation: Optional[str] = None
    attestation_reasons: list[str] = field(default_factory=list)
    certificates_checked: int = 0
    evidence_root_fingerprint: Optional[str] = None
    root_fingerprint_overridden: bool = False

    def _fail(self, msg: str) -> "AttestationResult":
        self.ok = False
        self.attestation = None
        if self.error is None:
            self.error = msg
        return self

    def _self_attested(self, reason: str) -> None:
        self.attestation = "SELF-ATTESTED"
        self.attestation_reasons.append(reason)

    @property
    def verdict(self) -> str:
        if not self.ok:
            return "FAILED"
        return f"VERIFIED, {self.attestation or 'SELF-ATTESTED'}"


# ---------------------------------------------------------------------------
# Certificate signing request
# ---------------------------------------------------------------------------


def make_csr(*, install_id: str, public_key_pem: str,
             deployment_class: str = "private",
             customer_id: Optional[str] = None) -> dict[str, Any]:
    """A certificate signing request: this install's **public** key.

    There is no flow in which a private key leaves the deployment. The CSR is
    unsigned on purpose — it asserts nothing that needs proving, and the
    certificate that comes back is what binds the key to an entitlement.

    The PEM is checked here rather than in the CLI, and rejected unless it is
    a public key. The two files sit side by side in the key directory with
    names four characters apart (``audit_signing_key.pub.pem`` and
    ``audit_signing_key.pem``); a typo must not be able to walk the
    deployment's Ed25519 signing key out of the boundary in a file the tool
    then describes as public-only.
    """
    pem = (public_key_pem or "").strip()
    if "PRIVATE KEY" in pem:
        raise ValueError(
            "that is a PRIVATE key. A CSR carries the public half only — "
            "check you passed audit_signing_key.pub.pem, not "
            "audit_signing_key.pem. Nothing has been written.")
    if not pem.startswith("-----BEGIN PUBLIC KEY-----"):
        raise ValueError("public_key_pem must be a PEM public key "
                         "(-----BEGIN PUBLIC KEY-----)")
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        load_pem_public_key(_canonical_pem(pem).encode("ascii"))
    except ImportError:
        pass  # stdlib-only install: the header check above is what we have
    except Exception as exc:
        raise ValueError(f"public_key_pem is not a usable public key: {exc}") from exc

    return {
        "format": CSR_FORMAT,
        "format_version": 1,
        "install_id": install_id,
        "deployment_class": deployment_class,
        "customer_id": customer_id,
        "public_key": _canonical_pem(pem),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Attestation verification
# ---------------------------------------------------------------------------


def _seal_hash(entry: dict[str, Any]) -> str:
    return hashlib.sha256(
        _canonical({k: entry.get(k) for k in SEAL_BODY_FIELDS})).hexdigest()


def _verify_continuity(attestation: dict[str, Any]) -> tuple[bool, str, int]:
    """Recompute the seal chain. ``(ok, reason, summed_billable)``."""
    proof = attestation.get("continuity")
    if not isinstance(proof, dict):
        return False, "missing continuity proof", 0
    if _as_int(proof.get("format_version")) != 2:
        return False, "unsupported continuity proof version", 0
    seals = proof.get("seals")
    if not isinstance(seals, list):
        return False, "malformed continuity proof", 0
    # The proof object is inside the allowlist boundary too. Checking only the
    # top level left one nesting level in which a signed export could carry
    # invoice ids, amounts and payment status — ground rule 7 is a legal
    # boundary, and a boundary with a hole in it is not one.
    extra = set(proof) - CONTINUITY_FIELDS
    if extra:
        return False, (f"continuity proof carries fields outside the "
                       f"allowlist: {', '.join(sorted(extra))}"), 0
    if hashlib.sha256(_canonical(list(seals))).hexdigest() != proof.get("digest"):
        return False, "continuity digest does not match its seals", 0

    first = _as_int(attestation.get("first_seq"))
    last = _as_int(attestation.get("last_seq"))
    if first is None or last is None:
        return False, "malformed sequence fields", 0

    if not seals:
        # An empty period still carries a chain *position* (``first == last``,
        # the head as the period closed): reported at 0 it would read to the
        # anchor cross-check as a chain rolled back to nothing.
        if first != last:
            return False, "empty continuity proof over a non-empty range", 0
        if attestation.get("merkle_root_open") or attestation.get("merkle_root_close"):
            return False, "empty continuity proof declares Merkle roots", 0
        return True, "empty period", 0

    total = 0
    prev: Optional[dict[str, Any]] = None
    for entry in seals:
        if not isinstance(entry, dict):
            return False, "malformed seal entry", 0
        extra = set(entry) - set(SEAL_BODY_FIELDS) - {"seal_hash", "billable"}
        if extra:
            return False, (f"seal entry carries unexpected fields: "
                           f"{', '.join(sorted(extra))}"), 0
        e_first = _as_int(entry.get("first_seq"))
        e_last = _as_int(entry.get("last_seq"))
        billable = _as_int(entry.get("billable"))
        if e_first is None or e_last is None or billable is None:
            return False, f"malformed seal {entry.get('seal_id')}", 0
        if e_last < e_first:
            return False, f"seal {entry.get('seal_id')} ends before it begins", 0
        if _seal_hash(entry) != entry.get("seal_hash"):
            return False, (f"seal {entry.get('seal_id')} does not hash to its "
                           "declared seal_hash"), 0
        if billable < 0 or billable > (e_last - e_first + 1):
            return False, (f"seal {entry.get('seal_id')} claims {billable} "
                           f"billable of {e_last - e_first + 1} leaves"), 0
        if prev is None:
            if e_first != first:
                return False, (f"the proof opens at seq {e_first} but the "
                               f"attestation declares {first}"), 0
        else:
            if entry.get("prev_seal_hash") != prev.get("seal_hash"):
                return False, (f"seal {entry.get('seal_id')} does not link to "
                               f"seal {prev.get('seal_id')}"), 0
            # No seq-adjacency check: ``audit_leaves.seq`` is a BIGSERIAL and
            # a rolled-back write burns a value, so a permanent hole between
            # two consecutive seals is ordinary Postgres behaviour, not
            # tampering. Linkage is what proves no seal was dropped.
            if e_first <= (_as_int(prev.get("last_seq")) or 0):
                return False, (f"seal {entry.get('seal_id')} overlaps seal "
                               f"{prev.get('seal_id')}, which ends at "
                               f"{prev.get('last_seq')}"), 0
        total += billable
        prev = entry

    if _as_int(prev.get("last_seq")) != last:
        return False, (f"the proof closes at seq {prev.get('last_seq')} but "
                       f"the attestation declares {last}"), 0
    if seals[0].get("merkle_root") != attestation.get("merkle_root_open"):
        return False, "merkle_root_open is not the first seal's root", 0
    if prev.get("merkle_root") != attestation.get("merkle_root_close"):
        return False, "merkle_root_close is not the last seal's root", 0
    return True, "ok", total


def root_signed_issuer_keys(certificates: Optional[dict[str, Any]],
                            evidence_root_fingerprint: Optional[str] = None,
                            ) -> list[str]:
    """Issuing public keys from *certificates* that the root actually signed.

    The anchor cross-check verifies anchors under a key the caller supplies —
    and the caller is often the party being checked. A key pulled out of a
    root-signed issuing certificate is a different thing from a PEM handed
    over loose, and the difference has to be visible: otherwise "anchors
    checked: 2" means the same whether CogNEXUS signed them or the reporting
    party did.
    """
    if not isinstance(certificates, dict):
        return []
    root_pem = certificates.get("root_public_key_pem") or ""
    if not root_pem or not _crypto_available():
        return []
    pin = (evidence_root_fingerprint if evidence_root_fingerprint is not None
           else _root_pin())
    if pin and _av._pem_fingerprint(root_pem) != pin.strip().lower():
        return []
    root_kid = _av._pem_key_id(root_pem)
    keys = []
    for cert in certificates.get("issuing_certificates") or []:
        if not isinstance(cert, dict):
            continue
        if cert.get("issuer_key_id") != root_kid:
            continue
        if not _av._cert_sig_ok(cert, root_pem):
            continue
        if cert.get("public_key"):
            keys.append(cert["public_key"])
    return keys


def verify_attestation(attestation: dict[str, Any],
                       deployment_public_key_pem: Optional[str] = None,
                       anchors: Optional[list[dict[str, Any]]] = None,
                       issuer_public_key_pem: Optional[str] = None,
                       certificates: Optional[dict[str, Any]] = None,
                       evidence_root_fingerprint: Optional[str] = None,
                       ) -> AttestationResult:
    """Verify a Sealed Usage Attestation offline.

    *certificates* is the chain the deployment was issued (root public key,
    issuing certificates, deployment certificates). Without it the result is
    capped at SELF-ATTESTED: a signature verifies against whatever key the
    caller hands over, and the party supplying the file can generate a key.

    With *anchors* and the issuer key, also cross-checks the attested position
    and usage against what CogNEXUS previously countersigned — the check that
    makes the count hard to understate.
    """
    res = AttestationResult()
    pin = (evidence_root_fingerprint if evidence_root_fingerprint is not None
           else _root_pin())
    res.evidence_root_fingerprint = pin
    res.root_fingerprint_overridden = bool(
        evidence_root_fingerprint is not None
        and (evidence_root_fingerprint or "").strip().lower()
        != (_root_pin() or "").strip().lower())

    if not isinstance(attestation, dict):
        return res._fail("attestation is not an object")
    if attestation.get("format") != ATTESTATION_FORMAT:
        return res._fail("not a usage attestation")
    if _as_int(attestation.get("format_version")) != 2:
        return res._fail("unsupported attestation version")
    extra = set(attestation) - ATTESTATION_FIELDS
    if extra:
        return res._fail(f"attestation carries fields outside the allowlist: "
                         f"{', '.join(sorted(extra))}")

    res.period = f"{attestation.get('period_start')} .. {attestation.get('period_end')}"
    if not attestation.get("install_id"):
        return res._fail("attestation names no install")
    if not attestation.get("licence_id"):
        return res._fail("attestation names no licence")
    period_start = _parse_ts(attestation.get("period_start"))
    period_end = _parse_ts(attestation.get("period_end"))
    if period_start is None:
        return res._fail("period_start is not a timestamp")
    if period_end is None:
        return res._fail("period_end is not a timestamp")

    ok, reason, summed = _verify_continuity(attestation)
    if not ok:
        return res._fail(reason)

    first = _as_int(attestation.get("first_seq"))
    last = _as_int(attestation.get("last_seq"))
    count = _as_int(attestation.get("billable_decisions"))
    if count is None:
        return res._fail("malformed count field")
    if last < first:
        return res._fail("period ends before it begins")
    if count < 0:
        return res._fail("negative billable count")
    if count != summed:
        return res._fail(f"billable count {count} is not the sum of the "
                         f"per-seal subtotals ({summed})")
    res.billable_decisions = count

    if deployment_public_key_pem:
        verdict = _verify_sig(attestation, deployment_public_key_pem)
        if verdict is None:
            res.warnings.append(
                "cryptography not installed — signature NOT verified. "
                "Install with: pip install 'artzain[verify]'")
        elif not verdict:
            return res._fail("signature invalid")
        else:
            res.signature_checked = True
    else:
        res.warnings.append("no deployment public key supplied — signature not checked")

    # `anchors=[]` means "I looked and there are none" — a materially
    # different statement from `anchors=None` ("I did not look"), and exactly
    # the un-anchored case worth warning about. Only the latter skips.
    if anchors is not None:
        if not issuer_public_key_pem:
            # Silently dropping the anchors would report the most reassuring
            # possible answer to a caller who explicitly asked for the strictest
            # check. One forgotten flag must not read as a clean pass.
            return res._fail(
                "anchors supplied without an issuing public key — an anchor "
                "that cannot be checked cannot be counted (pass --issuer-key)")
        ok, reason = _check_anchors(attestation, anchors, issuer_public_key_pem, res)
        if not ok:
            return res._fail(reason)
    else:
        # Silence here would be the most reassuring possible output for the
        # least checked case: every timestamp in the artifact was written by
        # the party reporting the usage.
        res.warnings.append(
            "no anchors supplied — nothing external bounds this report. Export "
            "them with 'artzain licence anchors' and pass --anchors/--issuer-key")

    _evaluate_attestation(res, attestation,
                          deployment_public_key_pem=deployment_public_key_pem,
                          certificates=certificates, root_fingerprint=pin,
                          period_start=period_start, period_end=period_end)
    return res


def usage_bounds(anchors: list[dict[str, Any]], first_seq: int, last_seq: int
                 ) -> tuple[Optional[int], Optional[int]]:
    """``(lower, upper)`` bounds on the billable count over ``[first, last]``.

    ``billable_through`` is monotone in chain position, so two countersigned
    samples bracket the usage between them. Bounds are selected by **sequence**
    rather than by signing time: where an anchor sits in the chain is what
    makes its number comparable, and when CogNEXUS happened to sign it is not.

    * *lower*: any two anchors at positions ``p < q`` with ``first-1 <= p`` and
      ``q <= last`` bracket an interval wholly inside the attested range, so
      the count cannot be below ``through(q) - through(p)``. The widest such
      pair is ``max(through) - min(through)`` across every anchor in
      ``[first-1, last]``.
    * *upper*: an anchor at or below ``first-1`` and one at or above ``last``
      bracket an interval that wholly *contains* the attested range.

    Neither needs an anchor at any particular position. That matters: an
    earlier design demanded one exactly at ``first-1`` and silently skipped
    the whole check otherwise — a check the operator could switch off by
    choosing where the period opens, and one that also rejected honest reports
    under every cadence the plan prescribes.

    Mirrors ``security.attestation.usage_bounds``.
    """
    points = []
    for anchor in anchors:
        seq = _as_int(anchor.get("last_seq"))
        through = _as_int(anchor.get("billable_through"))
        if seq is not None and through is not None:
            points.append((seq, through))
    if not points:
        return None, None

    inside = [t for seq, t in points if first_seq - 1 <= seq <= last_seq]
    lower = (max(inside) - min(inside)) if len(inside) >= 2 else None

    before = [t for seq, t in points if seq <= first_seq - 1]
    after = [t for seq, t in points if seq >= last_seq]
    upper = (min(after) - max(before)) if before and after else None
    return lower, upper


def _check_anchors(attestation: dict[str, Any], anchors: list[dict[str, Any]],
                   issuer_pem: str, res: AttestationResult) -> tuple[bool, str]:
    """Cross-check against CogNEXUS-countersigned anchors.

    Anchors that fail their own signature are ignored, not trusted: forged
    anchors must not be able to fail a genuine attestation. Anchors that
    *cannot* be checked are counted separately and reported — never silently
    dropped, which would turn a missing dependency into a clean pass.
    """
    close_seq = _as_int(attestation.get("last_seq")) or 0
    open_seq = _as_int(attestation.get("first_seq")) or 0
    install_id = attestation.get("install_id")
    start = _parse_ts(attestation.get("period_start"))
    end = _parse_ts(attestation.get("period_end"))

    roots_by_seq: dict[int, Any] = {}
    proof = attestation.get("continuity")
    if isinstance(proof, dict):
        for entry in proof.get("seals") or []:
            if isinstance(entry, dict):
                seq = _as_int(entry.get("last_seq"))
                if seq is not None:
                    roots_by_seq[seq] = entry.get("merkle_root")

    usable: list[tuple[datetime, dict[str, Any]]] = []
    for anchor in anchors:
        if not isinstance(anchor, dict) or anchor.get("format") != ANCHOR_FORMAT:
            continue
        if set(anchor) - ANCHOR_FIELDS:
            continue
        verdict = _verify_sig(anchor, issuer_pem)
        if verdict is None:
            res.anchors_unverifiable += 1
            continue
        if verdict is not True:
            continue
        if anchor.get("install_id") != install_id:
            continue
        at = _parse_ts(anchor.get("anchored_at"))
        if at is None:
            continue
        usable.append((at, anchor))

    if res.anchors_unverifiable:
        res.warnings.append(
            f"{res.anchors_unverifiable} anchor(s) supplied but NOT checked — "
            "cryptography is not installed, so the cross-check that bounds "
            "the count did not run. Install with: pip install 'artzain[verify]'")

    if not usable:
        if not res.anchors_unverifiable:
            res.warnings.append(
                "no signed anchor covers this period — the chain's position in "
                "time rests on the deployment's own clock")
        return True, "ok"

    usable.sort(key=lambda pair: pair[0])
    newest_at, newest = usable[-1]

    # --- position: what CogNEXUS saw, and when -----------------------------
    for at, anchor in usable:
        anchored_seq = _as_int(anchor.get("last_seq"))
        if anchored_seq is None:
            continue
        in_window = (end is None or at <= end)

        if in_window:
            res.anchors_checked += 1
            if anchored_seq > close_seq:
                return False, (
                    f"attestation closes at seq {close_seq} but an anchor "
                    f"signed at {anchor.get('anchored_at')} already recorded "
                    f"seq {anchored_seq} — an append-only chain cannot go "
                    "backwards")
        elif anchored_seq < close_seq:
            return False, (
                f"attestation closes at seq {close_seq} but an anchor signed "
                f"later, at {anchor.get('anchored_at')}, recorded only seq "
                f"{anchored_seq}")

        declared_root = roots_by_seq.get(anchored_seq)
        if declared_root is not None and anchor.get("merkle_root") != declared_root:
            return False, (
                f"an anchor signed at {anchor.get('anchored_at')} recorded "
                f"root {anchor.get('merkle_root')} at seq {anchored_seq}, but "
                f"the attestation's seal at that position declares "
                f"{declared_root} — the chain was rebuilt")

    # --- usage: what CogNEXUS countersigned --------------------------------
    lower, upper = usage_bounds([a for _at, a in usable], open_seq, close_seq)
    res.usage_bounded = lower is not None or upper is not None
    count = _as_int(attestation.get("billable_decisions")) or 0
    if lower is not None and count < lower:
        return False, (f"attestation reports {count} billable decisions but "
                       f"CogNEXUS already countersigned {lower} over "
                       "this span")
    if upper is not None and count > upper:
        return False, (f"attestation reports {count} billable decisions but a "
                       f"later anchor puts at most {upper} in this span")
    if not res.usage_bounded:
        res.warnings.append(
            "no pair of anchors brackets this period's usage — the count is "
            "bounded by the seal chain's arithmetic but by nothing external. "
            "Anchor at each period close to bound it")

    # --- what this artifact alone cannot settle ----------------------------
    # The newest anchor at or before the period opens says where the chain had
    # reached before it started. If the period opens well past that, the
    # leaves in between are not in *this* report — they may have been in an
    # earlier one, or nowhere. A single attestation cannot tell those apart,
    # so the gap is reported rather than judged; whoever holds the series
    # checks contiguity across consecutive periods directly.
    floor: Optional[dict[str, Any]] = None
    if start is not None:
        for at, anchor in usable:
            if at > start:
                break
            floor = anchor
    if floor is not None:
        floor_seq = _as_int(floor.get("last_seq"))
        if floor_seq is not None and open_seq > floor_seq + 1:
            res.opening_gap = open_seq - floor_seq - 1
            res.warnings.append(
                f"the period opens at seq {open_seq} but the newest anchor "
                f"before it recorded seq {floor_seq} — {res.opening_gap} "
                "leaves are not covered by this report and must appear in an "
                "adjacent one")

    newest_seq = _as_int(newest.get("last_seq"))
    if newest_seq is not None:
        res.tail_leaves = close_seq - newest_seq
    res.seconds_since_anchor = int(
        (datetime.now(timezone.utc) - newest_at).total_seconds())
    if res.anchors_checked == 0:
        res.warnings.append(
            "no signed anchor covers this period — the chain's position in "
            "time rests on the deployment's own clock")
    return True, "ok"


def _evaluate_attestation(res: AttestationResult, attestation: dict[str, Any],
                          *, deployment_public_key_pem: Optional[str],
                          certificates: Optional[dict[str, Any]],
                          root_fingerprint: Optional[str],
                          period_start: datetime,
                          period_end: datetime) -> None:
    """Set ``res.attestation`` for a structurally intact attestation.

    Never fails the artifact for a *missing* certificate — absence caps the
    claim at SELF-ATTESTED and is named in ``attestation_reasons``. A
    certificate that actively contradicts the attestation is different: that is
    a claim under a licence the deployment does not hold, and it fails.
    """
    if not certificates or not (certificates.get("deployment_certificates")
                                or certificates.get("issuing_certificates")):
        return res._self_attested(
            "no certificate chain supplied — the signing key is not tied to "
            "CogNEXUS, so this is the reporting party's own word")
    if not _crypto_available():
        return res._self_attested(
            "cryptography not installed — certificate chain not evaluated")
    if not res.signature_checked:
        return res._self_attested(
            "attestation signature not verified — a certificate cannot bind a "
            "signature that was not checked")
    if res.anchors_unverifiable:
        return res._self_attested(
            "anchors supplied but not checked — the usage cross-check did not run")

    deploy, reason, checked, notes = validated_deployment_certificates(
        certificates, root_fingerprint)
    res.certificates_checked += checked
    res.attestation_reasons.extend(notes)
    if reason is not None:
        return res._self_attested(reason)

    signer_pem = _canonical_pem(deployment_public_key_pem)
    matching = [c for c in deploy
                if _canonical_pem(c.get("public_key") or "") == signer_pem]
    if not matching:
        return res._self_attested(
            "the key that verified this attestation is not the subject of any "
            "certificate in the chain")

    # A deployment can hold several certificates for one key — renewals
    # accumulate, and a licence change is a re-issue. So agreement is checked
    # across the whole set before disagreement is: one stale certificate
    # naming last year's licence must not fail an attestation that a current
    # certificate covers exactly. Only when *nothing* agrees does a
    # contradiction become a failure, and it is a failure rather than a
    # downgrade because it is a claim under an entitlement this key was never
    # issued.
    covering, contradiction = [], None
    for cert in matching:
        nb = _parse_ts(cert.get("not_before"))
        na = _parse_ts(cert.get("not_after"))
        if nb is None or na is None:
            continue
        cert_install = cert.get("install_id")
        cert_licence = cert.get("licence_id")
        if cert_install and cert_install != attestation.get("install_id"):
            contradiction = contradiction or (
                f"attestation claims install {attestation.get('install_id')} "
                f"but its certificate was issued to {cert_install}")
            continue
        if cert_licence and cert_licence != attestation.get("licence_id"):
            contradiction = contradiction or (
                f"attestation claims licence {attestation.get('licence_id')} "
                f"but its certificate carries {cert_licence}")
            continue
        if not cert_install:
            res.attestation_reasons.append(
                f"certificate {cert.get('cert_id')} names no install")
            continue
        if not cert_licence:
            res.attestation_reasons.append(
                f"certificate {cert.get('cert_id')} names no licence")
            continue
        # Valid through the period's close, which is the point the usage
        # accrued to. Demanding it also predate the period's *open* sounds
        # stricter but is not: it makes the first period after certification
        # permanently unattestable — a certificate is issued today, the month
        # it lands in began before it, and the operator can do nothing about
        # that. What matters is said out loud instead.
        if nb <= period_end <= na:
            covering.append(cert)
            if nb > period_start:
                res.attestation_reasons.append(
                    f"certificate {cert.get('cert_id')} was issued at {nb.isoformat()}, "
                    f"after this period opened — usage before that point is "
                    "covered by whatever certificate was in force then, not "
                    "by this one")

    if covering:
        res.attestation = "ATTESTED"
        return
    if contradiction:
        res._fail(contradiction)
        return
    return res._self_attested(
        "no certificate for the signing key names this licence and install "
        "and is valid across the whole attested period")


def verify_certificate_offline(certificate: dict[str, Any],
                               certificates: Optional[dict[str, Any]] = None,
                               evidence_root_fingerprint: Optional[str] = None,
                               ) -> tuple[bool, str, bool]:
    """Does *certificate* chain to the Evidence Root? ``(ok, reason, pinned)``.

    Used by ``artzain licence install`` before anything touches disk. A
    certificate is a claim about what a deployment is entitled to; installing
    one without checking it, and then printing its validity window back to the
    operator as fact, is worse than not having the command.

    ``pinned`` is ``False`` when the chain was checked against the root the
    caller supplied rather than a fingerprint this verifier pins. That is the
    normal state before the Evidence Root ceremony publishes one, and it is a
    weaker statement — it says the certificate is internally consistent with
    the root in the same file, not that the root is CogNEXUS's. The caller has
    to say so; refusing outright would make the certificate flow unusable
    until the ceremony, and passing silently would overclaim.
    """
    if not isinstance(certificate, dict):
        return False, "not an object", False
    if certificate.get("format") != DEPLOYMENT_CERT_FORMAT:
        return False, "not a deployment certificate", False
    if not _crypto_available():
        return False, ("cryptography not installed — a certificate cannot be "
                       "installed unverified. pip install 'artzain[verify]'"), False

    # ONLY the certificate under test. Merging it into a chain that already
    # carries deployment certificates meant a forged blob could ride along
    # unchecked and then be matched by public key against a genuine
    # certificate that did chain — reported as verified, with the forged
    # licence, install and validity window printed back as fact.
    chain = dict(certificates or {})
    chain["deployment_certificates"] = [certificate]
    root_pem = chain.get("root_public_key_pem") or ""
    pin = (evidence_root_fingerprint if evidence_root_fingerprint is not None
           else _root_pin())
    pinned = bool(pin)
    if not pin:
        if not root_pem:
            return False, "no Evidence Root public key supplied", False
        pin = _av._pem_fingerprint(root_pem)

    deploy, reason, _checked, _notes = validated_deployment_certificates(chain, pin)
    if reason is not None:
        return False, reason, pinned
    if not deploy:
        return False, "this certificate does not chain to the root", pinned
    return True, "ok", pinned
