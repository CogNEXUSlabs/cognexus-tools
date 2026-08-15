"""Offline verification of a CogNexus audit evidence bundle (FR-3, WS2 §2.4).

Zero network, zero server trust.  Given a bundle directory (or ``.zip``) produced
by ``GET /api/v1/audit/export``, this recomputes every leaf hash, checks the
hash-chain linkage and Merkle roots, and verifies Ed25519 signatures against the
bundled public keys.  It is the Art. 12 "offline reconstruction" artifact.

Bundle layout::

    leaves.jsonl    one JSON leaf record per line (canonical body + chain meta)
    seals.jsonl     one JSON seal record per line
    keys.json       [{key_id, public_key_pem, ...}]  (keys.pem is the same, PEM-only)
    manifest.json   range / counts / key ids

Leaf-hash, chain, and Merkle integrity verify with the standard library alone.
**Signature** verification needs the ``cryptography`` package; install the extra::

    pip install 'artzain[verify]'

Without it, signatures are reported as ``skipped`` (everything else still runs).
"""

from __future__ import annotations

import base64
import hashlib
import json
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

_GENESIS_HASH = "0" * 64

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

    def _fail(self, seq: Optional[int], msg: str) -> "VerifyResult":
        self.ok = False
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


# ---------------------------------------------------------------------------
# RFC 6962 Merkle (stdlib mirror of services/merkle.py)
# ---------------------------------------------------------------------------


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
# Bundle loading
# ---------------------------------------------------------------------------


def _read_jsonl(text: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
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
    return {"leaves": leaves, "seals": seals, "keys": keys, "manifest": manifest}


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def verify_bundle(bundle_path: str | Path) -> VerifyResult:
    """Verify a bundle directory or .zip. Returns a :class:`VerifyResult`."""
    path = Path(bundle_path)
    res = VerifyResult()
    if not path.exists():
        return res._fail(None, f"bundle path not found: {path}")

    try:
        bundle = _load_bundle(path)
    except Exception as exc:
        return res._fail(None, f"could not read bundle: {exc}")

    leaves = sorted(bundle["leaves"], key=lambda r: int(r.get("seq", 0)))
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
    for leaf in leaves:
        seq = int(leaf.get("seq", 0))
        leaf_by_seq[seq] = leaf

        recomputed = _leaf_hash(leaf)
        if recomputed != leaf.get("leaf_hash"):
            return res._fail(seq, f"leaf_hash mismatch at seq {seq} (record tampered)")

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

    # 3) Seals: hash + signature + Merkle root over covered leaves.
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
    prev_seal_hash: Optional[str] = None
    for seal in sorted(seals, key=lambda r: int(r.get("first_seq", 0))):
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

        first_seq = int(seal.get("first_seq", 0))
        last_seq = int(seal.get("last_seq", 0))
        expected = last_seq - first_seq + 1
        covered = [leaf_by_seq[s] for s in range(first_seq, last_seq + 1) if s in leaf_by_seq]
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
        elif within_window:
            # The bundle spans this seal's range but leaves are missing → deletion.
            missing = [s for s in range(first_seq, last_seq + 1) if s not in leaf_by_seq]
            return res._fail(
                missing[0] if missing else first_seq,
                f"deleted leaf — seal {seal.get('seal_id')} expects {expected} leaves "
                f"in seq {first_seq}..{last_seq}, found {len(covered)} (missing {missing})",
            )
        elif dense and seal_starts_inside:
            # Contiguous (full) export, yet a signed seal commits to leaves past
            # the last one present → the tail was truncated.
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

    return res
