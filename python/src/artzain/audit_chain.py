"""Cryptographic audit chain for the CogNexus SDK (pure stdlib).

Implements SHA-256 *hash chaining* and *HMAC-SHA-256 per-entry signing* for
the local JSONL audit trail written by :mod:`artzain.events`.

The implementation uses only Python's standard library (``hashlib``,
``hmac``, ``json``, ``os``, ``threading``) to preserve the package's
zero-mandatory-dependency guarantee.

Key management
--------------
``COGNEXUS_AUDIT_HMAC_KEY``
    Hex-encoded 32-byte (64 hex char) HMAC signing key.

    If unset, a random key is generated once per process.  This means the
    signature is useful for detecting in-session tampering but will **not**
    survive a process restart.  For persistent cross-restart verification,
    set this variable to a stable secret and store the key securely.

Wire format (fields added to each record)
-----------------------------------------
``seq``         int  — 1-based monotonic sequence number.
``prev_hash``   str  — SHA-256 hex of the preceding raw line (``"0"*64``
                       for the genesis entry).
``entry_hash``  str  — SHA-256 hex of the canonical record
                       (sorted keys, ``entry_hash`` / ``sig`` excluded).
``sig``         str  — HMAC-SHA-256 hex of ``entry_hash``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

_log = logging.getLogger("artzain.audit_chain")

_GENESIS_HASH = "0" * 64


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------


class AuditLogWriteError(OSError):
    """Raised when an audit log entry cannot be written to disk."""


# ---------------------------------------------------------------------------
# HMAC signer (stdlib only)
# ---------------------------------------------------------------------------


class _HMACSigner:
    """HMAC-SHA-256 signer loaded from ``COGNEXUS_AUDIT_HMAC_KEY`` or ephemeral."""

    def __init__(self) -> None:
        raw = (os.environ.get("COGNEXUS_AUDIT_HMAC_KEY") or "").strip()
        if raw:
            try:
                self._key = bytes.fromhex(raw)
                if len(self._key) < 16:
                    raise ValueError("key too short")
            except (ValueError, Exception) as exc:
                _log.warning("audit_chain: invalid COGNEXUS_AUDIT_HMAC_KEY (%s); generating ephemeral key", exc)
                self._key = secrets.token_bytes(32)
                self._ephemeral = True
            else:
                self._ephemeral = False
        else:
            self._key = secrets.token_bytes(32)
            self._ephemeral = True
            _log.warning(
                "audit_chain: COGNEXUS_AUDIT_HMAC_KEY not set — "
                "using ephemeral HMAC key; signatures will not survive process restart"
            )

    def sign(self, data: bytes) -> str:
        return hmac.new(self._key, data, hashlib.sha256).hexdigest()

    def verify(self, data: bytes, sig_hex: str) -> bool:
        expected = hmac.new(self._key, data, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, sig_hex)


# ---------------------------------------------------------------------------
# Chain state sidecar
# ---------------------------------------------------------------------------


@dataclass
class _ChainState:
    seq: int = 0
    tip_hash: str = _GENESIS_HASH


# ---------------------------------------------------------------------------
# MerkleAuditChain (stdlib)
# ---------------------------------------------------------------------------


class MerkleAuditChain:
    """Thread-safe SHA-256 hash chain over a JSONL audit log file.

    Use :func:`get_chain` to obtain the singleton for a given path.
    """

    def __init__(self, path: Path, signer: _HMACSigner) -> None:
        self._path = path
        self._signer = signer
        self._lock = threading.Lock()
        self._state: Optional[_ChainState] = None

    @property
    def _state_path(self) -> Path:
        return self._path.with_suffix(".chain_state")

    def _load_state(self) -> _ChainState:
        sp = self._state_path
        try:
            if sp.exists():
                try:
                    d = json.loads(sp.read_text(encoding="utf-8"))
                    return _ChainState(seq=int(d["seq"]), tip_hash=str(d["tip_hash"]))
                except Exception:
                    _log.debug("chain state file %s unreadable; rebuilding from the log", sp, exc_info=True)
        except OSError:
            pass

        try:
            if self._path.exists():
                try:
                    last_line: Optional[str] = None
                    seq = 0
                    with self._path.open("r", encoding="utf-8") as fh:
                        for raw in fh:
                            stripped = raw.strip()
                            if stripped:
                                last_line = stripped
                                seq += 1
                    if last_line is not None:
                        tip = hashlib.sha256(last_line.encode("utf-8")).hexdigest()
                        return _ChainState(seq=seq, tip_hash=tip)
                except Exception:
                    _log.debug("audit log %s unreadable; starting a fresh chain", self._path, exc_info=True)
        except OSError:
            pass

        return _ChainState()

    def _save_state(self, state: _ChainState) -> None:
        sp = self._state_path
        tmp = sp.with_suffix(".chain_state.tmp")
        try:
            tmp.write_text(
                json.dumps({"seq": state.seq, "tip_hash": state.tip_hash}),
                encoding="utf-8",
            )
            tmp.replace(sp)
        except Exception as exc:
            _log.warning("audit_chain: could not save chain state: %s", exc)

    def append(self, record: dict[str, Any]) -> str:
        """Hash-chain *record*, sign it, write it to JSONL, and return the raw line.

        Raises :exc:`AuditLogWriteError` if the file cannot be written.
        """
        with self._lock:
            if self._state is None:
                self._state = self._load_state()

            state = self._state
            new_seq = state.seq + 1

            chained: dict[str, Any] = {**record, "seq": new_seq, "prev_hash": state.tip_hash}

            canonical = json.dumps(
                chained, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            )
            entry_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            chained["entry_hash"] = entry_hash
            chained["sig"] = self._signer.sign(entry_hash.encode("ascii"))

            line = json.dumps(chained, ensure_ascii=False, separators=(",", ":"))

            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                with self._path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
            except OSError as exc:
                raise AuditLogWriteError(
                    f"audit log unwritable — {self._path}: {exc}"
                ) from exc

            new_tip = hashlib.sha256(line.encode("utf-8")).hexdigest()
            self._state = _ChainState(seq=new_seq, tip_hash=new_tip)
            self._save_state(self._state)
            return line


# ---------------------------------------------------------------------------
# Module-level registry
# ---------------------------------------------------------------------------

_chains: dict[str, MerkleAuditChain] = {}
_chains_lock = threading.Lock()
_signer_instance: Optional[_HMACSigner] = None
_signer_lock = threading.Lock()


def _get_signer() -> _HMACSigner:
    global _signer_instance
    with _signer_lock:
        if _signer_instance is None:
            _signer_instance = _HMACSigner()
        return _signer_instance


def get_chain(path: Path) -> MerkleAuditChain:
    """Return the singleton :class:`MerkleAuditChain` for *path*.

    All callers writing to the same JSONL file share one instance and one
    lock, preventing interleaved writes.
    """
    key = str(path.resolve())
    with _chains_lock:
        if key not in _chains:
            _chains[key] = MerkleAuditChain(path, _get_signer())
        return _chains[key]


# ---------------------------------------------------------------------------
# Offline verification
# ---------------------------------------------------------------------------


@dataclass
class VerifyResult:
    """Result of :func:`verify_chain`."""

    ok: bool
    entries_checked: int
    first_bad_seq: Optional[int] = None
    error: Optional[str] = None

    def __str__(self) -> str:
        if self.ok:
            return f"chain OK — {self.entries_checked} entries verified"
        return (
            f"chain INVALID at seq={self.first_bad_seq}: {self.error} "
            f"(checked {self.entries_checked} entries before failure)"
        )


def verify_chain(path: Path) -> VerifyResult:
    """Verify the hash chain and HMAC signatures in a JSONL audit log.

    Note: HMAC verification requires the same ``COGNEXUS_AUDIT_HMAC_KEY``
    that was used to sign the entries.  If an ephemeral key was used, only
    hash-chain integrity (``prev_hash`` / ``entry_hash``) can be verified.
    """
    if not path.exists():
        return VerifyResult(ok=True, entries_checked=0)

    signer = _get_signer()
    prev_hash = _GENESIS_HASH
    seq = 0
    chained_seen = False

    try:
        with path.open("r", encoding="utf-8") as fh:
            for raw_line in fh:
                line = raw_line.rstrip("\n")
                if not line.strip():
                    continue

                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as exc:
                    return VerifyResult(
                        ok=False,
                        entries_checked=seq,
                        first_bad_seq=seq + 1,
                        error=f"JSON parse error: {exc}",
                    )

                entry_seq = entry.get("seq")
                if entry_seq is None:
                    if chained_seen:
                        # Pre-chain (unsequenced) entries are only legitimate
                        # before the first chained one; after that an
                        # unsequenced line is a way to hide an entry from the
                        # hash and signature checks.
                        return VerifyResult(
                            ok=False,
                            entries_checked=seq,
                            first_bad_seq=seq + 1,
                            error=f"unchained entry after seq={seq}",
                        )
                    prev_hash = hashlib.sha256(line.encode("utf-8")).hexdigest()
                    seq += 1
                    continue
                chained_seen = True

                entry_seq = int(entry_seq)
                expected_seq = seq + 1
                if entry_seq != expected_seq:
                    return VerifyResult(
                        ok=False,
                        entries_checked=seq,
                        first_bad_seq=entry_seq,
                        error=f"sequence gap — expected {expected_seq}, got {entry_seq}",
                    )

                if entry.get("prev_hash", "") != prev_hash:
                    return VerifyResult(
                        ok=False,
                        entries_checked=seq,
                        first_bad_seq=entry_seq,
                        error=f"prev_hash mismatch at seq={entry_seq}",
                    )

                stored_hash = entry.get("entry_hash", "")
                stored_sig = entry.get("sig", "")
                body = {k: v for k, v in entry.items() if k not in ("entry_hash", "sig")}
                canonical = json.dumps(
                    body, ensure_ascii=False, sort_keys=True, separators=(",", ":")
                )
                expected_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

                if stored_hash != expected_hash:
                    return VerifyResult(
                        ok=False,
                        entries_checked=seq,
                        first_bad_seq=entry_seq,
                        error=f"entry_hash mismatch at seq={entry_seq}",
                    )

                # A missing signature fails verification rather than skipping
                # it — the hash chain alone can be recomputed by any writer.
                if not stored_sig:
                    return VerifyResult(
                        ok=False,
                        entries_checked=seq,
                        first_bad_seq=entry_seq,
                        error=f"missing signature at seq={entry_seq}",
                    )
                if not signer.verify(stored_hash.encode("ascii"), stored_sig):
                    return VerifyResult(
                        ok=False,
                        entries_checked=seq,
                        first_bad_seq=entry_seq,
                        error=f"HMAC mismatch at seq={entry_seq}",
                    )

                prev_hash = hashlib.sha256(line.encode("utf-8")).hexdigest()
                seq = entry_seq

    except OSError as exc:
        return VerifyResult(ok=False, entries_checked=seq, error=f"IO error: {exc}")

    return VerifyResult(ok=True, entries_checked=seq)


__all__ = [
    "AuditLogWriteError",
    "MerkleAuditChain",
    "VerifyResult",
    "get_chain",
    "verify_chain",
]
