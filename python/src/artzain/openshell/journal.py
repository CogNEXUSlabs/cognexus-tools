"""What the sidecar owes the engine, kept in order until the engine takes it.

After a governed write commits, the sidecar reports the sandbox's new policy
hash. The gateway does not wait for that report, and the engine may be out
of reach when it is made. A report that was only counted as failed was lost:
the engine went on expecting the old hash, and the sandbox showed as drifted
until its next governed write.

:class:`Journal` is an ordered list of such entries.

* **Order is the point.** The engine keeps the last hash it is told for a
  sandbox. Entries leave from the front only (:meth:`Journal.settle`), so a
  report made during an outage is never delivered after a later one for the
  same sandbox.
* **It is hash-chained.** Every entry carries the SHA-256 of the entry
  before it and of its own content. A file that was cut short, edited by
  hand, or had an entry taken out of the middle does not verify and is not
  replayed: it is set aside as ``<name>.damaged`` and the journal starts
  empty. The chain is not keyed. It shows damage; it does not stop someone
  who can write the sidecar's files from writing a whole new chain. The
  engine still checks every report against the decision it names.
* **With a path it survives a restart.** The file is JSON, ``0600``, in a
  ``0700`` folder of the sidecar user's own, replaced whole by a rename on
  every change. It holds what a report holds: a sandbox id, a policy hash, a
  decision id and a method name. No policy body, no credential. A file
  written for another gateway id is not read.
* **It is bounded.** At :data:`MAX_PENDING` entries a new one is refused,
  and the caller counts it as it always did.
* A file that cannot be written costs the memory across restarts and nothing
  else. The sidecar says so once and carries on.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

from artzain._private_files import private_dir, replace_file, write_private

logger = logging.getLogger("artzain.openshell.journal")

JOURNAL_VERSION = 1
#: Entries that may wait at once.
MAX_PENDING = 1000
#: One entry's body, as JSON. A report is a few hundred bytes.
MAX_BODY_BYTES = 4096
#: A journal file larger than this is not one of ours.
_MAX_FILE_BYTES = 16 * 1024 * 1024
#: What the first entry of a new chain follows.
GENESIS = "0" * 64


def entry_hash(seq: int, at_ms: int, kind: str, body: Mapping[str, Any], prev: str) -> str:
    """The SHA-256 that binds an entry to its content and to the one before."""
    material = json.dumps([seq, at_ms, kind, body, prev], sort_keys=True,
                          separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(material.encode("ascii")).hexdigest()


def _is_hash(value: Any) -> bool:
    return (isinstance(value, str) and len(value) == 64
            and all(ch in "0123456789abcdef" for ch in value))


def _is_count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


class Journal:
    """Entries the engine has not taken, oldest first. Kept in *path* when
    one is given, in memory otherwise."""

    def __init__(self, *, path: Optional[str] = None, gateway_id: str = "",
                 max_pending: int = MAX_PENDING,
                 clock: Callable[[], float] = time.time) -> None:
        self._path = Path(path) if path else None
        self._gateway_id = gateway_id
        self._max_pending = max_pending
        self._clock = clock
        self._lock = threading.Lock()
        #: The entry just before the oldest one that waits: ``(seq, hash)``.
        self._base: Tuple[int, str] = (0, GENESIS)
        self._entries: List[Dict[str, Any]] = []
        self._save_failed = False
        self._load()

    # -- reading ------------------------------------------------------------

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    @property
    def head(self) -> Tuple[int, str]:
        """``(seq, hash)`` of the newest entry ever appended."""
        with self._lock:
            return self._head()

    @property
    def base(self) -> Tuple[int, str]:
        """``(seq, hash)`` of the entry just before the oldest that waits:
        the last one settled, or the chain's start."""
        with self._lock:
            return self._base

    def _head(self) -> Tuple[int, str]:
        if self._entries:
            return (self._entries[-1]["seq"], self._entries[-1]["hash"])
        return self._base

    def first(self) -> Optional[Dict[str, Any]]:
        """A copy of the oldest entry that waits, or None."""
        with self._lock:
            return copy.deepcopy(self._entries[0]) if self._entries else None

    def pending(self) -> List[Dict[str, Any]]:
        """Copies of the entries that wait, oldest first."""
        with self._lock:
            return copy.deepcopy(self._entries)

    def holds(self, seq: int) -> bool:
        """Whether entry *seq* still waits."""
        with self._lock:
            return any(entry["seq"] == seq for entry in self._entries)

    # -- writing ------------------------------------------------------------

    def append(self, kind: str, body: Mapping[str, Any], *,
               durable: bool = False) -> Optional[int]:
        """Add an entry behind the ones that wait. Returns its ``seq``, or
        None when the journal is full or *body* is not a small JSON object.

        With *durable*, the entry stays only once it is in the file: a
        journal without a file, or a file that cannot be written, takes
        nothing and returns None. Break-glass relies on that, since a write
        it allows must not go unrecorded."""
        try:
            plain = json.loads(json.dumps(dict(body), allow_nan=False))
            if len(json.dumps(plain).encode("utf-8")) > MAX_BODY_BYTES:
                return None
        except (TypeError, ValueError):
            return None
        with self._lock:
            if len(self._entries) >= self._max_pending:
                return None
            if durable and self._path is None:
                return None
            seq, prev = self._head()
            seq += 1
            at_ms = int(self._clock() * 1000)
            kind = str(kind)[:40]
            self._entries.append({"seq": seq, "at_ms": at_ms, "kind": kind, "body": plain,
                                  "prev": prev,
                                  "hash": entry_hash(seq, at_ms, kind, plain, prev)})
            self._save()
            if durable and self._save_failed:
                self._entries.pop()
                self._save()
                return None
            return seq

    def settle(self, seq: int) -> bool:
        """Take the oldest entry off, when it is entry *seq*: it was
        delivered, or refused for good. False when it is not the oldest,
        and nothing changes."""
        with self._lock:
            if not self._entries or self._entries[0]["seq"] != seq:
                return False
            done = self._entries.pop(0)
            self._base = (done["seq"], done["hash"])
            self._save()
            return True

    def settle_through(self, seq: int) -> int:
        """Take off every waiting entry up to and including *seq*, oldest
        first. Returns how many left; 0 when *seq* names none that waits."""
        with self._lock:
            if not self._entries or not self._entries[0]["seq"] <= seq <= self._entries[-1]["seq"]:
                return 0
            taken = [entry for entry in self._entries if entry["seq"] <= seq]
            self._entries = self._entries[len(taken):]
            self._base = (taken[-1]["seq"], taken[-1]["hash"])
            self._save()
            return len(taken)

    # -- the file -----------------------------------------------------------

    def _document(self) -> Dict[str, Any]:
        return {"version": JOURNAL_VERSION, "gateway_id": self._gateway_id,
                "base": {"seq": self._base[0], "hash": self._base[1]},
                "entries": self._entries}

    def _save(self) -> None:
        """Called with the lock held, after a change."""
        path = self._path
        if path is None:
            return
        temporary = path.with_name(path.name + ".new")
        try:
            private_dir(path.parent)
            write_private(temporary, json.dumps(self._document()).encode("utf-8"))
            replace_file(temporary, path)
            self._save_failed = False
        except OSError as exc:
            if not self._save_failed:
                logger.warning("report journal not written (%s); reports that wait will "
                               "not survive a restart", type(exc).__name__)
            self._save_failed = True

    @staticmethod
    def _verified(document: Any) -> Tuple[Tuple[int, str], List[Dict[str, Any]]]:
        """The base and entries of a journal document whose chain holds.
        Raises ``ValueError`` when anything in it does not."""
        base = document.get("base")
        entries = document.get("entries")
        if not isinstance(base, dict) or not isinstance(entries, list):
            raise ValueError("not a journal")
        seq, prev = base.get("seq"), base.get("hash")
        if not _is_count(seq) or not _is_hash(prev):
            raise ValueError("no chain base")
        checked: List[Dict[str, Any]] = []
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {
                    "seq", "at_ms", "kind", "body", "prev", "hash"}:
                raise ValueError("not an entry")
            if not (_is_count(entry["at_ms"]) and isinstance(entry["kind"], str)
                    and isinstance(entry["body"], dict)):
                raise ValueError("not an entry")
            if entry["seq"] != seq + 1 or entry["prev"] != prev:
                raise ValueError("the chain is broken")
            if entry["hash"] != entry_hash(entry["seq"], entry["at_ms"], entry["kind"],
                                           entry["body"], entry["prev"]):
                raise ValueError("an entry does not match its hash")
            seq, prev = entry["seq"], entry["hash"]
            checked.append(entry)
        return (base["seq"], base["hash"]), checked

    def _load(self) -> None:
        path = self._path
        if path is None:
            return
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                raise ValueError("journal file too large")
            document = json.loads(path.read_bytes().decode("utf-8"))
            if not isinstance(document, dict) or document.get("version") != JOURNAL_VERSION:
                raise ValueError("not a version %d journal" % JOURNAL_VERSION)
            if document.get("gateway_id") != self._gateway_id:
                logger.warning("report journal is another gateway's; starting empty")
                return
            base, entries = self._verified(document)
        except FileNotFoundError:
            return
        except (OSError, ValueError) as exc:
            logger.warning("report journal not replayed (%s); set aside as %s.damaged",
                           type(exc).__name__, path.name)
            self._set_aside(path)
            return
        self._base, self._entries = base, entries

    @staticmethod
    def _set_aside(path: Path) -> None:
        with contextlib.suppress(OSError):
            os.replace(path, path.with_name(path.name + ".damaged"))


__all__ = ["GENESIS", "JOURNAL_VERSION", "MAX_PENDING", "Journal", "entry_hash"]
