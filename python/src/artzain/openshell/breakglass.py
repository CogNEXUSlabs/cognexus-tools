"""Break-glass: governed writes the gateway's host allows while ArtzAIn
cannot decide.

Every governed write fails closed when the engine cannot answer, so an
ArtzAIn outage stops every change to the gateway's sandboxes. Break-glass
(plan S5.3, decision D8) lets the gateway's own host user open a window in
which such a write is allowed and journaled instead. When the engine can be
reached again, the sidecar sends it the journal, and it seals each entry as
a flagged receipt and puts the window in the Review Queue.

* **Only the host opens a window.** ``artzain connect openshell break-glass``
  calls the sidecar's loopback route with the sidecar's own token. No engine
  answer and no gateway call can open one.
* **A window lasts 1 to** :data:`MAX_MINUTES` **minutes and names a reason.**
  One is open at a time. It ends on its own, without the engine: when its
  time is up on the wall clock, when as much time has passed on the
  monotonic clock (so setting the wall clock back does not stretch it), or
  when the wall clock reads earlier than its opening. The operator can close
  it early.
* **It covers only what ArtzAIn could not answer** (``interceptor``): no
  answer at all, or a 5xx. Anything ArtzAIn answered still holds, and so
  does every local refusal. A gateway-wide write is never allowed.
* **A write that cannot be journaled is refused.** Each allowed write is an
  entry of a hash-chained :class:`~artzain.openshell.journal.Journal` kept
  in a file of the sidecar user's own, written before the write is allowed.
  The entry holds the method, the action and target ArtzAIn would have
  decided, the SHA-256 of the payload it would have been sent, the digest
  of the operation, the caller's subject id and the request id. No policy
  body and no credential.
* **The journal leaves the host only when the engine took it**, in order,
  through the gateway's own route (``sidecar.deliver_breakglass``).

The chain is not keyed: someone who can write the sidecar's files can write
a new chain, as they could unbind the gateway. The engine checks that each
upload continues from what it last took, and flags one that does not.
"""

from __future__ import annotations

import contextlib
import copy
import json
import logging
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Optional

from artzain._private_files import private_dir, replace_file, write_private
from artzain.openshell.journal import Journal

logger = logging.getLogger("artzain.openshell.breakglass")

#: The longest a window may be open, in minutes (D8: four hours).
MAX_MINUTES = 240
#: The longest reason, in characters.
MAX_REASON_CHARS = 500
#: Who opened the window, as the host names its user.
MAX_OPENED_BY_CHARS = 64
#: Entries that may wait for the engine at once.
MAX_ENTRIES = 1000
#: Entries sent to the engine in one call.
UPLOAD_BATCH = 100
#: Files in the sidecar's state folder.
JOURNAL_FILE = "breakglass-journal.json"
WINDOW_FILE = "breakglass-window.json"
WINDOW_VERSION = 1

KIND_OPEN = "breakglass_open"
KIND_WRITE = "breakglass_write"
KIND_CLOSE = "breakglass_close"

_WINDOW_KEYS = frozenset({"id", "opened_ms", "until_ms", "minutes", "reason", "opened_by",
                          "writes"})


class Refused(Exception):
    """A window that does not open or close. ``status`` is the HTTP status
    the sidecar's route answers with."""

    def __init__(self, message: str, status: int) -> None:
        super().__init__(message)
        self.status = status


def _whole(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _one_line(value: Any, limit: int) -> str:
    """*value* stripped, when it is a non-empty string of at most *limit*
    printable characters on one line; empty otherwise."""
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if not text or len(text) > limit or any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        return ""
    return text


class BreakGlass:
    """The window and its journal, kept in *directory* (the sidecar's state
    folder). Without a directory there is no journal file, and no window
    opens."""

    def __init__(self, directory: Optional[Any], *, gateway_id: str,
                 clock: Callable[[], float] = time.time,
                 monotonic: Callable[[], float] = time.monotonic,
                 max_entries: int = MAX_ENTRIES) -> None:
        self._dir = Path(directory) if directory else None
        self._gateway_id = gateway_id
        self._clock = clock
        self._monotonic = monotonic
        self._lock = threading.Lock()
        self.journal = Journal(path=str(self._dir / JOURNAL_FILE) if self._dir else None,
                               gateway_id=gateway_id, max_pending=max_entries, clock=clock)
        self._window: Optional[Dict[str, Any]] = None
        #: The monotonic time the window ends, when this process opened or
        #: read it. A restart starts it again from the wall clock.
        self._deadline: Optional[float] = None
        self._load()

    @property
    def enabled(self) -> bool:
        return self._dir is not None

    # -- the window -----------------------------------------------------------

    def window(self) -> Optional[Dict[str, Any]]:
        """A copy of the open window, or None. A window whose time is up is
        closed here, and its close journaled."""
        with self._lock:
            self._expire()
            return copy.deepcopy(self._window)

    def open(self, minutes: Any, reason: Any, opened_by: Any = "") -> Dict[str, Any]:
        """Open a window of *minutes* for *reason*. Raises :class:`Refused`."""
        if not self.enabled:
            raise Refused("break-glass needs the sidecar's journal file "
                          "(OPENSHELL_SIDECAR_JOURNAL; `artzain connect openshell up` sets it)", 409)
        if not _whole(minutes) or not 1 <= minutes <= MAX_MINUTES:
            raise Refused(f"minutes must be a whole number from 1 to {MAX_MINUTES}", 400)
        text = _one_line(reason, MAX_REASON_CHARS)
        if not text:
            raise Refused(f"a reason is needed: one line, at most {MAX_REASON_CHARS} characters", 400)
        who = _one_line(opened_by, MAX_OPENED_BY_CHARS) if opened_by else ""
        with self._lock:
            self._expire()
            if self._window is not None:
                raise Refused("a break-glass window is already open until %s; close it first"
                              % _utc(self._window["until_ms"]), 409)
            opened_ms = int(self._clock() * 1000)
            window = {"id": uuid.uuid4().hex, "opened_ms": opened_ms,
                      "until_ms": opened_ms + minutes * 60_000, "minutes": minutes,
                      "reason": text, "opened_by": who, "writes": 0}
            seq = self.journal.append(KIND_OPEN, {
                "window": window["id"], "minutes": minutes, "until_ms": window["until_ms"],
                "reason": text, "opened_by": who}, durable=True)
            if seq is None:
                raise Refused("break-glass journal could not be written; no window opened", 503)
            self._window = window
            self._deadline = self._monotonic() + minutes * 60
            self._save_window()
            logger.warning("break-glass window %s open for %d minutes", window["id"], minutes)
            return copy.deepcopy(window)

    def close(self, why: str = "operator") -> Optional[Dict[str, Any]]:
        """Close the open window. Returns it, or None when none was open."""
        with self._lock:
            self._expire()
            if self._window is None:
                return None
            return self._end(why)

    def record_write(self, facts: Mapping[str, Any]) -> Optional[str]:
        """Journal one write under the open window. Returns the window id, or
        None when no window is open or the entry is not in the file."""
        with self._lock:
            self._expire()
            if self._window is None:
                return None
            seq = self.journal.append(KIND_WRITE, {"window": self._window["id"], **facts},
                                      durable=True)
            if seq is None:
                return None
            self._window["writes"] += 1
            self._save_window()
            return self._window["id"]

    def status(self) -> Dict[str, Any]:
        """What the sidecar's route and ``status`` show."""
        return {"enabled": self.enabled, "window": self.window(),
                "pending": len(self.journal)}

    # -- with the lock held ---------------------------------------------------

    def _expire(self) -> None:
        window = self._window
        if window is None:
            return
        now_ms = int(self._clock() * 1000)
        if now_ms < window["opened_ms"]:
            self._end("clock")
        elif now_ms >= window["until_ms"] or (
                self._deadline is not None and self._monotonic() >= self._deadline):
            self._end("expired")

    def _end(self, why: str) -> Dict[str, Any]:
        window = self._window
        assert window is not None
        if self.journal.append(KIND_CLOSE, {"window": window["id"], "closed": why,
                                            "writes": window["writes"]}, durable=True) is None:
            logger.warning("break-glass window %s closed; its close could not be journaled",
                           window["id"])
        self._window = None
        self._deadline = None
        self._save_window()
        logger.warning("break-glass window %s closed (%s) after %d write(s)",
                       window["id"], why, window["writes"])
        return copy.deepcopy(window)

    # -- the window file ------------------------------------------------------

    def _save_window(self) -> None:
        if self._dir is None:
            return
        path = self._dir / WINDOW_FILE
        temporary = path.with_name(path.name + ".new")
        document = {"version": WINDOW_VERSION, "gateway_id": self._gateway_id,
                    "window": self._window}
        try:
            private_dir(self._dir)
            write_private(temporary, json.dumps(document).encode("utf-8"))
            replace_file(temporary, path)
        except OSError as exc:
            # The journal holds the window; only a restart forgets it, and a
            # forgotten window is a closed one.
            logger.warning("break-glass window file not written (%s)", type(exc).__name__)

    def _load(self) -> None:
        if self._dir is None:
            return
        path = self._dir / WINDOW_FILE
        try:
            document = json.loads(path.read_bytes().decode("utf-8"))
        except FileNotFoundError:
            return
        except (OSError, ValueError) as exc:
            logger.warning("break-glass window file not read (%s): no window is open",
                           type(exc).__name__)
            return
        window = document.get("window") if isinstance(document, dict) else None
        if window is None:
            return
        if (document.get("version") != WINDOW_VERSION
                or document.get("gateway_id") != self._gateway_id
                or not self._holds(window)):
            logger.warning("break-glass window file does not hold: no window is open")
            with contextlib.suppress(OSError):
                path.unlink()
            return
        self._window = dict(window)
        remaining_ms = window["until_ms"] - int(self._clock() * 1000)
        self._deadline = self._monotonic() + max(0, remaining_ms) / 1000

    @staticmethod
    def _holds(window: Any) -> bool:
        """Whether a window read from its file is one :meth:`open` could
        have written."""
        if not isinstance(window, dict) or set(window) != _WINDOW_KEYS:
            return False
        minutes, opened, until = window["minutes"], window["opened_ms"], window["until_ms"]
        return (isinstance(window["id"], str) and len(window["id"]) == 32
                and _whole(minutes) and 1 <= minutes <= MAX_MINUTES
                and _whole(opened) and _whole(until) and until == opened + minutes * 60_000
                and bool(_one_line(window["reason"], MAX_REASON_CHARS))
                and isinstance(window["opened_by"], str)
                and _whole(window["writes"]) and window["writes"] >= 0)


def _utc(at_ms: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(at_ms / 1000))


__all__ = ["JOURNAL_FILE", "KIND_CLOSE", "KIND_OPEN", "KIND_WRITE", "MAX_ENTRIES",
           "MAX_MINUTES", "MAX_REASON_CHARS", "UPLOAD_BATCH", "WINDOW_FILE", "BreakGlass",
           "Refused"]
