"""What the sidecar knows of its gateway's sandboxes, kept across restarts.

The gateway names a sandbox by name and workspace in every call but the
create's answer, and an update's ``post_commit`` names no sandbox at all. So
the sidecar has to remember, for each sandbox it has seen: the uuid its
create returned, and the effective policy hash its last committed update
reported. :class:`~artzain.openshell.interceptor.OperationLedger` holds the
first in memory. :class:`GatewayLedger` adds the second and writes both to a
private state file, which the next process reads back.

* The file is JSON, ``0600``, in a ``0700`` folder of the sidecar user's own
  (:mod:`artzain._private_files`). It is replaced whole on every change, by a
  rename, so a reader never sees half a file.
* It holds names, ids and policy hashes. No policy body, no credential.
* It is this gateway's: a file written for another gateway id is not read.
* A file that cannot be read or written costs the memory across restarts and
  nothing else. The sidecar says so once and carries on.
* ``complete`` records that the view was filled from a full listing of the
  gateway. Until then a snapshot built from this view alone is sent as
  partial: a sandbox created before the sidecar was bound is not in it. A
  sidecar that lists every workspace through the CLI
  (``OPENSHELL_SIDECAR_LIST_CLI``) replaces the view with each listing
  (:meth:`GatewayLedger.replace_all`) instead.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from artzain._private_files import private_dir, replace_file, write_private
from artzain.openshell.interceptor import DEFAULT_WORKSPACE, OperationLedger

logger = logging.getLogger("artzain.openshell.state")

STATE_VERSION = 1
#: A state file larger than this is not one of ours.
_MAX_STATE_BYTES = 16 * 1024 * 1024
_MAX_TEXT = 200


def _text(value: Any) -> str:
    return value.strip()[:_MAX_TEXT] if isinstance(value, str) else ""


class GatewayLedger(OperationLedger):
    """An :class:`OperationLedger` that also knows each sandbox's effective
    policy hash, and keeps its sandboxes in *state_path* when one is given."""

    def __init__(self, *, state_path: Optional[str] = None, gateway_id: str = "",
                 **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._state_path = Path(state_path) if state_path else None
        self._gateway_id = gateway_id
        self._hashes: Dict[str, str] = {}
        self._complete = False
        self._revision = 0
        self._save_failed = False
        self._load()

    # -- what changed ------------------------------------------------------

    @property
    def revision(self) -> int:
        """Goes up each time the sandboxes, a hash or ``complete`` changes."""
        with self._lock:
            return self._revision

    @property
    def complete(self) -> bool:
        with self._lock:
            return self._complete

    def mark_complete(self, complete: bool = True) -> None:
        """Record that the view now holds every sandbox of the gateway."""
        with self._lock:
            if self._complete != bool(complete):
                self._complete = bool(complete)
                self._changed()

    def learn_sandbox(self, workspace: str, name: str, sandbox_id: str) -> None:
        if not name or not sandbox_id:
            return
        key = (workspace or DEFAULT_WORKSPACE, name)
        with self._lock:
            before = self._sandboxes.get(key)
        super().learn_sandbox(workspace, name, sandbox_id)
        with self._lock:
            if before != sandbox_id:
                # A name that is another sandbox now, or one the bound pushed
                # out, leaves a hash that is nobody's.
                self._prune_hashes()
                self._changed()

    def forget_sandbox(self, workspace: str, name: str) -> None:
        key = (workspace or DEFAULT_WORKSPACE, name)
        with self._lock:
            gone = self._sandboxes.get(key)
        super().forget_sandbox(workspace, name)
        if gone:
            with self._lock:
                self._hashes.pop(gone, None)
                self._changed()

    def note_policy_hash(self, sandbox_id: str, policy_hash: str) -> None:
        """Remember the effective hash a committed write reported for a
        sandbox this ledger knows. An unknown sandbox is not remembered."""
        sandbox_id, policy_hash = _text(sandbox_id), _text(policy_hash)
        if not sandbox_id or not policy_hash:
            return
        with self._lock:
            if sandbox_id not in self._sandboxes.values():
                return
            if self._hashes.get(sandbox_id) != policy_hash:
                self._hashes[sandbox_id] = policy_hash
                self._changed()

    def policy_hash(self, sandbox_id: str) -> str:
        with self._lock:
            return self._hashes.get(str(sandbox_id or ""), "")

    def sandboxes(self) -> List[Dict[str, str]]:
        """Every known sandbox: workspace, name, id and effective hash (empty
        when no committed update has reported one)."""
        with self._lock:
            return [{"workspace": workspace, "name": name, "id": sandbox_id,
                     "effective_policy_hash": self._hashes.get(sandbox_id, "")}
                    for (workspace, name), sandbox_id in self._sandboxes.items()]

    def replace_workspace(self, workspace: str, listed: Iterable[Tuple[str, str]]) -> None:
        """Make *workspace* hold exactly the ``(name, id)`` pairs a full
        listing of it returned. A sandbox the listing does not have is gone;
        a hash is kept for an id that is still there."""
        workspace = workspace or DEFAULT_WORKSPACE
        wanted = {(workspace, _text(name)): _text(sandbox_id)
                  for name, sandbox_id in listed if _text(name) and _text(sandbox_id)}
        with self._lock:
            current = {key: value for key, value in self._sandboxes.items()
                       if key[0] == workspace}
            if current == wanted:
                return
            for key in current:
                if key not in wanted:
                    del self._sandboxes[key]
            for key, sandbox_id in wanted.items():
                self._sandboxes[key] = sandbox_id
            while len(self._sandboxes) > self._max_sandboxes:
                self._sandboxes.popitem(last=False)
            self._prune_hashes()
            self._changed()

    def replace_all(self, listed: Iterable[Tuple[str, str, str]]) -> None:
        """Make the whole view exactly the ``(workspace, name, id)`` triples a
        full listing of every workspace returned. A sandbox the listing does
        not have is gone; a hash is kept for an id that is still there."""
        wanted = {(_text(workspace) or DEFAULT_WORKSPACE, _text(name)): _text(sandbox_id)
                  for workspace, name, sandbox_id in listed
                  if _text(name) and _text(sandbox_id)}
        with self._lock:
            if dict(self._sandboxes) == wanted:
                return
            for key in [key for key in self._sandboxes if key not in wanted]:
                del self._sandboxes[key]
            for key, sandbox_id in wanted.items():
                self._sandboxes[key] = sandbox_id
            while len(self._sandboxes) > self._max_sandboxes:
                self._sandboxes.popitem(last=False)
            self._prune_hashes()
            self._changed()

    # -- the file ----------------------------------------------------------

    def _prune_hashes(self) -> None:
        known = set(self._sandboxes.values())
        for sandbox_id in [key for key in self._hashes if key not in known]:
            del self._hashes[sandbox_id]

    def _changed(self) -> None:
        """Called with the lock held, after a change."""
        self._revision += 1
        self._save()

    def _document(self) -> Dict[str, Any]:
        return {
            "version": STATE_VERSION,
            "gateway_id": self._gateway_id,
            "complete": self._complete,
            "sandboxes": [
                {"workspace": workspace, "name": name, "id": sandbox_id,
                 "effective_policy_hash": self._hashes.get(sandbox_id, "")}
                for (workspace, name), sandbox_id in self._sandboxes.items()],
        }

    def _save(self) -> None:
        path = self._state_path
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
                logger.warning("sidecar state not written (%s); sandbox names will not "
                               "survive a restart", type(exc).__name__)
            self._save_failed = True

    def _load(self) -> None:
        path = self._state_path
        if path is None:
            return
        try:
            if path.stat().st_size > _MAX_STATE_BYTES:
                raise ValueError("state file too large")
            document = json.loads(path.read_bytes().decode("utf-8"))
        except FileNotFoundError:
            return
        except (OSError, ValueError) as exc:
            logger.warning("sidecar state not read (%s); starting with none",
                           type(exc).__name__)
            return
        if not isinstance(document, dict) or document.get("version") != STATE_VERSION:
            logger.warning("sidecar state is not a version %d file; starting with none",
                           STATE_VERSION)
            return
        if _text(document.get("gateway_id")) != self._gateway_id:
            logger.warning("sidecar state is another gateway's; starting with none")
            return
        entries = document.get("sandboxes")
        with self._lock:
            for entry in entries if isinstance(entries, list) else []:
                if not isinstance(entry, dict):
                    continue
                name, sandbox_id = _text(entry.get("name")), _text(entry.get("id"))
                if not name or not sandbox_id:
                    continue
                key = (_text(entry.get("workspace")) or DEFAULT_WORKSPACE, name)
                self._sandboxes[key] = sandbox_id
                policy_hash = _text(entry.get("effective_policy_hash"))
                if policy_hash:
                    self._hashes[sandbox_id] = policy_hash
            while len(self._sandboxes) > self._max_sandboxes:
                self._sandboxes.popitem(last=False)
            self._prune_hashes()
            self._complete = document.get("complete") is True


__all__ = ["STATE_VERSION", "GatewayLedger"]
