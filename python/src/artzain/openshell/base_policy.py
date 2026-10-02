"""The base policy the sidecar gives a new sandbox, as the engine delivered it.

A team's active bundle may carry an OpenShell base policy. The engine
compiles and proves it, and hands it to the gateway's sidecar
(``GET /api/v1/openshell/gateways/{id}/base-policy``). The sidecar applies it
to a ``CreateSandbox`` that carries no policy of its own
(:mod:`artzain.openshell.interceptor`). :class:`BasePolicyStore` is where the
sidecar keeps what it was told.

It is in one of three states:

* ``have``: the engine delivered a policy. A create with no policy gets it.
* ``none``: the engine said the team has none. A create is decided as it is.
* ``unknown``: the sidecar has not been told, or cannot trust what it holds.
  A create with no policy is refused until it has been told. One that brings
  its own policy is decided as usual.

A policy is trusted only with its digest: the SHA-256 of its canonical JSON
(sorted keys, no spaces, UTF-8 unescaped), which the engine sends with it. An
answer whose policy does not match its digest is not taken. A copy kept on
disk is checked the same way when it is read back, so a damaged or edited
copy is ``unknown``, not a policy.

The copy is a private file (``0600`` in a ``0700`` folder), replaced whole by
a rename. It holds a policy and no credential.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import threading
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple

from artzain._private_files import private_dir, write_private

logger = logging.getLogger("artzain.openshell.base_policy")

UNKNOWN, NONE, HAVE = "unknown", "none", "have"
CACHE_VERSION = 1
_MAX_CACHE_BYTES = 4 * 1024 * 1024


def policy_digest(policy: Mapping[str, Any]) -> str:
    """SHA-256 of *policy*'s canonical JSON, as the engine computes it."""
    canonical = json.dumps(policy, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class BasePolicyStore:
    """What the engine last said this gateway's base policy is."""

    def __init__(self, *, cache_path: Optional[str] = None, gateway_id: str = "") -> None:
        self._path = Path(cache_path) if cache_path else None
        self._gateway_id = gateway_id
        self._lock = threading.Lock()
        self._state = UNKNOWN
        self._policy: Optional[Dict[str, Any]] = None
        self._digest = ""
        self._bundle: Optional[Dict[str, Any]] = None
        self._save_failed = False
        self._load()

    # -- what the sidecar asks ---------------------------------------------

    def current(self) -> Tuple[str, Optional[Dict[str, Any]]]:
        """``(state, policy)``. The policy is a copy, and None unless ``have``."""
        with self._lock:
            policy = json.loads(json.dumps(self._policy)) if self._state == HAVE else None
            return self._state, policy

    @property
    def digest(self) -> str:
        with self._lock:
            return self._digest if self._state == HAVE else ""

    # -- what the engine says ----------------------------------------------

    def accept(self, answer: Any) -> bool:
        """Take the engine's answer. False when it is not one to take.

        An answer for another gateway, one with no verdict either way, or a
        policy that does not match its digest changes nothing.
        """
        if not isinstance(answer, dict) or answer.get("gateway_id") != self._gateway_id:
            return False
        policy = answer.get("base_policy")
        bundle = answer.get("bundle") if isinstance(answer.get("bundle"), dict) else None
        if policy is None:
            if not str(answer.get("reason") or "").strip():
                return False
            self._set(NONE, None, "", bundle)
            return True
        digest = answer.get("digest")
        if not isinstance(policy, dict) or not policy or not isinstance(digest, str):
            return False
        if policy_digest(policy) != digest:
            logger.warning("base policy not taken: it does not match its digest")
            return False
        # A copy of its own: the answer is the caller's to change afterwards.
        self._set(HAVE, json.loads(json.dumps(policy)), digest, bundle)
        return True

    def invalidate(self) -> None:
        """Forget what is held: the engine has a base it will not deliver."""
        self._set(UNKNOWN, None, "", None)

    # -- the copy on disk --------------------------------------------------

    def _set(self, state: str, policy: Optional[Dict[str, Any]], digest: str,
             bundle: Optional[Dict[str, Any]]) -> None:
        with self._lock:
            if (state, digest, policy) == (self._state, self._digest, self._policy):
                return
            self._state, self._policy, self._digest, self._bundle = state, policy, digest, bundle
            self._save()

    def _save(self) -> None:
        path = self._path
        if path is None:
            return
        try:
            if self._state == UNKNOWN:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(path)
                return
            document = {"version": CACHE_VERSION, "gateway_id": self._gateway_id,
                        "state": self._state, "digest": self._digest,
                        "base_policy": self._policy, "bundle": self._bundle}
            temporary = path.with_name(path.name + ".new")
            private_dir(path.parent)
            write_private(temporary, json.dumps(document).encode("utf-8"))
            os.replace(temporary, path)
            self._save_failed = False
        except OSError as exc:
            if not self._save_failed:
                logger.warning("base policy copy not written (%s); a restart will ask "
                               "the engine again", type(exc).__name__)
            self._save_failed = True

    def _load(self) -> None:
        path = self._path
        if path is None:
            return
        try:
            if path.stat().st_size > _MAX_CACHE_BYTES:
                raise ValueError("copy too large")
            document = json.loads(path.read_bytes().decode("utf-8"))
        except FileNotFoundError:
            return
        except (OSError, ValueError) as exc:
            logger.warning("base policy copy not read (%s)", type(exc).__name__)
            return
        if (not isinstance(document, dict) or document.get("version") != CACHE_VERSION
                or document.get("gateway_id") != self._gateway_id):
            logger.warning("base policy copy is not this gateway's; not used")
            return
        bundle = document.get("bundle") if isinstance(document.get("bundle"), dict) else None
        if document.get("state") == NONE:
            self._state, self._bundle = NONE, bundle
            return
        policy, digest = document.get("base_policy"), document.get("digest")
        if (document.get("state") != HAVE or not isinstance(policy, dict) or not policy
                or not isinstance(digest, str) or policy_digest(policy) != digest):
            logger.warning("base policy copy does not match its digest; not used")
            return
        self._state, self._policy, self._digest, self._bundle = HAVE, policy, digest, bundle


__all__ = ["HAVE", "NONE", "UNKNOWN", "BasePolicyStore", "policy_digest"]
