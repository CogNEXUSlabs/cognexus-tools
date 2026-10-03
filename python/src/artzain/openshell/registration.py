"""The gateway registration for the ArtzAIn sidecar, from one list of bindings.

An OpenShell v0.1.2 gateway learns about an interceptor from
``[[openshell.gateway.interceptors]]`` tables in ``gateway.toml``, and asks
the interceptor what it binds with ``Describe``. Both have to name the same
methods and phases: a binding the sidecar does not decide would be denied on
every call, and one it decides but the gateway does not send is never
governed. So both come from here, and from the ``BOUND_*`` sets of
:mod:`artzain.openshell.interceptor`.

Two registrations share one endpoint, because an allowlist takes one binding
per RPC per registration and a ``post_commit`` binding must fail open:

* ``artzain``: ``modify_operation`` and ``validate``, fail-closed;
* ``artzain-observe``: ``post_commit``, fail-open.

:func:`render` writes them in the v0.1.2 schema (``[openshell] version =
2``), the layout of the engine repository's example registration, which a
test holds to this output.
"""

from __future__ import annotations

import hashlib
from typing import List, Optional, Sequence, Tuple

from artzain.openshell.interceptor import (
    BOUND_MODIFY,
    BOUND_POST,
    BOUND_VALIDATE,
    PHASE_MODIFY,
    PHASE_POST,
    PHASE_VALIDATE,
)

#: The two registrations, in the order the gateway runs them.
DECIDING, OBSERVING = "artzain", "artzain-observe"
NAMES = (DECIDING, OBSERVING)
SERVICE = "openshell.v1.OpenShell"
#: The interceptor timeout the example registration gives, and its bounds as
#: v0.1.2 accepts them (5 ms .. 60 s).
TIMEOUT_MS_DEFAULT = 1500
TIMEOUT_MS_MIN, TIMEOUT_MS_MAX = 5, 60_000


def bindings(only: Optional[Sequence[str]] = None) -> List[Tuple[str, List[str]]]:
    """``(method, phases)`` for every method the sidecar decides, sorted.

    With *only*, the phases are limited to those, and a method left with
    none is left out.
    """
    out = []
    for method in sorted(BOUND_VALIDATE | BOUND_MODIFY | BOUND_POST):
        phases = [phase for phase, bound in (
            (PHASE_MODIFY, BOUND_MODIFY),
            (PHASE_VALIDATE, BOUND_VALIDATE),
            (PHASE_POST, BOUND_POST),
        ) if method in bound and (only is None or phase in only)]
        if phases:
            out.append((method, phases))
    return out


def _deciding_order() -> List[Tuple[str, List[str]]]:
    """The deciding registration's bindings: the two that are decided in
    ``modify_operation`` first, then the rest, as the example lists them."""
    deciding = bindings((PHASE_MODIFY, PHASE_VALIDATE))
    first = [b for b in deciding if PHASE_MODIFY in b[1]]
    return first + [b for b in deciding if PHASE_MODIFY not in b[1]]


def _table(name: str, endpoint: str, order: int, failure: str, timeout_ms: int,
           bound: List[Tuple[str, List[str]]]) -> List[str]:
    lines = [
        "[[openshell.gateway.interceptors]]",
        f'name           = "{name}"',
        f'grpc_endpoint  = "{endpoint}"',
        f"order          = {order}",
        'binding_policy = "allowlist"',
        f'failure_policy = "{failure}"',
        f'timeout        = "{timeout_ms}ms"',
        "",
    ]
    for method, phases in bound:
        lines += [
            "[[openshell.gateway.interceptors.bindings]]",
            f'rpc    = "{SERVICE}/{method}"',
            "phases = [" + ", ".join(f'"{phase}"' for phase in phases) + "]",
            "",
        ]
    return lines


def render(endpoint: str, *, timeout_ms: int = TIMEOUT_MS_DEFAULT,
           version_table: bool = False) -> str:
    """The two registrations as TOML, for a sidecar at *endpoint*.

    *endpoint* is ``unix:///absolute/path``. With *version_table* the text
    starts with ``[openshell] version = 2``, for a file that has no
    ``[openshell]`` table of its own. Raises ``ValueError`` for an endpoint
    or a timeout the gateway would refuse.
    """
    if not endpoint.startswith("unix:///") or any(ch in endpoint for ch in '"\\\n\r\t '):
        raise ValueError("the endpoint must be unix:///absolute/path")
    if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int) or not (
            TIMEOUT_MS_MIN <= timeout_ms <= TIMEOUT_MS_MAX):
        raise ValueError(f"the timeout must be {TIMEOUT_MS_MIN}..{TIMEOUT_MS_MAX} ms")
    lines: List[str] = []
    if version_table:
        lines += ["[openshell]", "version = 2", ""]
    lines += _table(DECIDING, endpoint, 10, "fail_closed", timeout_ms, _deciding_order())
    lines += _table(OBSERVING, endpoint, 20, "fail_open", timeout_ms, bindings((PHASE_POST,)))
    return "\n".join(lines).rstrip("\n") + "\n"


def digest(text: str) -> str:
    """The SHA-256 the sidecar reports in its heartbeat
    (``OPENSHELL_REGISTRATION_DIGEST``): of the registration text as
    written."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


__all__ = ["DECIDING", "NAMES", "OBSERVING", "TIMEOUT_MS_DEFAULT", "bindings", "digest",
           "render"]
