"""The ArtzAIn sidecar that runs beside an OpenShell gateway.

It answers the gateway's interceptor calls with :func:`handle_evaluate` (the
rules are :mod:`artzain.openshell.interceptor`), asks the ArtzAIn Decision API,
reports the committed policy hash after a governed write, keeps an inventory
of the gateway's sandboxes for the catalog, and seals OpenShell FINDING and
CONFIG events. It only ever calls out to the engine, over a connection it
keeps warm (:mod:`artzain.openshell.transport`).

With a gateway credential (``cnxg_...``) it also sends the engine a heartbeat
every minute and its inventory every five minutes and on change
(:class:`Reporter`). The engine cannot reach a customer's gateway, so this is
how such a gateway's sandboxes reach the catalog. It also fetches the base
policy of its team's active bundle, and gives it to a new sandbox whose
create carries none (:mod:`artzain.openshell.base_policy`). Until it has
been told what the base policy is, such a create is refused.

The gateway calls the gRPC ``GatewayInterceptor`` service
(:mod:`artzain.openshell.servicer`), served on ``OPENSHELL_SIDECAR_GRPC``
when that is set. The HTTP routes are for the ArtzAIn catalog and for tools:
``GET /artzain/inventory``, ``GET /artzain/reports`` (whether the engine took
the last heartbeat and inventory), ``POST /v1/evaluate``, ``POST
/artzain/ocsf``, and an open ``GET /healthz``.

Settings (environment):

* ``OPENSHELL_SIDECAR_HOST`` / ``OPENSHELL_SIDECAR_PORT``: the HTTP bind
  address, loopback ``127.0.0.1:8088`` by default.
* ``OPENSHELL_SIDECAR_GRPC``: where the gateway calls the interceptor,
  ``unix:///absolute/path`` or a loopback ``host:port``. Needs
  ``artzain[openshell]``. ``OPENSHELL_SIDECAR_SOCKET_MODE`` sets the
  socket's mode (default ``600``).
* ``OPENSHELL_JWT_PUBLIC_KEY`` and ``OPENSHELL_JWT_GATEWAY_ID``: the gateway's
  ``gateway_jwt`` public key file and id. When set, every gRPC call must carry
  the gateway's signed token.
* ``OPENSHELL_SIDECAR_TOKEN``: when set, every request needs it as
  ``Authorization: Bearer``, compared in constant time.
* ``OPENSHELL_GATEWAY_ID``: this sidecar's gateway. It names the decision
  target, the agent (``openshell:<gateway id>``) and the inventory; a request
  cannot choose another.
* ``ARTZAIN_DECISION_URL``: the engine origin, or its ``/api/v1/decisions``
  URL. ``http`` or ``https`` only. Every call goes to this origin and to
  no other.
* ``OPENSHELL_SIDECAR_PROXY``: how to reach the engine. Unset, the
  connection is direct and the environment's proxy settings are ignored;
  ``env`` uses them; ``http://[user:password@]host[:port]`` names an HTTP
  proxy, which is asked to ``CONNECT``.
* ``OPENSHELL_SIDECAR_CA_BUNDLE``: a PEM file of the certificate
  authorities to trust for the engine, instead of the system's.
* ``COGNEXUS_API_KEY``: the Decision API key. Never logged.
* ``OPENSHELL_SIDECAR_DECIDE_TIMEOUT_MS``: the deadline for each engine call
  (default 1200, held to 50..30000). Keep it below the gateway
  registration's ``timeout`` so a slow engine is a sidecar deny, not a
  gateway transport error.
* ``OPENSHELL_SIDECAR_STATE``: a file the sidecar keeps its sandboxes in
  (names, ids and policy hashes), so a restart does not lose them. Unset,
  they are kept in memory only (:mod:`artzain.openshell.state`).
* ``OPENSHELL_SIDECAR_LIST_WORKSPACES``: workspaces to list through the
  OpenShell SDK for the inventory, comma-separated. Listing uses the
  operator's own CLI identity (``SandboxClient.from_active_cluster()``),
  so it is off unless this is set. Unset, the inventory is what the
  sidecar has seen commit.
* ``OPENSHELL_SIDECAR_LIST_CLI``: an ``openshell`` CLI to list every
  workspace's sandboxes with (``sandbox list --all-workspaces -o json``) for
  each inventory, instead. ``artzain connect openshell`` sets it to the CLI
  the operator registered with the gateway; it runs as the sidecar's user,
  with that user's CLI identity, and is not given the credential.
* ``OPENSHELL_REGISTRATION_DIGEST``: the SHA-256 of the gateway
  registration this sidecar was installed with, sent in the heartbeat.
* ``OPENSHELL_SIDECAR_BASE_POLICY``: a file to keep the delivered base
  policy in, so a restart has it before the engine answers. Unset, a
  restarted sidecar refuses a create with no policy until it does.
* ``OPENSHELL_SIDECAR_JOURNAL``: a file to keep the reports the engine has
  not taken yet, so a restart does not lose them. Unset, they wait in
  memory (:mod:`artzain.openshell.journal`).

A connection reset is retried once inside the same deadline, only for a
decision that carries a ``request_id``: the Decision API replays a repeated
id instead of sealing and billing it twice. No other call is sent twice
within its deadline. The handler never logs the key, the bearer, or a
request body.

A projection report the engine could not be given waits in the journal
and is sent again, in order, until the engine takes it or refuses it for
good.

When the engine answers 429 (the hourly rate is used up), the write is
refused with a reason that says so and how long to wait, and the gateway
reports it as ``RESOURCE_EXHAUSTED``. It is not retried here: the operator
runs the command again.

Run it with ``artzain openshell sidecar`` or
``python -m artzain.openshell.sidecar``.
"""

from __future__ import annotations

import hmac
import io
import json
import logging
import os
import re
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import uuid
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from artzain.openshell import base_policy as base_policies
from artzain.openshell import transport
from artzain.openshell.interceptor import (
    BOUND_POST,
    DEFAULT_WORKSPACE,
    PHASE_POST,
    OperationLedger,
    classify_ocsf,
    evaluate,
    method_name,
)
from artzain.openshell.journal import Journal
from artzain.openshell.state import GatewayLedger

logger = logging.getLogger("artzain.openshell.sidecar")

InventoryFn = Callable[[], Dict[str, Any]]
DecideFn = Callable[[Dict[str, Any]], Dict[str, Any]]
#: Lists each workspace's sandboxes: ``{workspace: [{id, name, phase}]}``.
ListFn = Callable[[Sequence[str]], Dict[str, List[Dict[str, str]]]]
PostFn = Callable[[str, Dict[str, Any]], Any]

#: Engine-call deadline in milliseconds, and its bounds. The example gateway
#: registration gives the interceptor 1500 ms; this stays under it.
DECIDE_TIMEOUT_MS_DEFAULT = 1200
_DECIDE_TIMEOUT_MS_MIN = 50
_DECIDE_TIMEOUT_MS_MAX = 30_000
#: A decision or projection answer is small; a larger body is refused.
_MAX_ANSWER_BYTES = transport.MAX_ANSWER_BYTES
_READ_CHUNK = 16 * 1024
#: How often the reports that wait in the journal are tried again.
REPORT_RETRY_SECONDS = 15.0
#: A report that has waited this long is given up: the engine has had
#: three days to take it, and one that can never be taken must not hold
#: back the ones behind it for ever.
REPORT_MAX_AGE_SECONDS = 72 * 3600.0
#: Statuses that refuse a report for good. Any other failure is tried again.
_REPORT_REFUSED = frozenset({400, 403, 404, 410, 413, 422})
#: What an OpenShell gateway's own credential starts with. Only it may send
#: a heartbeat or an inventory.
GATEWAY_KEY_PREFIX = "cnxg_"
#: A snapshot lists at most this many sandboxes; the engine refuses more.
MAX_SNAPSHOT_SANDBOXES = 200
#: The deadline for a heartbeat or an inventory. Nothing waits on them, so
#: they get longer than a decision does.
REPORT_TIMEOUT_SECONDS = 10.0
HEARTBEAT_SECONDS = 60.0
INVENTORY_SECONDS = 300.0
BASE_POLICY_SECONDS = 300.0
#: How long a change waits before it is sent, so a burst is one snapshot.
INVENTORY_CHANGE_DELAY_SECONDS = 5.0
#: A listing that fails is tried again this soon. ``up`` restarts the gateway
#: just after the sidecar starts, and the first listing can land while that
#: restart is in progress; the next ordinary inventory is five minutes away.
LISTING_RETRY_SECONDS = 2.0
#: Prompt tries after a failed listing, then the ordinary interval. About as
#: long as ``up`` waits for the first inventory: enough for the gateway to
#: come back, and then a gateway that stays unlistable is not listed every
#: two seconds.
LISTING_RETRY_LIMIT = 15
#: A CLI listing: sandboxes per page, the most pages read, and the deadline
#: for all of them. More pages than this is more sandboxes than a snapshot
#: carries.
LIST_PAGE_SIZE = 100
LIST_MAX_PAGES = 10
LIST_TIMEOUT_SECONDS = 30.0
#: What the CLI is not given: it needs neither to list sandboxes.
_NOT_FOR_THE_CLI = ("COGNEXUS_API_KEY", "OPENSHELL_SIDECAR_TOKEN")
_MIN_INTERVAL_SECONDS, _MAX_INTERVAL_SECONDS = 30.0, 3600.0


def _gateway_id() -> str:
    return os.environ.get("OPENSHELL_GATEWAY_ID") or "gateway"


def decide_timeout_seconds() -> float:
    """``OPENSHELL_SIDECAR_DECIDE_TIMEOUT_MS`` in seconds, bounded.

    A value that is not a positive integer means the default; anything else
    is held to 50 ms .. 30 s.
    """
    raw = (os.environ.get("OPENSHELL_SIDECAR_DECIDE_TIMEOUT_MS") or "").strip()
    try:
        ms = int(raw)
    except ValueError:
        ms = 0
    if ms <= 0:
        ms = DECIDE_TIMEOUT_MS_DEFAULT
    ms = max(_DECIDE_TIMEOUT_MS_MIN, min(_DECIDE_TIMEOUT_MS_MAX, ms))
    return ms / 1000.0


def list_workspaces() -> List[str]:
    """The workspaces ``OPENSHELL_SIDECAR_LIST_WORKSPACES`` names, in order."""
    raw = os.environ.get("OPENSHELL_SIDECAR_LIST_WORKSPACES") or ""
    names: List[str] = []
    for part in raw.split(","):
        name = part.strip()
        if name and name not in names:
            names.append(name)
    return names


def sdk_list(workspaces: Sequence[str]) -> Dict[str, List[Dict[str, str]]]:
    """List each workspace's sandboxes through the OpenShell SDK. Raises.

    The client is the operator's own (``from_active_cluster`` reads the
    CLI's gateway files and identity), and each workspace is listed by
    name: the SDK's ``list_all`` takes no default. A listing carries a
    sandbox's id, name and phase, and no policy hash.
    """
    from openshell.sandbox import SandboxClient  # type: ignore

    client = SandboxClient.from_active_cluster()
    listed: Dict[str, List[Dict[str, str]]] = {}
    for workspace in workspaces:
        refs = client.list_all(workspace=workspace)
        listed[workspace] = [{
            "id": str(getattr(ref, "id", "") or ""),
            "name": str(getattr(ref, "name", "") or ""),
            "phase": str(getattr(getattr(ref, "status", None), "phase", "") or ""),
        } for ref in refs or []]
    return listed


def list_cli() -> str:
    """The CLI ``OPENSHELL_SIDECAR_LIST_CLI`` names, or empty."""
    return (os.environ.get("OPENSHELL_SIDECAR_LIST_CLI") or "").strip()


def _field(value: Any) -> str:
    return value if isinstance(value, str) else ""


def cli_list(cli: str, *, run: Optional[Callable[..., Any]] = None,
             timeout: float = LIST_TIMEOUT_SECONDS) -> List[Dict[str, str]]:
    """Every sandbox on the gateway, in every workspace, as the ``openshell``
    CLI lists them: ``sandbox list --all-workspaces -o json``, page by page.
    Each entry is its workspace, id, name and phase. Raises when a page
    cannot be had or read, when the pages do not end, or after *timeout*.

    The CLI runs with the sidecar's environment, so it uses the gateway and
    identity its user registered; it is not given the credential.
    """
    run = run or subprocess.run
    env = {name: value for name, value in os.environ.items() if name not in _NOT_FOR_THE_CLI}
    env["NO_COLOR"] = "1"
    deadline = time.monotonic() + timeout
    listed: List[Dict[str, str]] = []
    token = ""
    for _page in range(LIST_MAX_PAGES):
        argv = [cli, "sandbox", "list", "--all-workspaces", "-o", "json",
                "--page-size", str(LIST_PAGE_SIZE)]
        if token:
            argv += ["--page-token", token]
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("the sandbox listing took too long")
        done = run(argv, env=env, stdin=subprocess.DEVNULL, capture_output=True,
                   timeout=left, check=False)
        if done.returncode != 0:
            raise RuntimeError(f"openshell sandbox list exited {done.returncode}")
        page = json.loads(done.stdout)
        sandboxes = page.get("sandboxes") if isinstance(page, dict) else None
        token = page.get("next_page_token") if isinstance(page, dict) else None
        if not isinstance(sandboxes, list) or not isinstance(token, str):
            raise ValueError("openshell sandbox list printed no page of sandboxes")
        listed += [{"workspace": _field(item.get("workspace")) or DEFAULT_WORKSPACE,
                    "id": _field(item.get("id")), "name": _field(item.get("name")),
                    "phase": _field(item.get("phase"))}
                   for item in sandboxes if isinstance(item, dict)]
        if not token:
            return listed
    raise RuntimeError(f"openshell sandbox list has more than {LIST_MAX_PAGES} pages")


def _entry(sandbox_id: str, name: str, phase: str, policy_hash: str) -> Dict[str, Any]:
    return {"id": sandbox_id, "name": name, "phase": phase, "command": "",
            "base_policy_hash": "", "effective_policy_hash": policy_hash,
            "provider_profiles": []}


def snapshot(ledger: Optional[GatewayLedger] = None, *,
             workspaces: Optional[Sequence[str]] = None,
             lister: Optional[ListFn] = None,
             cli: Optional[str] = None) -> Dict[str, Any]:
    """This gateway's sandboxes, as the engine's inventory route takes them.

    Never raises. ``partial`` says the list may not be every sandbox:

    * With a *cli* to list through (``OPENSHELL_SIDECAR_LIST_CLI`` by
      default), every workspace is listed, and the listing replaces what the
      ledger held. ``partial`` is false. If the listing fails, the snapshot is
      what the ledger holds, it is partial, and ``error`` names the failure.
    * Otherwise, with *workspaces* to list, each is listed whole, and what the listing
      returns replaces what the ledger held for it. ``partial`` is false.
      If a listing fails, the snapshot is what the ledger holds, it is
      partial, and ``error`` names the failure.
    * With none, the snapshot is what the ledger holds: the sandboxes this
      sidecar has seen created. It is partial until the ledger is marked
      complete.
    * More than 200 sandboxes are sent as the first 200, partial.

    A sandbox's effective policy hash is the one its last committed update
    reported to this sidecar. One it has not seen is sent empty.
    """
    ledger = ledger if ledger is not None else _LEDGER
    cli = list_cli() if cli is None else cli
    workspaces = list_workspaces() if workspaces is None else list(workspaces)
    error = ""
    phases: Dict[str, str] = {}
    listed_whole = every_workspace = False
    if cli:
        try:
            everything = cli_list(cli)
            ledger.replace_all([(entry["workspace"], entry["name"], entry["id"])
                                for entry in everything])
            phases.update({entry["id"]: entry["phase"] for entry in everything})
            listed_whole = every_workspace = True
        except Exception as exc:  # noqa: BLE001 - the snapshot is still sent, as partial
            logger.warning("openshell listing failed: %s", type(exc).__name__)
            error = type(exc).__name__
    elif workspaces:
        try:
            listed = (lister or sdk_list)(workspaces)
            for workspace in workspaces:
                entries = listed.get(workspace) or []
                # An entry with no name or no id is not kept.
                ledger.replace_workspace(
                    workspace, [(entry.get("name"), entry.get("id")) for entry in entries])
                phases.update({entry.get("id"): str(entry.get("phase") or "")
                               for entry in entries})
            listed_whole = True
        except ImportError:
            error = "openshell_sdk_missing"
        except Exception as exc:  # noqa: BLE001 - the snapshot is still sent, as partial
            logger.warning("openshell listing failed: %s", type(exc).__name__)
            error = type(exc).__name__
    known = ledger.sandboxes()
    if listed_whole and not every_workspace:
        # Only what was listed: a workspace that was not asked for is not in
        # a snapshot that says it is whole.
        known = [entry for entry in known if entry["workspace"] in workspaces]
    partial = not (listed_whole or ledger.complete)
    if len(known) > MAX_SNAPSHOT_SANDBOXES:
        known, partial = known[:MAX_SNAPSHOT_SANDBOXES], True
    result: Dict[str, Any] = {
        "gateway_id": _gateway_id(),
        "sandboxes": [_entry(entry["id"], entry["name"], phases.get(entry["id"], ""),
                             entry["effective_policy_hash"]) for entry in known],
        "partial": partial,
    }
    if error:
        result["error"] = error
    return result


def inventory() -> Dict[str, Any]:
    """The snapshot as ``GET /artzain/inventory`` serves it. Never raises.

    The engine's connector reads ``degraded`` as "this is not every
    sandbox" and then takes none of them, so a partial snapshot is
    degraded.
    """
    current = snapshot()
    answer = {"gateway_id": current["gateway_id"], "sandboxes": current["sandboxes"],
              "degraded": bool(current["partial"])}
    if current["partial"]:
        answer["error"] = current.get("error") or "partial_inventory"
    return answer


#: The earlier name of :func:`inventory`.
sdk_inventory = inventory


def _engine_url(path: str) -> str:
    """An engine URL from ``ARTZAIN_DECISION_URL`` (origin or decisions URL).

    Empty when unset, or when it is not an ``http``/``https`` URL with a host.
    """
    url = (os.environ.get("ARTZAIN_DECISION_URL") or "").strip().rstrip("/")
    if not url:
        return ""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        return ""
    if url.endswith("/api/v1/decisions"):
        return url[: -len("/api/v1/decisions")] + path
    return url + path


#: The engine client, with the settings it was built for (:func:`_client`).
_CLIENT: Optional[Tuple[Optional[transport.Settings],
                         Optional[transport.EngineClient]]] = None
_CLIENT_LOCK = threading.Lock()


def _client() -> Optional[transport.EngineClient]:
    """The client for the engine the environment names, or None when it
    names none. Raises :class:`transport.SettingsError` for a proxy or a
    certificate bundle that cannot be honoured.

    It is built again only when a setting changes: building one builds a
    TLS context, which loads the certificate store, and a new client has
    no kept connection.
    """
    global _CLIENT
    settings = transport.settings_from_environment()
    with _CLIENT_LOCK:
        built = _CLIENT
        if built is not None and built[0] == settings:
            return built[1]
        if built is not None and built[1] is not None:
            built[1].close()
        _CLIENT = None  # so a settings error is met again, not a stale client
        client = transport.EngineClient(settings) if settings is not None else None
        _CLIENT = (settings, client)
        return client


def _engine_request(method: str, target: str, key: str, data: Optional[bytes], *,
                    deadline: float, retry_on_reset: bool) -> Any:
    """One JSON request to the engine, answered before *deadline*. Raises
    on failure; a status that is not 2xx is an ``urllib.error.HTTPError``
    that carries the answer's headers and what was read of its body."""
    from artzain import cloud

    client = _client()
    if client is None:
        raise RuntimeError("engine URL unset")
    headers = cloud._api_request_headers(key)
    headers["Accept"] = "application/json"
    if data is not None:
        headers["Content-Type"] = "application/json"
    status, answer_headers, body = client.request(
        method, target, headers=headers, body=data, deadline=deadline,
        retry_on_reset=retry_on_reset)
    if not 200 <= status < 300:
        raise urllib.error.HTTPError(target, status, "engine answered %d" % status,
                                     answer_headers, io.BytesIO(body))
    return json.loads(body or b"null")


def _read_answer(resp: Any, deadline: float) -> Any:
    """Read a JSON answer of at most ``_MAX_ANSWER_BYTES`` before *deadline*."""
    chunks = []
    size = 0
    while True:
        if time.monotonic() > deadline:
            raise TimeoutError("sidecar engine deadline passed")
        chunk = resp.read(_READ_CHUNK)
        if not chunk:
            break
        size += len(chunk)
        if size > _MAX_ANSWER_BYTES:
            raise ValueError("engine answer too large")
        chunks.append(chunk)
    return json.loads(b"".join(chunks) or b"null")


def _post_engine(target: str, key: str, payload: Mapping[str, Any], *,
                 retry_on_reset: bool, timeout: Optional[float] = None) -> Any:
    """``POST`` JSON to the engine inside one deadline. Raises on failure.

    The deadline is the decision deadline unless *timeout* gives another.

    Nothing is followed, so a 3xx is an error like any other status. With
    *retry_on_reset*, a connection reset is retried once, at once, in the
    time that is left. Nothing else is retried. The deadline starts before
    the client is built, which loads the certificate store (see
    :func:`warm`).
    """
    deadline = time.monotonic() + (decide_timeout_seconds() if timeout is None else timeout)
    return _engine_request("POST", target, key, json.dumps(dict(payload)).encode("utf-8"),
                           deadline=deadline, retry_on_reset=retry_on_reset)


def _rate_limited(exc: urllib.error.HTTPError, deadline: float) -> Dict[str, Any]:
    """The deny for an engine 429: how long to wait, and the hourly limit
    when the engine names it.

    The wait is the ``Retry-After`` header (:func:`_retry_after_seconds`).
    """
    header = exc.headers.get("Retry-After") if exc.headers else None
    limited: Dict[str, Any] = {"outcome": "deny", "status_code": 429, "decision_id": "",
                               "retry_after": _retry_after_seconds(str(header or ""))}
    limit = _named_limit(exc, deadline)
    if limit:
        limited["limit_per_hour"] = limit
    return limited


def _retry_after_seconds(raw: str) -> int:
    """A ``Retry-After`` value as whole seconds, held to 1 s .. 24 h. A
    value that is not a count of seconds (a date, a fraction, nothing)
    means 1 s."""
    raw = raw.strip()
    if not (raw.isascii() and raw.isdigit()):
        return 1
    digits = raw.lstrip("0")
    if len(digits) > 5:  # past 24 h whatever it says
        return 86400
    return max(1, min(int(digits or "0"), 86400))


def _named_limit(exc: urllib.error.HTTPError, deadline: float) -> int:
    """``detail.limit_per_hour`` of a 429's answer, read before *deadline*.
    0 when the answer cannot be read or names no limit: the limit is a
    detail of the reason, and the refusal stands without it."""
    try:
        answer = _read_answer(exc, deadline)
    except Exception:  # noqa: BLE001 - see the docstring
        return 0
    detail = answer.get("detail") if isinstance(answer, dict) else None
    limit = detail.get("limit_per_hour") if isinstance(detail, dict) else None
    if isinstance(limit, bool) or not isinstance(limit, int):
        return 0
    return limit if 0 < limit < 10**9 else 0


def http_decide(payload: Dict[str, Any]) -> Dict[str, Any]:
    """``POST`` the Decision API. Fail closed. The key is not logged."""
    key = os.environ.get("COGNEXUS_API_KEY") or ""
    target = _engine_url("/api/v1/decisions")
    if not target or not key:
        return {"outcome": "deny", "status_code": 503, "decision_id": ""}
    started = time.monotonic()
    try:
        body = _post_engine(
            target, key, payload,
            retry_on_reset=bool(str(payload.get("request_id") or "").strip()),
        )
    except Exception as exc:  # noqa: BLE001 - interceptor must deny, not raise
        if isinstance(exc, urllib.error.HTTPError) and exc.code == 429:
            limited = _rate_limited(exc, started + decide_timeout_seconds())
            logger.warning("decision API rate limit reached; retry in %d s",
                           limited["retry_after"])
            return limited
        logger.warning("decision API unreachable: %s", type(exc).__name__)
        return {"outcome": "deny", "status_code": 503, "decision_id": ""}
    _LATENCY.add((time.monotonic() - started) * 1000.0)
    if not isinstance(body, dict):
        return {"outcome": "deny", "status_code": 503, "decision_id": ""}
    body.setdefault("status_code", 200)
    return body


def http_report_projection(payload: Dict[str, Any]) -> bool:
    """Report a committed policy hash. True when the engine took it now.
    Fail open: never raises, never blocks commit.

    The report joins the journal behind any that wait, and the journal is
    then delivered in order (:func:`deliver_reports`). So with nothing
    waiting it is sent at once, and when the engine is out of reach it
    waits its turn instead of being lost. A report that is not delivered
    now is counted once, for the heartbeat.
    """
    if not (os.environ.get("COGNEXUS_API_KEY") or "") or not _engine_url(""):
        logger.warning("projection report skipped: decision URL or key unset")
        return False
    seq = _JOURNAL.append("projection", payload)
    if seq is None:
        logger.warning("projection report dropped: the journal is full")
        _UNDELIVERED.add()
        return False
    delivered = deliver_reports()
    if seq in delivered:
        return True
    _UNDELIVERED.add()
    return False


def _send_report(entry: Mapping[str, Any]) -> str:
    """Send one journal entry: ``delivered``, ``refused`` (for good) or
    ``later``. Never raises.

    A 409 is the engine saying this decision already recorded its
    projection: an earlier try landed and its answer was lost, so it is
    delivered. A report that has waited :data:`REPORT_MAX_AGE_SECONDS` is
    given up.
    """
    key = os.environ.get("COGNEXUS_API_KEY") or ""
    target = _engine_url("/api/v1/openshell/projections")
    if entry.get("kind") != "projection":
        logger.warning("journal entry of a kind this sidecar does not send: dropped")
        return "refused"
    if not target or not key:
        return "later"
    try:
        _post_engine(target, key, entry["body"], retry_on_reset=False)
        return "delivered"
    except urllib.error.HTTPError as exc:
        if exc.code == 409:
            return "delivered"
        if exc.code in _REPORT_REFUSED:
            logger.warning("projection report refused: HTTP %d", exc.code)
            return "refused"
        failure = "HTTP %d" % exc.code
    except Exception as exc:  # noqa: BLE001 - post_commit cannot fail closed
        failure = type(exc).__name__
    if time.time() * 1000 - int(entry.get("at_ms") or 0) > REPORT_MAX_AGE_SECONDS * 1000:
        logger.warning("projection report given up after %d h: %s",
                       REPORT_MAX_AGE_SECONDS // 3600, failure)
        return "refused"
    logger.warning("projection report failed: %s", failure)
    return "later"


def deliver_reports() -> List[int]:
    """Send the reports that wait, oldest first, until one cannot be sent
    now. Returns the ``seq`` of each one the engine took. Never raises.

    One thread delivers at a time, so the order holds. A caller that finds
    another already delivering returns at once: that one, or the next
    turn of the housekeeping loop, sends what it added.
    """
    delivered: List[int] = []
    if not _DELIVERING.acquire(blocking=False):
        return delivered
    try:
        journal = _JOURNAL
        while True:
            entry = journal.first()
            if entry is None:
                break
            outcome = _send_report(entry)
            if outcome == "later":
                break
            journal.settle(entry["seq"])
            if outcome == "delivered":
                delivered.append(entry["seq"])
    except Exception as exc:  # noqa: BLE001 - see the docstring
        logger.warning("report delivery error: %s", type(exc).__name__)
    finally:
        _DELIVERING.release()
    return delivered


class LatencyWindow:
    """The last *size* engine round trips, in milliseconds."""

    def __init__(self, size: int = 512) -> None:
        self._lock = threading.Lock()
        self._samples: "deque[float]" = deque(maxlen=size)

    def add(self, milliseconds: float) -> None:
        with self._lock:
            self._samples.append(max(0.0, float(milliseconds)))

    def percentile(self, fraction: float) -> Optional[int]:
        """The sample at *fraction* of the way up (nearest rank), or None
        when there is none yet."""
        with self._lock:
            ordered = sorted(self._samples)
        if not ordered:
            return None
        rank = max(1, -(-len(ordered) * fraction // 1))  # ceil, at least the first
        return int(round(ordered[min(len(ordered), int(rank)) - 1]))


class Counter:
    """A count several threads add to."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._value = 0

    def add(self, amount: int = 1) -> None:
        with self._lock:
            self._value = max(0, self._value + amount)

    @property
    def value(self) -> int:
        with self._lock:
            return self._value


#: This process's recent allows and known sandboxes (see ``GatewayLedger``).
#: :func:`main` replaces it with one that keeps its sandboxes in the state
#: file when ``OPENSHELL_SIDECAR_STATE`` is set.
_LEDGER: GatewayLedger = GatewayLedger()
#: Decision round trips, for the heartbeat's p50 and p95.
_LATENCY = LatencyWindow()
#: Reports to the engine that failed since the last heartbeat it took.
_UNDELIVERED = Counter()
#: The reports the engine has not taken yet, in order. :func:`main` replaces
#: it with one kept in ``OPENSHELL_SIDECAR_JOURNAL`` when that is set.
_JOURNAL: Journal = Journal()
#: Held by the one thread that is delivering the journal.
_DELIVERING = threading.Lock()
#: The base policy the engine delivered. None unless this sidecar holds a
#: gateway credential (:func:`main`): a sidecar on an account key is not
#: given one, and decides a create with no policy as it always did.
_BASE: Optional[base_policies.BasePolicyStore] = None


def _after_post_commit(request: Mapping[str, Any], result: Mapping[str, Any],
                       ledger: OperationLedger) -> None:
    """What a committed write teaches the sidecar, and reports to the engine.

    A committed create returns the sandbox's uuid: the ledger remembers it by
    workspace and name, because later calls name the sandbox that way. A
    committed update returns the new policy hash and the sandbox's
    annotations, the decision stamp among them: that pair, with the sandbox
    the decision named, is the projection report. A write this sidecar did
    not stamp, or whose sandbox it could not resolve, is not reported.
    """
    method = method_name(str(request.get("method") or ""))
    if method not in BOUND_POST:
        return
    body = request.get("body") if isinstance(request.get("body"), dict) else {}
    if method == "CreateSandbox":
        sandbox = body.get("sandbox") if isinstance(body.get("sandbox"), dict) else {}
        metadata = sandbox.get("metadata") if isinstance(sandbox.get("metadata"), dict) else {}
        ledger.learn_sandbox(str(metadata.get("workspace") or DEFAULT_WORKSPACE),
                             str(metadata.get("name") or ""), str(metadata.get("id") or ""))
    annotations = result.get("log_annotations") if isinstance(
        result.get("log_annotations"), dict) else {}
    policy_hash = str(
        annotations.get("policy_hash")
        or body.get("policy_hash")
        or body.get("policyHash")
        or ""
    ).strip()
    # ``evaluate`` read the stamp off the committed write into the annotations.
    decision_id = str(annotations.get("decision_id") or "").strip()
    decided = ledger.decided(decision_id) if decision_id else None
    sandbox_id = str(
        (decided or {}).get("sandbox_id")
        or request.get("sandbox_id")
        or body.get("sandbox_id")
        or ""
    ).strip()
    if policy_hash and sandbox_id and isinstance(ledger, GatewayLedger):
        # The inventory sends this hash, whether or not a report follows.
        ledger.note_policy_hash(sandbox_id, policy_hash)
    if not (policy_hash and decision_id and sandbox_id):
        return
    http_report_projection({
        "sandbox_id": sandbox_id[:200],
        "policy_hash": policy_hash[:128],
        "decision_id": decision_id[:26],
        "method": method,
    })


def _as_this_gateway(request: Mapping[str, Any]) -> Dict[str, Any]:
    """The request as this sidecar decides it.

    The gateway and the agent are this sidecar's, whatever the request says.
    The decision's ``request_id`` is the operation's own at-most-once id when
    it has one (``requestId`` in the gateway's protobuf-JSON), or a fresh one,
    so a retried call replays instead of sealing twice.
    """
    gateway_id = _gateway_id()
    out = dict(request)
    out["gateway_id"] = gateway_id
    out["agent_did"] = f"openshell:{gateway_id}"
    body = out.get("body") if isinstance(out.get("body"), dict) else {}
    if not str(out.get("request_id") or "").strip():
        own = str(body.get("requestId") or body.get("request_id") or "").strip()
        out["request_id"] = own or uuid.uuid4().hex
    return out


def handle_evaluate(request: Dict[str, Any], *,
                    decide: Optional[DecideFn] = None,
                    base_policy: Optional[Dict[str, Any]] = None,
                    ledger: Optional[OperationLedger] = None) -> Dict[str, Any]:
    """Answer one interceptor call as this gateway. Fail closed before commit."""
    ledger = ledger if ledger is not None else _LEDGER
    request = _as_this_gateway(request)
    base_required = False
    if base_policy is None and _BASE is not None:
        state, base_policy = _BASE.current()
        base_required = state == base_policies.UNKNOWN
    result = evaluate(request, decide=decide or http_decide, base_policy=base_policy,
                      ledger=ledger, base_required=base_required)
    if str(request.get("phase") or "") == PHASE_POST:
        try:
            _after_post_commit(request, result, ledger)
        except Exception as exc:  # noqa: BLE001 - post_commit must stay allow
            logger.warning("projection report hook failed: %s", type(exc).__name__)
    return result


def handle_ocsf(event: Dict[str, Any], *,
                decide: Optional[DecideFn] = None) -> Dict[str, Any]:
    """Classify one OpenShell event, and seal it when it is a policy event."""
    classified = classify_ocsf(event)
    if classified.get("disposition") != "seal":
        return classified
    caller = decide or http_decide
    seal = {
        **classified["decision"],
        "agent_did": f"openshell:{_gateway_id()}",
        "request_id": uuid.uuid4().hex,
    }
    try:
        decision = caller(seal)
    except Exception as exc:  # noqa: BLE001
        logger.warning("ocsf seal failed: %s", type(exc).__name__)
        return {**classified, "sealed": False, "error": type(exc).__name__}
    return {
        **classified,
        "sealed": str(decision.get("outcome") or "") == "allow" or bool(decision.get("decision_id")),
        "decision_id": decision.get("decision_id"),
    }


def _authorized(header: str) -> bool:
    expected = os.environ.get("OPENSHELL_SIDECAR_TOKEN") or ""
    if not expected:
        return True
    prefix = "Bearer "
    if not header.startswith(prefix):
        return False
    presented = header[len(prefix):]
    return hmac.compare_digest(presented, expected)


def make_handler(inventory_fn: InventoryFn, decide: DecideFn,
                 base_policy: Optional[Dict[str, Any]] = None,
                 reports_fn: Optional[Callable[[], Dict[str, Any]]] = None) -> type:
    """HTTP handler. ``log_message`` is a no-op so tokens and bodies stay out of logs.

    *reports_fn* answers ``GET /artzain/reports`` (:meth:`Reporter.status`);
    without one the sidecar reports nothing, and says so.
    """

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003 - stdlib hook
            return None

        def _json(self, status: int, payload: Dict[str, Any]) -> None:
            raw = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _read_json(self) -> Optional[Dict[str, Any]]:
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0 or length > 1_000_000:
                return None
            try:
                parsed = json.loads(self.rfile.read(length).decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError):
                return None
            return parsed if isinstance(parsed, dict) else None

        def _gate(self) -> bool:
            if _authorized(self.headers.get("Authorization") or ""):
                return True
            self._json(401, {"allowed": False, "reason": "sidecar token rejected"})
            return False

        def do_GET(self) -> None:  # noqa: N802 - stdlib hook
            path = urllib.parse.urlparse(self.path).path
            if path == "/healthz":
                # Open to any local caller: it says only that the process is up.
                self._json(200, {"ok": True})
                return
            if not self._gate():
                return
            if path == "/artzain/reports":
                self._json(200, reports_fn() if reports_fn is not None else {"reporting": False})
                return
            if path != "/artzain/inventory":
                self._json(404, {"error": "not_found"})
                return
            self._json(200, inventory_fn())

        def do_POST(self) -> None:  # noqa: N802 - stdlib hook
            if not self._gate():
                return
            path = urllib.parse.urlparse(self.path).path
            payload = self._read_json()
            if payload is None:
                self._json(400, {"allowed": False, "reason": "body must be a JSON object"})
                return
            if path == "/v1/evaluate":
                self._json(200, handle_evaluate(payload, decide=decide, base_policy=base_policy))
                return
            if path == "/artzain/ocsf":
                self._json(200, handle_ocsf(payload, decide=decide))
                return
            self._json(404, {"error": "not_found"})

    return Handler


def _report(path: str, payload: Dict[str, Any]) -> Any:
    """``POST`` a heartbeat or an inventory to the engine. Raises on failure."""
    key = os.environ.get("COGNEXUS_API_KEY") or ""
    target = _engine_url(path)
    if not target or not key:
        raise RuntimeError("engine URL or key unset")
    return _post_engine(target, key, payload, retry_on_reset=False,
                        timeout=REPORT_TIMEOUT_SECONDS)


def _get_engine(target: str, key: str, *, timeout: float) -> Any:
    """``GET`` JSON from the engine inside *timeout*. Raises on failure."""
    return _engine_request("GET", target, key, None,
                           deadline=time.monotonic() + timeout, retry_on_reset=False)


def fetch_base_policy() -> Any:
    """Ask the engine for this gateway's base policy. Raises on failure;
    an HTTP error keeps its status (``urllib.error.HTTPError``)."""
    key = os.environ.get("COGNEXUS_API_KEY") or ""
    gateway = urllib.parse.quote(_gateway_id(), safe="")
    target = _engine_url(f"/api/v1/openshell/gateways/{gateway}/base-policy")
    if not target or not key:
        raise RuntimeError("engine URL or key unset")
    return _get_engine(target, key, timeout=REPORT_TIMEOUT_SECONDS)


def refresh_base_policy(store: base_policies.BasePolicyStore,
                        fetch: Optional[Callable[[], Any]] = None) -> Any:
    """Fetch the base policy into *store*. Returns the engine's answer, or
    None when there was none to take. Never raises.

    * An answer the store takes replaces what it held.
    * 409 is the engine saying the active bundle's base is not within its
      boundary. What the store held belongs to an earlier bundle, so it is
      forgotten, and a create with no policy is refused until that is put
      right.
    * Any other failure (the engine is unreachable, 5xx, an answer that
      fails its digest) leaves the store as it was.
    """
    try:
        answer = (fetch or fetch_base_policy)()
    except urllib.error.HTTPError as exc:
        if exc.code == 409:
            logger.warning("the engine holds a base policy it will not deliver (409)")
            store.invalidate()
        else:
            logger.warning("base policy fetch failed: HTTP %d", exc.code)
        return None
    except Exception as exc:  # noqa: BLE001 - the loop goes on
        logger.warning("base policy fetch failed: %s", type(exc).__name__)
        return None
    return answer if store.accept(answer) else None


#: How long the gateway's own version is kept before it is asked again: its
#: package can be upgraded under a running sidecar.
GATEWAY_VERSION_SECONDS = 600
_VERSION_IN = re.compile(r"(\d+)\.(\d+)\.(\d+)")
_gateway_version: Dict[str, Any] = {"at": None, "value": ""}
_gateway_version_lock = threading.Lock()


def _gateway_openshell_version() -> str:
    """What ``openshell-gateway --version`` says, when the gateway's binary is
    on this host's PATH (the deb or rpm gateway that ``artzain connect
    openshell`` binds), or empty. An answer, or the lack of one, is kept for
    :data:`GATEWAY_VERSION_SECONDS`."""
    now = time.monotonic()
    with _gateway_version_lock:
        at = _gateway_version["at"]
        if at is not None and now - at < GATEWAY_VERSION_SECONDS:
            return _gateway_version["value"]
        value = ""
        binary = shutil.which("openshell-gateway")
        if binary:
            try:
                done = subprocess.run([binary, "--version"], capture_output=True, text=True,
                                      timeout=10, check=False)
                found = _VERSION_IN.search(f"{done.stdout or ''} {done.stderr or ''}")
                if done.returncode == 0 and found:
                    value = found.group(0)
            except (OSError, subprocess.SubprocessError):
                pass
        _gateway_version.update(at=now, value=value)
        return value


def _sdk_openshell_version() -> str:
    """The installed OpenShell SDK's version, or empty."""
    try:
        from importlib import metadata

        return str(metadata.version("openshell"))[:40]
    except Exception:  # noqa: BLE001 - not installed, or no metadata
        return ""


def _openshell_version() -> str:
    """The OpenShell version the heartbeat reports: the gateway's own when its
    binary is on this host, else the installed OpenShell SDK's, else empty.
    The engine tells the gateway's owner about OpenShell's security advisories
    by it."""
    return _gateway_openshell_version() or _sdk_openshell_version()


def _interval(answer: Any, name: str, default: float) -> float:
    """The interval the engine asked for, held to 30 s .. 1 h."""
    value = answer.get(name) if isinstance(answer, dict) else None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return default
    return max(_MIN_INTERVAL_SECONDS, min(_MAX_INTERVAL_SECONDS, float(value)))


class Reporter:
    """Sends this gateway's heartbeat and inventory to the engine.

    * A heartbeat every minute: the sidecar's version, the OpenShell SDK's
      when it is installed, the registration digest when it is configured,
      the p50 and p95 of recent decision round trips, and how many reports
      failed since the last heartbeat the engine took.
    * The inventory every five minutes, and a few seconds after the ledger
      changes. A listing that failed is tried again after
      :data:`LISTING_RETRY_SECONDS`, up to :data:`LISTING_RETRY_LIMIT`
      times, and each try is still sent: a partial one says the list may
      not be every sandbox.
    * The engine's answer may ask for another interval; it is held to
      30 s .. 1 h.
    * Nothing here raises, and a heartbeat or an inventory the engine did
      not take is not retried before its next turn. It is counted, not
      queued: the next one carries the same state.
    * With a base policy store, the base policy is fetched first, at start
      and every five minutes.
    """

    def __init__(self, ledger: GatewayLedger, *, post: Optional[PostFn] = None,
                 lister: Optional[ListFn] = None,
                 clock: Callable[[], float] = time.monotonic,
                 latency: Optional[LatencyWindow] = None,
                 undelivered: Optional[Counter] = None,
                 base: Optional[base_policies.BasePolicyStore] = None,
                 fetch_base: Optional[Callable[[], Any]] = None) -> None:
        self._base = base
        self._fetch_base = fetch_base
        self._base_every = BASE_POLICY_SECONDS
        self._next_base = clock()
        self._ledger = ledger
        self._post = post or _report
        self._lister = lister
        self._clock = clock
        self._latency = latency if latency is not None else _LATENCY
        self._undelivered = undelivered if undelivered is not None else _UNDELIVERED
        self._heartbeat_every = HEARTBEAT_SECONDS
        self._inventory_every = INVENTORY_SECONDS
        self._next_heartbeat = clock()
        self._next_inventory = clock()
        self._listing_retries = 0
        self._sent_revision: Optional[int] = None
        self._changed_at: Optional[float] = None
        self._status_lock = threading.Lock()
        self._status: Dict[str, Any] = {"reporting": True, "heartbeat": "pending",
                                        "inventory": "pending"}

    def status(self) -> Dict[str, Any]:
        """Whether the engine took the last heartbeat and the last inventory
        (``pending`` before the first try, then ``ok`` or ``failed`` with the
        failure's name), and what that inventory held: how many sandboxes,
        whether it was partial, and why a listing failed."""
        with self._status_lock:
            return dict(self._status)

    def _note(self, what: str, error: str = "", **taken: Any) -> None:
        with self._status_lock:
            self._status[what] = "failed" if error else "ok"
            if error:
                self._status[f"{what}_error"] = error
            else:
                self._status.pop(f"{what}_error", None)
                self._status.update(taken)

    def heartbeat_body(self) -> Dict[str, Any]:
        from artzain import __version__

        body: Dict[str, Any] = {"sidecar_version": __version__,
                                "undelivered_reports": self._undelivered.value}
        openshell_version = _openshell_version()
        if openshell_version:
            body["openshell_version"] = openshell_version
        digest = (os.environ.get("OPENSHELL_REGISTRATION_DIGEST") or "").strip().lower()
        if len(digest) == 64 and all(ch in "0123456789abcdef" for ch in digest):
            body["registration_digest"] = digest
        for name, fraction in (("decide_p50_ms", 0.5), ("decide_p95_ms", 0.95)):
            value = self._latency.percentile(fraction)
            if value is not None:
                body[name] = value
        return body

    def send_heartbeat(self) -> bool:
        body = self.heartbeat_body()
        try:
            answer = self._post("/api/v1/openshell/heartbeat", body)
        except Exception as exc:  # noqa: BLE001 - the loop goes on
            logger.warning("heartbeat failed: %s", type(exc).__name__)
            self._note("heartbeat", type(exc).__name__)
            return False
        self._note("heartbeat")
        # The engine has the count now; what failed meanwhile stays counted.
        self._undelivered.add(-int(body["undelivered_reports"]))
        self._heartbeat_every = _interval(answer, "next_heartbeat_seconds",
                                          self._heartbeat_every)
        return True

    def send_inventory(self) -> bool:
        revision = self._ledger.revision
        current = snapshot(self._ledger, lister=self._lister)
        try:
            answer = self._post("/api/v1/openshell/inventory",
                                {"sandboxes": current["sandboxes"],
                                 "partial": bool(current["partial"])})
        except Exception as exc:  # noqa: BLE001 - the loop goes on
            logger.warning("inventory report failed: %s", type(exc).__name__)
            self._undelivered.add()
            self._note("inventory", type(exc).__name__)
            return False
        self._note("inventory", sandboxes=len(current["sandboxes"]),
                   partial=bool(current["partial"]))
        with self._status_lock:
            if current["partial"] and current.get("error"):
                self._status["listing_error"] = current["error"]
            else:
                self._status.pop("listing_error", None)
        # A listing changes the ledger too; what was sent is what it is now.
        self._sent_revision = max(revision, self._ledger.revision)
        self._changed_at = None
        self._inventory_every = _interval(answer, "next_inventory_seconds",
                                          self._inventory_every)
        return True

    def _listing_retry_due(self) -> bool:
        """Whether a listing that just failed should be tried again shortly.

        A post the engine did not take is not one of these: that failure
        waits for the ordinary interval. A listing that keeps failing gets
        :data:`LISTING_RETRY_LIMIT` prompt tries, and then the ordinary
        interval too, until a listing succeeds.
        """
        with self._status_lock:
            failed = bool(self._status.get("listing_error"))
        if not failed:
            self._listing_retries = 0
            return False
        if self._listing_retries >= LISTING_RETRY_LIMIT:
            return False
        self._listing_retries += 1
        return True

    def step(self) -> float:
        """Send what is due. Returns the seconds until something is."""
        now = self._clock()
        if self._base is not None and now >= self._next_base:
            answer = refresh_base_policy(self._base, self._fetch_base)
            self._base_every = _interval(answer, "refresh_seconds", self._base_every)
            self._next_base = now + self._base_every
        if now >= self._next_heartbeat:
            self.send_heartbeat()
            self._next_heartbeat = now + self._heartbeat_every
        changed = self._sent_revision is not None and (
            self._ledger.revision != self._sent_revision)
        if changed and self._changed_at is None:
            self._changed_at = now
        settled = (self._changed_at is not None
                   and now - self._changed_at >= INVENTORY_CHANGE_DELAY_SECONDS)
        if now >= self._next_inventory or settled:
            posted = self.send_inventory()
            self._next_inventory = now + self._inventory_every
            self._changed_at = None
            # The engine has the partial inventory. Try the listing again
            # shortly, so a gateway that was restarting is listed once it
            # is back, instead of at the next ordinary interval.
            if posted and self._listing_retry_due():
                self._next_inventory = now + LISTING_RETRY_SECONDS
        due = min(self._next_heartbeat, self._next_inventory)
        if self._base is not None:
            due = min(due, self._next_base)
        if self._changed_at is not None:
            due = min(due, self._changed_at + INVENTORY_CHANGE_DELAY_SECONDS)
        return max(0.0, due - self._clock())

    def run(self, stop: threading.Event) -> None:
        """Report until *stop* is set. Wakes at least every 5 s, so a
        change is noticed without anything having to signal it."""
        while not stop.is_set():
            try:
                wait = self.step()
            except Exception as exc:  # noqa: BLE001 - a report must not end the loop
                logger.warning("report loop error: %s", type(exc).__name__)
                wait = INVENTORY_CHANGE_DELAY_SECONDS
            stop.wait(min(max(wait, 0.5), INVENTORY_CHANGE_DELAY_SECONDS))


def reporter_for_environment(ledger: GatewayLedger) -> Optional[Reporter]:
    """A :class:`Reporter`, when this sidecar holds a gateway credential and
    an engine URL. With an account key the engine refuses its reports and
    hands it no base policy.

    It also sets up the base policy store (``_BASE``), read back from
    ``OPENSHELL_SIDECAR_BASE_POLICY`` when that names a file.
    """
    global _BASE
    key = os.environ.get("COGNEXUS_API_KEY") or ""
    if not key.startswith(GATEWAY_KEY_PREFIX) or not _engine_url(""):
        return None
    cache = (os.environ.get("OPENSHELL_SIDECAR_BASE_POLICY") or "").strip()
    _BASE = base_policies.BasePolicyStore(cache_path=cache or None,
                                          gateway_id=_gateway_id())
    return Reporter(ledger, base=_BASE)


def warm() -> bool:
    """Build the engine client and open a connection before a request
    needs one. True when a connection is waiting.

    Building the client builds a TLS context, which loads the certificate
    store, and a new connection costs the TCP and TLS handshakes. Paid
    inside a governed write, both eat into the gateway's timeout. Raises
    :class:`transport.SettingsError` for a setting that cannot be
    honoured; an engine that cannot be reached is not an error here.
    """
    client = _client()
    return client.warm() if client is not None else False


class Housekeeper:
    """What the sidecar does between requests: renews the warm connection
    every 30 s, and tries the reports that wait every 15 s."""

    def __init__(self, *, clock: Callable[[], float] = time.monotonic,
                 warm_fn: Optional[Callable[[], Any]] = None,
                 deliver: Optional[Callable[[], Any]] = None,
                 waiting: Optional[Callable[[], int]] = None) -> None:
        self._clock = clock
        self._warm = warm_fn or warm
        self._deliver = deliver or deliver_reports
        self._waiting = waiting or (lambda: len(_JOURNAL))
        self._next_warm = clock() + transport.WARM_EVERY_SECONDS
        self._next_delivery = clock() + REPORT_RETRY_SECONDS

    def step(self) -> float:
        """Do what is due. Returns the seconds until something is."""
        now = self._clock()
        if now >= self._next_delivery:
            self._next_delivery = now + REPORT_RETRY_SECONDS
            if self._waiting():
                self._deliver()
        if now >= self._next_warm:
            self._next_warm = now + transport.WARM_EVERY_SECONDS
            try:
                self._warm()
            except transport.SettingsError as exc:
                logger.warning("engine connection settings: %s", exc)
        return max(0.0, min(self._next_warm, self._next_delivery) - self._clock())

    def run(self, stop: threading.Event) -> None:
        """Keep house until *stop* is set."""
        while not stop.is_set():
            try:
                wait = self.step()
            except Exception as exc:  # noqa: BLE001 - the loop goes on
                logger.warning("housekeeping error: %s", type(exc).__name__)
                wait = REPORT_RETRY_SECONDS
            stop.wait(max(wait, 0.5))


def start_grpc(endpoint: str) -> Any:
    """Serve the gateway's ``GatewayInterceptor`` calls on *endpoint*.

    Needs the ``artzain[openshell]`` extra. Refuses to start on a
    configuration it cannot honour rather than serve unverified calls it was
    told to verify.
    """
    try:
        import google.protobuf  # noqa: F401 - the servicer imports these lazily
        import grpc  # noqa: F401

        from artzain.openshell import servicer
    except ImportError as exc:
        raise SystemExit(
            "OPENSHELL_SIDECAR_GRPC is set, but grpcio or protobuf is not installed: "
            "pip install 'artzain[openshell]'") from exc
    try:
        verifier = servicer.GatewayTokenVerifier.from_env()
    except (OSError, ValueError) as exc:
        raise SystemExit(f"gateway token settings: {exc}") from exc
    if verifier is None:
        logger.warning(
            "gateway calls are not verified: set OPENSHELL_JWT_PUBLIC_KEY and "
            "OPENSHELL_JWT_GATEWAY_ID when the gateway signs its extension calls")
    try:
        return servicer.serve(endpoint, servicer=servicer.Servicer(verifier=verifier))
    except ValueError as exc:
        raise SystemExit(f"OPENSHELL_SIDECAR_GRPC: {exc}") from exc


def main() -> None:
    host = os.environ.get("OPENSHELL_SIDECAR_HOST") or "127.0.0.1"
    port = int(os.environ.get("OPENSHELL_SIDECAR_PORT") or "8088")
    try:
        warm()
    except transport.SettingsError as exc:
        # Not a direct connection instead, and not the system's authorities.
        raise SystemExit(f"engine connection settings: {exc}") from exc
    built = _CLIENT
    logger.info("engine connection: %s",
                json.dumps(transport.describe(built[0] if built else None)))
    global _LEDGER, _JOURNAL
    state_path = (os.environ.get("OPENSHELL_SIDECAR_STATE") or "").strip()
    _LEDGER = GatewayLedger(state_path=state_path or None, gateway_id=_gateway_id())
    journal_path = (os.environ.get("OPENSHELL_SIDECAR_JOURNAL") or "").strip()
    _JOURNAL = Journal(path=journal_path or None, gateway_id=_gateway_id())
    if len(_JOURNAL):
        logger.info("%d report(s) from before the restart wait for the engine",
                    len(_JOURNAL))
    if not state_path:
        logger.info("OPENSHELL_SIDECAR_STATE is unset: sandbox names are kept in "
                    "memory only, and a restart loses them")
    # The gateway calls Describe when it starts, so the socket comes up first.
    grpc_endpoint = (os.environ.get("OPENSHELL_SIDECAR_GRPC") or "").strip()
    grpc_server = start_grpc(grpc_endpoint) if grpc_endpoint else None
    reporter = reporter_for_environment(_LEDGER)
    handler = make_handler(inventory, http_decide,
                           reports_fn=reporter.status if reporter is not None else None)
    server = ThreadingHTTPServer((host, port), handler)
    restore = _stop_on_signal(server)
    stop_reports = threading.Event()
    threading.Thread(target=Housekeeper().run, args=(stop_reports,), daemon=True,
                     name="openshell-housekeeping").start()
    if reporter is not None:
        threading.Thread(target=reporter.run, args=(stop_reports,), daemon=True,
                         name="openshell-reports").start()
    else:
        logger.info("heartbeat and inventory are not sent: they need a gateway "
                    "credential and ARTZAIN_DECISION_URL")
    logger.info("openshell sidecar listening on %s:%s", host, port)
    # The socket and the port are bound: whatever waits for the sidecar may
    # start now.
    _notify_ready()
    try:
        server.serve_forever()
    finally:
        stop_reports.set()
        restore()
        if grpc_server is not None:
            grpc_server.stop(5)


def _notify_ready() -> None:
    """Tell systemd the sidecar serves, when it runs as a ``Type=notify``
    unit (``NOTIFY_SOCKET`` set). The gateway's unit is ordered after the
    sidecar's, so it starts once the socket is there instead of racing it.
    A notification that cannot be sent is logged, and the sidecar serves on."""
    address = os.environ.get("NOTIFY_SOCKET") or ""
    if not address:
        return
    import socket

    if address.startswith("@"):  # an abstract socket
        address = "\0" + address[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect(address)
            sock.sendall(b"READY=1")
    except (OSError, AttributeError) as exc:  # AttributeError: no AF_UNIX here
        logger.warning("could not tell systemd the sidecar is ready: %s", type(exc).__name__)


def _stop_on_signal(server: Any) -> Callable[[], None]:
    """SIGTERM and SIGINT end :func:`main` cleanly: the HTTP loop stops, then
    the gRPC server drains for up to 5 s. Returns what puts the previous
    handlers back."""
    import signal

    def _stop(_signum: int, _frame: Any) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    previous = []
    for name in ("SIGTERM", "SIGINT"):
        sig = getattr(signal, name, None)
        if sig is None:
            continue
        try:
            previous.append((sig, signal.signal(sig, _stop)))
        except ValueError:  # not the main thread (tests, embedding)
            break

    def restore() -> None:
        for sig, handler in previous:
            signal.signal(sig, handler)

    return restore


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
