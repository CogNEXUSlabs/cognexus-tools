"""The ArtzAIn sidecar that runs beside an OpenShell gateway.

It answers the gateway's interceptor calls with :func:`handle_evaluate` (the
rules are :mod:`artzain.openshell.interceptor`), asks the ArtzAIn Decision API,
reports the committed policy hash after a governed write, lists sandboxes for
the catalog, and seals OpenShell FINDING and CONFIG events. It only ever calls
out to the engine.

The gateway calls the gRPC ``GatewayInterceptor`` service
(:mod:`artzain.openshell.servicer`), served on ``OPENSHELL_SIDECAR_GRPC``
when that is set. The HTTP routes are for the ArtzAIn catalog and for tools:
``GET /artzain/inventory``, ``POST /v1/evaluate``, ``POST /artzain/ocsf``, and
an open ``GET /healthz``.

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
  URL. ``http`` or ``https`` only.
* ``COGNEXUS_API_KEY``: the Decision API key. Never logged.
* ``OPENSHELL_SIDECAR_DECIDE_TIMEOUT_MS``: the deadline for each engine call
  (default 1200, held to 50..30000). Keep it below the gateway
  registration's ``timeout`` so a slow engine is a sidecar deny, not a
  gateway transport error.

A connection reset is retried once inside the same deadline, only for a
decision that carries a ``request_id``: the Decision API replays a repeated
id instead of sealing and billing it twice. Nothing else is retried. The
handler never logs the key, the bearer, or a request body.

Run it with ``artzain openshell sidecar`` or
``python -m artzain.openshell.sidecar``.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, Mapping, Optional

from artzain.openshell.interceptor import (
    BOUND_POST,
    PHASE_POST,
    classify_ocsf,
    evaluate,
    method_name,
)

logger = logging.getLogger("artzain.openshell.sidecar")

InventoryFn = Callable[[], Dict[str, Any]]
DecideFn = Callable[[Dict[str, Any]], Dict[str, Any]]

#: Engine-call deadline in milliseconds, and its bounds. The example gateway
#: registration gives the interceptor 1500 ms; this stays under it.
DECIDE_TIMEOUT_MS_DEFAULT = 1200
_DECIDE_TIMEOUT_MS_MIN = 50
_DECIDE_TIMEOUT_MS_MAX = 30_000
#: A decision or projection answer is small; a larger body is refused.
_MAX_ANSWER_BYTES = 256 * 1024
_READ_CHUNK = 16 * 1024


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


def sdk_inventory() -> Dict[str, Any]:
    """List sandboxes when the OpenShell SDK is installed. Never raises."""
    gateway_id = _gateway_id()
    try:
        from openshell.sandbox import SandboxClient  # type: ignore
    except Exception as exc:  # noqa: BLE001 - missing SDK is a named degrade
        logger.info("openshell SDK unavailable: %s", type(exc).__name__)
        return {
            "gateway_id": gateway_id,
            "sandboxes": [],
            "degraded": True,
            "error": "openshell_sdk_missing",
        }
    try:
        client = SandboxClient()
        refs = client.list_all()
    except Exception as exc:  # noqa: BLE001 - the engine must still get a named degrade
        logger.warning("openshell inventory failed: %s", type(exc).__name__)
        return {
            "gateway_id": gateway_id,
            "sandboxes": [],
            "degraded": True,
            "error": type(exc).__name__,
        }
    sandboxes = []
    for ref in refs or []:
        status = getattr(ref, "status", None)
        sandboxes.append({
            "id": str(getattr(ref, "id", "") or ""),
            "name": str(getattr(ref, "name", "") or ""),
            "phase": str(getattr(status, "phase", "") or ""),
            "command": "",
            "base_policy_hash": str(getattr(ref, "base_policy_hash", "") or ""),
            "effective_policy_hash": str(getattr(ref, "effective_policy_hash", "") or ""),
            "provider_profiles": [],
        })
    return {"gateway_id": gateway_id, "sandboxes": sandboxes, "degraded": False}


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


def _is_connection_reset(exc: BaseException) -> bool:
    """A reset, or a close with no answer (``RemoteDisconnected``), raw or
    wrapped by urllib. A timeout is not one."""
    if isinstance(exc, ConnectionResetError):
        return True
    return (isinstance(exc, urllib.error.URLError)
            and isinstance(getattr(exc, "reason", None), ConnectionResetError))


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
                 retry_on_reset: bool) -> Any:
    """``POST`` JSON to the engine inside one deadline. Raises on failure.

    The SDK's opener follows no redirect, so a 3xx is an error like any other
    status. With *retry_on_reset*, a connection reset is retried once, at
    once, in the time that is left. Nothing else is retried. The deadline
    starts before the opener is built, which loads the certificate store
    (see :func:`warm`).
    """
    from artzain import cloud

    deadline = time.monotonic() + decide_timeout_seconds()
    headers = cloud._api_request_headers(key)
    headers["Content-Type"] = "application/json"
    headers["Accept"] = "application/json"
    data = json.dumps(dict(payload)).encode("utf-8")
    attempts = 2 if retry_on_reset else 1
    for attempt in range(attempts):
        opener = cloud._api_opener()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        req = urllib.request.Request(target, data=data, method="POST", headers=headers)
        try:
            with opener.open(req, timeout=remaining) as resp:
                return _read_answer(resp, deadline)
        except Exception as exc:
            if attempt + 1 < attempts and _is_connection_reset(exc):
                logger.info("engine connection reset; retrying once")
                continue
            raise
    raise TimeoutError("sidecar engine deadline passed")


def http_decide(payload: Dict[str, Any]) -> Dict[str, Any]:
    """``POST`` the Decision API. Fail closed. The key is not logged."""
    key = os.environ.get("COGNEXUS_API_KEY") or ""
    target = _engine_url("/api/v1/decisions")
    if not target or not key:
        return {"outcome": "deny", "status_code": 503, "decision_id": ""}
    try:
        body = _post_engine(
            target, key, payload,
            retry_on_reset=bool(str(payload.get("request_id") or "").strip()),
        )
    except Exception as exc:  # noqa: BLE001 - interceptor must deny, not raise
        logger.warning("decision API unreachable: %s", type(exc).__name__)
        return {"outcome": "deny", "status_code": 503, "decision_id": ""}
    if not isinstance(body, dict):
        return {"outcome": "deny", "status_code": 503, "decision_id": ""}
    body.setdefault("status_code", 200)
    return body


def http_report_projection(payload: Dict[str, Any]) -> bool:
    """``POST`` the projection report. Fail open: never raises, never blocks commit.

    Not retried: a decision id records one projection, so a report that
    landed before a reset would be refused the second time anyway.
    """
    key = os.environ.get("COGNEXUS_API_KEY") or ""
    target = _engine_url("/api/v1/openshell/projections")
    if not target or not key:
        logger.warning("projection report skipped: decision URL or key unset")
        return False
    try:
        body = _post_engine(target, key, payload, retry_on_reset=False)
    except Exception as exc:  # noqa: BLE001 - post_commit cannot fail closed
        logger.warning("projection report failed: %s", type(exc).__name__)
        return False
    return isinstance(body, dict) and bool(body.get("policy_hash") or body.get("sandbox_id"))


def _report_after_post_commit(request: Mapping[str, Any], result: Mapping[str, Any]) -> None:
    """Best-effort projection report after a bound post_commit evaluate."""
    method = method_name(str(request.get("method") or ""))
    if method not in BOUND_POST:
        return
    body = request.get("body") if isinstance(request.get("body"), dict) else {}
    annotations = result.get("log_annotations") if isinstance(
        result.get("log_annotations"), dict) else {}
    policy_hash = str(
        annotations.get("policy_hash")
        or body.get("policy_hash")
        or body.get("policyHash")
        or ""
    ).strip()
    decision_id = str(
        annotations.get("decision_id")
        or request.get("decision_id")
        or ""
    ).strip()
    sandbox_id = str(
        request.get("sandbox_id")
        or body.get("sandbox_id")
        or body.get("sandbox")
        or body.get("name")
        or ""
    ).strip()
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
                    base_policy: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Answer one interceptor call as this gateway. Fail closed before commit."""
    request = _as_this_gateway(request)
    result = evaluate(request, decide=decide or http_decide, base_policy=base_policy)
    if str(request.get("phase") or "") == PHASE_POST:
        try:
            _report_after_post_commit(request, result)
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
                 base_policy: Optional[Dict[str, Any]] = None) -> type:
    """HTTP handler. ``log_message`` is a no-op so tokens and bodies stay out of logs."""

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


def warm() -> None:
    """Build the engine opener before the first request.

    Building it builds a TLS context, which loads the certificate store. Paid
    inside the first governed write, that eats into the gateway's timeout.
    """
    from artzain import cloud

    cloud._api_opener()


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
    warm()
    # The gateway calls Describe when it starts, so the socket comes up first.
    grpc_endpoint = (os.environ.get("OPENSHELL_SIDECAR_GRPC") or "").strip()
    grpc_server = start_grpc(grpc_endpoint) if grpc_endpoint else None
    handler = make_handler(sdk_inventory, http_decide)
    server = ThreadingHTTPServer((host, port), handler)
    restore = _stop_on_signal(server)
    logger.info("openshell sidecar listening on %s:%s", host, port)
    try:
        server.serve_forever()
    finally:
        restore()
        if grpc_server is not None:
            grpc_server.stop(5)


def _stop_on_signal(server: Any) -> Callable[[], None]:
    """SIGTERM and SIGINT end :func:`main` cleanly: the HTTP loop stops, then
    the gRPC server drains for up to 5 s. Returns what puts the previous
    handlers back."""
    import signal
    import threading

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
