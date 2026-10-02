"""The gRPC service an OpenShell gateway calls: ``GatewayInterceptor``.

The gateway calls ``Describe`` once per registration when it starts, and
``Evaluate`` for each bound RPC and phase. This module answers both from
:func:`artzain.openshell.sidecar.handle_evaluate`, over a Unix socket (the
default) or a loopback TCP port. It never listens on a routable address.

* ``Describe`` returns the bindings the sidecar decides
  (:mod:`artzain.openshell.interceptor`'s ``BOUND_*`` sets) and the extension
  protocol metadata: protocol 1.0 and the
  ``openshell.gateway-interceptor.contract`` capability, supported and
  required. It makes no network call, so a gateway can start while the
  ArtzAIn engine is unreachable. A gateway on another protocol major, or one
  without the contract capability, is refused and does not start.
* ``Evaluate`` turns the protobuf call into the sidecar's request and the
  answer back. A deny carries ``PERMISSION_DENIED``, ``UNAVAILABLE`` when
  the engine could not decide, or ``RESOURCE_EXHAUSTED`` when its rate
  limit refused the decision. Patches go back only from
  ``modify_operation``, and a ``post_commit`` answer is always an allow: the
  gateway cannot revoke a commit.
* With ``OPENSHELL_JWT_PUBLIC_KEY`` set, every call must carry the gateway's
  signed token (``gateway_jwt``). A missing or invalid one is refused with
  ``UNAUTHENTICATED``. The gateway treats that as a failed call: a
  pre-commit write fails closed, and the gateway will not start while
  ``Describe`` is refused.

Needs ``grpcio``, ``protobuf`` and ``cryptography``:
``pip install 'artzain[openshell]'``.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import logging
import os
import time
from concurrent import futures
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from artzain.openshell import _wire
from artzain.openshell.interceptor import (
    BOUND_MODIFY,
    BOUND_POST,
    BOUND_VALIDATE,
    PHASE_MODIFY,
    PHASE_POST,
    PHASE_VALIDATE,
)

logger = logging.getLogger("artzain.openshell.servicer")

PROTOCOL_MAJOR = 1
PROTOCOL_MINOR = 0
CONTRACT_CAPABILITY = "openshell.gateway-interceptor.contract"
IMPLEMENTATION_NAME = "artzain/openshell-sidecar"
TOKEN_TYPE = "openshell-ext+jwt"
#: The audiences of the two registrations in the example gateway config.
DEFAULT_AUDIENCES = (
    "urn:openshell:extension:interceptor:artzain",
    "urn:openshell:extension:interceptor:artzain-observe",
)
#: The phases each of those registrations binds. The gateway logs a warning
#: for every binding a manifest declares and its registration does not
#: configure, so a caller known to be one of the two is told only its own.
REGISTRATION_PHASES = {
    DEFAULT_AUDIENCES[0]: (PHASE_MODIFY, PHASE_VALIDATE),
    DEFAULT_AUDIENCES[1]: (PHASE_POST,),
}
_SERVICE_RPC = "openshell.v1.OpenShell"
_MAX_TOKEN_BYTES = 8192
_MAX_REASON = 500
_MAX_ANNOTATION_KEY = 64
_MAX_ANNOTATION_VALUE = 256

HandleFn = Callable[[Dict[str, Any]], Dict[str, Any]]


def bindings(only: Optional[Sequence[str]] = None) -> List[Tuple[str, List[str]]]:
    """``(method, phases)`` for every method the sidecar decides, sorted.

    With *only*, the phases are limited to those, and a method left with
    none is left out.
    """
    methods = sorted(BOUND_VALIDATE | BOUND_MODIFY | BOUND_POST)
    out = []
    for method in methods:
        phases = [phase for phase, bound in (
            (PHASE_MODIFY, BOUND_MODIFY),
            (PHASE_VALIDATE, BOUND_VALIDATE),
            (PHASE_POST, BOUND_POST),
        ) if method in bound and (only is None or phase in only)]
        if phases:
            out.append((method, phases))
    return out


def registration_phases(claims: Optional[Mapping[str, Any]]) -> Optional[Tuple[str, ...]]:
    """The phases the calling registration binds, when its token says which it is.

    None when it cannot be told: no token, an audience that is not one of
    the example's two, or a token for both. Such a caller is told every
    binding, since a manifest that leaves out one its registration
    configures stops the gateway from starting.
    """
    if not claims:
        return None
    aud = claims.get("aud")
    named = aud if isinstance(aud, list) else [aud]
    if len(named) != 1 or not isinstance(named[0], str):
        return None
    return REGISTRATION_PHASES.get(named[0])


def status_name(status_code: int) -> str:
    """The gRPC status name the gateway reports for a deny: ``UNAVAILABLE``
    when the engine could not be asked, ``RESOURCE_EXHAUSTED`` when its rate
    limit refused the decision, ``PERMISSION_DENIED`` otherwise."""
    return {503: "UNAVAILABLE", 429: "RESOURCE_EXHAUSTED"}.get(
        int(status_code), "PERMISSION_DENIED")


def _implementation_version() -> str:
    try:
        from artzain import __version__
    except Exception:  # noqa: BLE001 - diagnostics only
        return ""
    return str(__version__)


# ---------------------------------------------------------------------------
# Gateway tokens
# ---------------------------------------------------------------------------


class TokenRejected(Exception):
    """The call's gateway token is missing or does not verify."""


def _b64url(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


class GatewayTokenVerifier:
    """Checks the EdDSA token a gateway with ``gateway_jwt`` puts on each call.

    The key is the gateway's ``public_key_path`` (an Ed25519 PEM). The issuer
    is ``openshell-gateway:<gateway_jwt.gateway_id>``, and the audience one of
    the registrations', ``urn:openshell:extension:interceptor:<name>``.
    """

    def __init__(self, public_key_pem: bytes, issuer: str,
                 audiences: Sequence[str] = DEFAULT_AUDIENCES, *,
                 leeway_seconds: int = 30, now: Callable[[], float] = time.time) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        key = load_pem_public_key(public_key_pem)
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("the gateway public key is not an Ed25519 key")
        if not issuer:
            raise ValueError("the gateway token issuer is empty")
        self._key = key
        self.issuer = issuer
        self.audiences = tuple(a for a in audiences if a)
        self._leeway = leeway_seconds
        self._now = now

    @classmethod
    def from_env(cls) -> Optional["GatewayTokenVerifier"]:
        """From ``OPENSHELL_JWT_PUBLIC_KEY`` (a path) and ``OPENSHELL_JWT_GATEWAY_ID``.

        None when no key is set. A key without a gateway id, or a key that
        cannot be read, is a configuration error.
        """
        path = (os.environ.get("OPENSHELL_JWT_PUBLIC_KEY") or "").strip()
        if not path:
            return None
        gateway_id = (os.environ.get("OPENSHELL_JWT_GATEWAY_ID") or "").strip()
        if not gateway_id:
            raise ValueError("OPENSHELL_JWT_PUBLIC_KEY is set without OPENSHELL_JWT_GATEWAY_ID")
        audiences = [a.strip() for a in (os.environ.get("OPENSHELL_JWT_AUDIENCES") or "").split(",")
                     if a.strip()] or list(DEFAULT_AUDIENCES)
        with open(path, "rb") as fh:
            pem = fh.read()
        return cls(pem, f"openshell-gateway:{gateway_id}", audiences)

    def verify(self, authorization: str) -> Dict[str, Any]:
        """The token's claims. Raises :class:`TokenRejected` with a short reason."""
        if not authorization:
            raise TokenRejected("no gateway token")
        if len(authorization) > _MAX_TOKEN_BYTES or not authorization.startswith("Bearer "):
            raise TokenRejected("malformed gateway token")
        parts = authorization[len("Bearer "):].strip().split(".")
        if len(parts) != 3:
            raise TokenRejected("malformed gateway token")
        try:
            header = json.loads(_b64url(parts[0]))
            claims = json.loads(_b64url(parts[1]))
            signature = _b64url(parts[2])
        except (ValueError, TypeError) as exc:
            raise TokenRejected("malformed gateway token") from exc
        if not isinstance(header, dict) or not isinstance(claims, dict):
            raise TokenRejected("malformed gateway token")
        if header.get("alg") != "EdDSA" or header.get("typ") != TOKEN_TYPE:
            raise TokenRejected("unexpected token type")
        try:
            self._key.verify(signature, f"{parts[0]}.{parts[1]}".encode("ascii"))
        except Exception as exc:  # noqa: BLE001 - InvalidSignature or a bad length
            raise TokenRejected("bad signature") from exc
        if claims.get("iss") != self.issuer:
            raise TokenRejected("wrong issuer")
        aud = claims.get("aud")
        audiences = aud if isinstance(aud, list) else [aud]
        if not any(a in self.audiences for a in audiences):
            raise TokenRejected("wrong audience")
        if claims.get("caller_kind") != "gateway":
            raise TokenRejected("not a gateway caller")
        now = self._now()
        exp = claims.get("exp")
        if not isinstance(exp, (int, float)) or isinstance(exp, bool) or exp + self._leeway < now:
            raise TokenRejected("expired")
        for early in ("nbf", "iat"):
            value = claims.get(early)
            if isinstance(value, (int, float)) and not isinstance(value, bool) \
                    and value - self._leeway > now:
                raise TokenRejected("not yet valid")
        return claims


# ---------------------------------------------------------------------------
# Protobuf to the sidecar's request, and back
# ---------------------------------------------------------------------------


def to_request(evaluation: Any) -> Optional[Dict[str, Any]]:
    """The sidecar request for one ``InterceptorEvaluation``; None without a phase."""
    from google.protobuf import json_format

    phase = evaluation.WhichOneof("phase")
    if phase == PHASE_MODIFY:
        body = evaluation.modify_operation.proposed_operation
    elif phase == PHASE_VALIDATE:
        body = evaluation.validate.proposed_operation
    elif phase == PHASE_POST:
        body = evaluation.post_commit.committed_response
    else:
        return None
    service = evaluation.service or _SERVICE_RPC
    return {
        "method": f"{service}/{evaluation.method}",
        "phase": phase,
        "body": json_format.MessageToDict(body),
        "principal": dict(evaluation.principal),
        "interceptor_name": evaluation.interceptor_name,
    }


def to_result(wire: Any, result: Mapping[str, Any], *, phase: Optional[str]) -> Any:
    """The ``InterceptorResult`` for the sidecar's answer to one phase."""
    from google.protobuf import json_format

    out = wire.InterceptorResult()
    if phase == PHASE_POST:
        out.allowed = True
    else:
        out.allowed = bool(result.get("allowed"))
    out.reason = str(result.get("reason") or "")[:_MAX_REASON]
    if not out.allowed:
        out.status_code = status_name(int(result.get("status_code") or 403))
    if out.allowed and phase == PHASE_MODIFY:
        for patch in result.get("patches") or []:
            item = out.patches.add(op=str(patch.get("op") or ""), path=str(patch.get("path") or ""))
            if "value" in patch:
                json_format.ParseDict(patch["value"], item.value)
            if patch.get("from"):
                setattr(item, "from", str(patch["from"]))
    for key, value in (result.get("log_annotations") or {}).items():
        out.log_annotations[str(key)[:_MAX_ANNOTATION_KEY]] = str(value)[:_MAX_ANNOTATION_VALUE]
    return out


# ---------------------------------------------------------------------------
# The service
# ---------------------------------------------------------------------------


class Servicer:
    """``Describe`` and ``Evaluate``. *handle* is the sidecar's decision."""

    def __init__(self, *, handle: Optional[HandleFn] = None,
                 verifier: Optional[GatewayTokenVerifier] = None,
                 wire: Any = None) -> None:
        if handle is None:
            from artzain.openshell.sidecar import handle_evaluate
            handle = handle_evaluate
        self._handle = handle
        self._verifier = verifier
        self.wire = wire or _wire.load()

    def _authenticate(self, context: Any) -> Optional[Dict[str, Any]]:
        """The verified token's claims, or None when no key is configured."""
        if self._verifier is None:
            return None
        import grpc

        metadata = dict(context.invocation_metadata() or ())
        try:
            return self._verifier.verify(str(metadata.get("authorization") or ""))
        except TokenRejected as exc:
            logger.warning("gateway token rejected: %s", exc)
            context.abort(grpc.StatusCode.UNAUTHENTICATED, f"gateway token rejected: {exc}")
        return None

    def manifest(self, only: Optional[Sequence[str]] = None) -> Any:
        """The manifest: every binding, or those in the phases *only* names."""
        w = self.wire
        out = w.InterceptorManifest(name="artzain", provider_profiles=False)
        phase_value = {
            PHASE_MODIFY: _wire.PHASE_MODIFY_OPERATION,
            PHASE_VALIDATE: _wire.PHASE_VALIDATE,
            PHASE_POST: _wire.PHASE_POST_COMMIT,
        }
        for method, phases in bindings(only):
            out.bindings.add(
                id=f"artzain-{method}",
                selector=w.InterceptorSelector(rpc=f"{_SERVICE_RPC}/{method}"),
                phases=[phase_value[p] for p in phases],
            )
        out.extension.CopyFrom(w.PeerMetadata(
            protocol_version=w.ProtocolVersion(major=PROTOCOL_MAJOR, minor=PROTOCOL_MINOR),
            implementation_name=IMPLEMENTATION_NAME,
            implementation_version=_implementation_version(),
            supported_capabilities=[CONTRACT_CAPABILITY],
            required_capabilities=[CONTRACT_CAPABILITY],
        ))
        return out

    def Describe(self, request: Any, context: Any) -> Any:  # noqa: N802 - gRPC method name
        claims = self._authenticate(context)
        gateway = request.gateway
        problem = _gateway_metadata_problem(gateway)
        if problem:
            import grpc

            logger.warning("gateway refused at Describe: %s", problem)
            context.abort(grpc.StatusCode.FAILED_PRECONDITION, problem)
        return self.manifest(registration_phases(claims))

    def Evaluate(self, request: Any, context: Any) -> Any:  # noqa: N802 - gRPC method name
        self._authenticate(context)
        call = to_request(request)
        if call is None:
            return to_result(self.wire, {"allowed": False, "status_code": 403,
                                         "reason": "evaluation carried no phase"}, phase=None)
        try:
            result = self._handle(call)
        except Exception as exc:  # noqa: BLE001 - a failed decision is a closed gate
            logger.warning("interceptor evaluation failed: %s", type(exc).__name__)
            result = {"allowed": False, "status_code": 503, "reason": "decision unavailable"}
        return to_result(self.wire, result, phase=call["phase"])


def _gateway_metadata_problem(gateway: Any) -> str:
    version = gateway.protocol_version
    if not gateway.HasField("protocol_version"):
        return "the gateway sent no protocol metadata"
    if version.major != PROTOCOL_MAJOR:
        return (f"the gateway speaks interceptor protocol {version.major}.{version.minor}; "
                f"this sidecar speaks {PROTOCOL_MAJOR}.{PROTOCOL_MINOR}")
    if CONTRACT_CAPABILITY not in gateway.supported_capabilities:
        return f"the gateway does not support {CONTRACT_CAPABILITY}"
    missing = [c for c in gateway.required_capabilities if c != CONTRACT_CAPABILITY]
    if missing:
        return "the gateway requires capabilities this sidecar lacks: " + ", ".join(missing)
    return ""


# ---------------------------------------------------------------------------
# Serving
# ---------------------------------------------------------------------------


def parse_endpoint(endpoint: str) -> Tuple[str, str]:
    """``("unix", path)`` or ``("tcp", "host:port")``. Loopback only.

    Accepts ``unix:///absolute/path``, or ``http://127.0.0.1:PORT``,
    ``127.0.0.1:PORT``, ``localhost:PORT`` and ``[::1]:PORT``.
    """
    text = (endpoint or "").strip()
    if text.startswith("unix://"):
        path = text[len("unix://"):]
        if not path.startswith("/"):
            raise ValueError("a unix:// endpoint needs an absolute path")
        return "unix", path
    if text.startswith("http://"):
        text = text[len("http://"):]
    host, _, port = text.rpartition(":")
    host = host.strip("[]")
    if not host or not port.isdigit() or not 0 < int(port) < 65536:
        raise ValueError("expected unix:///path or a loopback host:port")
    if host != "localhost":
        try:
            if not ipaddress.ip_address(host).is_loopback:
                raise ValueError("the sidecar listens on loopback only")
        except ValueError as exc:
            raise ValueError("the sidecar listens on loopback only") from exc
    return "tcp", f"{'[::1]' if host == '::1' else host}:{port}"


def _socket_mode() -> int:
    raw = (os.environ.get("OPENSHELL_SIDECAR_SOCKET_MODE") or "").strip()
    try:
        mode = int(raw, 8) if raw else 0o600
    except ValueError:
        mode = 0o600
    return mode & 0o660


def serve(endpoint: str, *, servicer: Servicer, max_workers: int = 16) -> Any:
    """Start the gRPC server on *endpoint* and return it (``server.stop(grace)``)."""
    import grpc

    wire = servicer.wire

    def _serialize(message: Any) -> bytes:
        return message.SerializeToString()

    handlers = {
        "Describe": grpc.unary_unary_rpc_method_handler(
            servicer.Describe, request_deserializer=wire.DescribeRequest.FromString,
            response_serializer=_serialize),
        "Evaluate": grpc.unary_unary_rpc_method_handler(
            servicer.Evaluate, request_deserializer=wire.InterceptorEvaluation.FromString,
            response_serializer=_serialize),
    }
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=max_workers))
    server.add_generic_rpc_handlers((grpc.method_handlers_generic_handler(_wire.SERVICE, handlers),))
    kind, address = parse_endpoint(endpoint)
    if kind == "unix":
        directory = os.path.dirname(address)
        os.makedirs(directory, mode=0o700, exist_ok=True)
        if os.path.exists(address):
            os.unlink(address)  # a stale socket from a previous run
        old_umask = os.umask(0o177)
        try:
            bound = server.add_insecure_port(f"unix:{address}")
        finally:
            os.umask(old_umask)
    else:
        bound = server.add_insecure_port(address)
    if not bound:
        raise OSError(f"could not listen on {endpoint}")
    server.start()
    if kind == "unix" and hasattr(os, "chmod"):
        try:
            os.chmod(address, _socket_mode())
        except OSError as exc:
            logger.warning("could not set the socket mode: %s", type(exc).__name__)
    logger.info("gateway interceptor listening on %s", endpoint)
    return server
