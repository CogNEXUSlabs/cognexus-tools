"""The gRPC ``GatewayInterceptor`` service in ``artzain.openshell.servicer``.

What an OpenShell v0.1.2 gateway needs from its interceptor, checked against
the protocol itself:

* The messages built at runtime (``_wire``) match, field by field, a
  descriptor set compiled from the pinned v0.1.2 ``gateway_interceptor.proto``
  and ``extension.proto`` (``fixtures/openshell_interceptor_v0_1_2.pb``;
  source SHA-256 below).
* ``Describe`` declares exactly the bindings the sidecar decides, and the
  extension handshake the gateway checks at startup; it refuses a gateway on
  another protocol major.
* ``Evaluate`` maps each phase to the sidecar's request and the answer back:
  status names, patches only from ``modify_operation``, ``post_commit``
  always an allow.
* Gateway tokens: with a key set, every call needs a valid token.
* The server listens on loopback or a Unix socket only.

Real gRPC calls go over a real server.
"""

from __future__ import annotations

import base64
import json
import os
import stat
import sys
import time
from pathlib import Path

import pytest

if os.environ.get("GITHUB_ACTIONS"):
    # CI installs the [openshell] dependencies; a skip there would hide the servicer.
    import google.protobuf  # noqa: F401
    import grpc  # noqa: F401
grpc = pytest.importorskip("grpc")
pytest.importorskip("google.protobuf")
pytest.importorskip("cryptography")

from google.protobuf import descriptor_pb2, json_format  # noqa: E402

from artzain.openshell import _wire, servicer  # noqa: E402
from artzain.openshell import interceptor as osi  # noqa: E402

FIXTURE = Path(__file__).parent / "fixtures" / "openshell_interceptor_v0_1_2.pb"
#: The protos the fixture was compiled from, at OpenShell tag v0.1.2
#: (integrations/openshell/wire-spike/fetch-protos.sh pins the same hashes).
PROTO_SHA256 = {
    "gateway_interceptor.proto": "931411aaae512b41117039f35b8c8727c8aefa87e898879e8b6f277c0149f79d",
    "extension.proto": "60f28ee9dc846d41152f4db7e82a439c78d024786efaceb464900d1d1ad129ad",
}
GATEWAY_META = {
    "protocol_version": {"major": 1},
    "implementation_name": "openshell/gateway",
    "implementation_version": "0.1.2",
    "supported_capabilities": ["openshell.gateway-interceptor.contract"],
    "required_capabilities": ["openshell.gateway-interceptor.contract"],
}


@pytest.fixture(scope="module")
def wire():
    return _wire.load()


# ---------------------------------------------------------------------------
# The runtime messages are the v0.1.2 protocol
# ---------------------------------------------------------------------------


def _upstream():
    fds = descriptor_pb2.FileDescriptorSet.FromString(FIXTURE.read_bytes())
    return {f.name: f for f in fds.file}


def _shape(message):
    return {
        "oneofs": [o.name for o in message.oneof_decl],
        "fields": sorted(
            (f.name, f.number, f.type, f.label, f.type_name,
             f.oneof_index if f.HasField("oneof_index") else None)
            for f in message.field),
        "nested": sorted(
            (n.name, n.options.map_entry,
             tuple(sorted((x.name, x.number, x.type) for x in n.field)))
            for n in message.nested_type),
    }


def test_every_runtime_message_matches_the_pinned_protocol():
    upstream = _upstream()
    ours = {f.package: f for f in _wire.file_descriptor_protos()}
    for package, source in (("openshell.extension.v1", "extension.proto"),
                            ("openshell.gateway_interceptor.v1", "gateway_interceptor.proto")):
        theirs = {m.name: m for m in upstream[source].message_type}
        assert upstream[source].package == package
        for message in ours[package].message_type:
            assert message.name in theirs, message.name
            assert _shape(message) == _shape(theirs[message.name]), message.name


def test_the_phase_enum_matches_the_pinned_protocol():
    upstream = _upstream()["gateway_interceptor.proto"]
    ours = _wire.file_descriptor_protos()[1]
    assert [(v.name, v.number) for v in ours.enum_type[0].value] == \
           [(v.name, v.number) for v in upstream.enum_type[0].value]


def test_the_served_methods_match_the_pinned_service():
    upstream = {m.name: (m.input_type, m.output_type)
                for m in _upstream()["gateway_interceptor.proto"].service[0].method}
    ours = {m.name: (m.input_type, m.output_type)
            for m in _wire.file_descriptor_protos()[1].service[0].method}
    # SnapshotProviderProfiles is not served: provider_profiles is false.
    assert set(upstream) - set(ours) == {"SnapshotProviderProfiles"}
    for name, types in ours.items():
        assert upstream[name] == types


def test_the_fixture_names_its_pinned_sources():
    # The hashes are the ones the wire-spike fetch script pins; keep them in step.
    script = Path(__file__).resolve().parents[2] / "integrations" / "openshell" / \
        "wire-spike" / "fetch-protos.sh"
    if not script.is_file():
        pytest.skip("the engine tree is not beside the SDK (public mirror)")
    text = script.read_text(encoding="utf-8")
    for name, digest in PROTO_SHA256.items():
        assert f"{digest} {name}" in text


# ---------------------------------------------------------------------------
# Describe
# ---------------------------------------------------------------------------


class _Context:
    def __init__(self, metadata=()):
        self._metadata = tuple(metadata)
        self.aborted = None

    def invocation_metadata(self):
        return self._metadata

    def abort(self, code, details):
        self.aborted = (code, details)
        raise RuntimeError(details)


def _describe(wire, meta=None):
    return json_format.ParseDict({"gateway": meta if meta is not None else GATEWAY_META},
                                 wire.DescribeRequest())


def test_describe_declares_exactly_the_decided_bindings(wire):
    manifest = servicer.Servicer(handle=lambda _r: {}, wire=wire).Describe(
        _describe(wire), _Context())
    declared = {b.selector.rpc: sorted(b.phases) for b in manifest.bindings}
    expected = {}
    for method in osi.BOUND_VALIDATE | osi.BOUND_MODIFY | osi.BOUND_POST:
        phases = []
        if method in osi.BOUND_MODIFY:
            phases.append(_wire.PHASE_MODIFY_OPERATION)
        if method in osi.BOUND_VALIDATE:
            phases.append(_wire.PHASE_VALIDATE)
        if method in osi.BOUND_POST:
            phases.append(_wire.PHASE_POST_COMMIT)
        expected[f"openshell.v1.OpenShell/{method}"] = sorted(phases)
    assert declared == expected
    assert len({b.id for b in manifest.bindings}) == len(manifest.bindings)
    assert manifest.provider_profiles is False


def test_describe_speaks_the_extension_protocol(wire):
    manifest = servicer.Servicer(handle=lambda _r: {}, wire=wire).Describe(
        _describe(wire), _Context())
    ext = manifest.extension
    assert (ext.protocol_version.major, ext.protocol_version.minor) == (1, 0)
    assert list(ext.supported_capabilities) == ["openshell.gateway-interceptor.contract"]
    assert list(ext.required_capabilities) == ["openshell.gateway-interceptor.contract"]


@pytest.mark.parametrize("meta", [
    {},
    {**GATEWAY_META, "protocol_version": {"major": 2}},
    {**GATEWAY_META, "supported_capabilities": []},
    {**GATEWAY_META, "required_capabilities": ["openshell.gateway-interceptor.contract",
                                               "openshell.gateway-interceptor.streaming"]},
])
def test_describe_refuses_a_gateway_it_cannot_serve(wire, meta):
    context = _Context()
    with pytest.raises(RuntimeError):
        servicer.Servicer(handle=lambda _r: {}, wire=wire).Describe(_describe(wire, meta), context)
    assert context.aborted[0] == grpc.StatusCode.FAILED_PRECONDITION


def test_describe_makes_no_decision(wire):
    def handle(_request):
        raise AssertionError("Describe must not decide")

    servicer.Servicer(handle=handle, wire=wire).Describe(_describe(wire), _Context())


# ---------------------------------------------------------------------------
# Evaluate
# ---------------------------------------------------------------------------


def _evaluation(wire, phase, body, method="UpdateConfig", principal=None):
    payload_key = "committed_response" if phase == "post_commit" else "proposed_operation"
    return json_format.ParseDict({
        "interceptor_name": "artzain", "binding_id": f"artzain-{method}",
        "service": "openshell.v1.OpenShell", "method": method,
        "principal": principal or {"subject": "u-1", "kind": "user"},
        phase: {payload_key: body},
    }, wire.InterceptorEvaluation())


def _run(wire, evaluation, answer):
    seen = []

    def handle(request):
        seen.append(request)
        return answer

    result = servicer.Servicer(handle=handle, wire=wire).Evaluate(evaluation, _Context())
    return result, seen


def test_a_validate_call_reaches_the_sidecar_as_its_request(wire):
    body = {"sandbox": "s1", "mergeOperations": [{"addRule": {"ruleName": "r"}}],
            "workspaceScope": {"workspace": "default"}}
    result, seen = _run(wire, _evaluation(wire, "validate", body),
                        {"allowed": True, "status_code": 200, "reason": "decision allow",
                         "log_annotations": {"decision_id": "01X"}})
    assert seen == [{
        "method": "openshell.v1.OpenShell/UpdateConfig",
        "phase": "validate",
        "body": body,
        "principal": {"subject": "u-1", "kind": "user"},
        "interceptor_name": "artzain",
    }]
    assert result.allowed is True
    assert result.status_code == ""
    assert dict(result.log_annotations) == {"decision_id": "01X"}


@pytest.mark.parametrize("code, name", [(403, "PERMISSION_DENIED"), (503, "UNAVAILABLE")])
def test_a_deny_carries_its_status_name(wire, code, name):
    result, _ = _run(wire, _evaluation(wire, "validate", {"sandbox": "s1"}),
                     {"allowed": False, "status_code": code, "reason": "decision deny"})
    assert result.allowed is False
    assert result.status_code == name
    assert result.reason == "decision deny"


def test_modify_operation_returns_the_patches(wire):
    patch = {"op": "add", "path": "/spec/policy", "value": {"version": 1}}
    result, _ = _run(wire, _evaluation(wire, "modify_operation", {"spec": {}}, "CreateSandbox"),
                     {"allowed": True, "patches": [patch]})
    assert json_format.MessageToDict(result)["patches"] == [patch]


def test_patches_go_back_from_modify_operation_only(wire):
    patch = {"op": "add", "path": "/spec/policy", "value": {"version": 1}}
    result, _ = _run(wire, _evaluation(wire, "validate", {"spec": {}}, "CreateSandbox"),
                     {"allowed": True, "patches": [patch]})
    assert list(result.patches) == []


def test_post_commit_is_always_an_allow(wire):
    result, seen = _run(wire, _evaluation(wire, "post_commit", {"policyHash": "ab" * 32}),
                        {"allowed": False, "status_code": 403, "reason": "x"})
    assert seen[0]["phase"] == "post_commit"
    assert seen[0]["body"] == {"policyHash": "ab" * 32}
    assert result.allowed is True
    assert result.status_code == ""


def test_an_evaluation_without_a_phase_is_denied_without_a_decision(wire):
    def handle(_request):
        raise AssertionError("must not decide")

    evaluation = wire.InterceptorEvaluation(method="UpdateConfig")
    result = servicer.Servicer(handle=handle, wire=wire).Evaluate(evaluation, _Context())
    assert result.allowed is False
    assert result.status_code == "PERMISSION_DENIED"


def test_a_failing_decision_is_unavailable(wire):
    def handle(_request):
        raise RuntimeError("boom")

    result = servicer.Servicer(handle=handle, wire=wire).Evaluate(
        _evaluation(wire, "validate", {"sandbox": "s1"}), _Context())
    assert result.allowed is False
    assert result.status_code == "UNAVAILABLE"


def test_the_sidecar_rules_run_behind_the_servicer(wire, monkeypatch):
    # The default handle is the sidecar's: a global policy is denied before any decision.
    monkeypatch.setenv("OPENSHELL_GATEWAY_ID", "gw-a")
    result = servicer.Servicer(wire=wire).Evaluate(
        _evaluation(wire, "validate", {"global": True, "policy": {"version": 1}}), _Context())
    assert result.allowed is False
    assert "global" in result.reason


# ---------------------------------------------------------------------------
# Gateway tokens
# ---------------------------------------------------------------------------


def _keys():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = Ed25519PrivateKey.generate()
    pem = private.public_key().public_bytes(serialization.Encoding.PEM,
                                            serialization.PublicFormat.SubjectPublicKeyInfo)
    return private, pem


def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _token(private, **claims):
    header = {"alg": "EdDSA", "typ": "openshell-ext+jwt", "kid": "k1"}
    header.update(claims.pop("_header", {}))
    now = int(time.time())
    body = {"iss": "openshell-gateway:gw", "sub": "openshell-gateway:gw",
            "aud": "urn:openshell:extension:interceptor:artzain",
            "caller_kind": "gateway", "iat": now, "exp": now + 900, "jti": "j"}
    body.update(claims)
    signing = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(body).encode())}"
    return "Bearer " + signing + "." + _b64(private.sign(signing.encode("ascii")))


@pytest.fixture
def signed():
    private, pem = _keys()
    return private, servicer.GatewayTokenVerifier(pem, "openshell-gateway:gw")


def test_a_valid_gateway_token_is_accepted(signed):
    private, verifier = signed
    claims = verifier.verify(_token(private))
    assert claims["iss"] == "openshell-gateway:gw"
    verifier.verify(_token(private, aud="urn:openshell:extension:interceptor:artzain-observe"))


@pytest.mark.parametrize("change, reason", [
    ({"iss": "openshell-gateway:other"}, "wrong issuer"),
    ({"aud": "urn:openshell:extension:interceptor:someone-else"}, "wrong audience"),
    ({"caller_kind": "supervisor"}, "not a gateway caller"),
    ({"exp": int(time.time()) - 120}, "expired"),
    ({"exp": "soon"}, "expired"),
    ({"iat": int(time.time()) + 3600}, "not yet valid"),
    ({"_header": {"alg": "none"}}, "unexpected token type"),
    ({"_header": {"typ": "JWT"}}, "unexpected token type"),
])
def test_a_bad_gateway_token_is_rejected(signed, change, reason):
    private, verifier = signed
    with pytest.raises(servicer.TokenRejected, match=reason):
        verifier.verify(_token(private, **change))


def test_a_token_signed_by_another_key_is_rejected(signed):
    _private, verifier = signed
    other, _pem = _keys()
    with pytest.raises(servicer.TokenRejected, match="bad signature"):
        verifier.verify(_token(other))


@pytest.mark.parametrize("header", ["", "Basic abc", "Bearer a.b", "Bearer !!.!!.!!",
                                    "Bearer " + "a" * 9000])
def test_a_missing_or_malformed_token_is_rejected(signed, header):
    _private, verifier = signed
    with pytest.raises(servicer.TokenRejected):
        verifier.verify(header)


def test_with_a_key_every_call_needs_a_token(wire, signed):
    private, verifier = signed
    service = servicer.Servicer(handle=lambda _r: {"allowed": True}, wire=wire, verifier=verifier)
    context = _Context()
    with pytest.raises(RuntimeError):
        service.Evaluate(_evaluation(wire, "validate", {"sandbox": "s1"}), context)
    assert context.aborted[0] == grpc.StatusCode.UNAUTHENTICATED
    context = _Context()
    with pytest.raises(RuntimeError):
        service.Describe(_describe(wire), context)
    assert context.aborted[0] == grpc.StatusCode.UNAUTHENTICATED
    ok = service.Evaluate(_evaluation(wire, "validate", {"sandbox": "s1"}),
                          _Context([("authorization", _token(private))]))
    assert ok.allowed is True


def test_the_verifier_reads_its_settings(monkeypatch, tmp_path):
    _private, pem = _keys()
    key = tmp_path / "public.pem"
    key.write_bytes(pem)
    monkeypatch.delenv("OPENSHELL_JWT_PUBLIC_KEY", raising=False)
    assert servicer.GatewayTokenVerifier.from_env() is None
    monkeypatch.setenv("OPENSHELL_JWT_PUBLIC_KEY", str(key))
    monkeypatch.delenv("OPENSHELL_JWT_GATEWAY_ID", raising=False)
    with pytest.raises(ValueError):
        servicer.GatewayTokenVerifier.from_env()
    monkeypatch.setenv("OPENSHELL_JWT_GATEWAY_ID", "spike")
    verifier = servicer.GatewayTokenVerifier.from_env()
    assert verifier.issuer == "openshell-gateway:spike"
    assert verifier.audiences == servicer.DEFAULT_AUDIENCES


def test_a_key_that_is_not_ed25519_is_refused():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    pem = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    with pytest.raises(ValueError):
        servicer.GatewayTokenVerifier(pem, "openshell-gateway:gw")


# ---------------------------------------------------------------------------
# Serving, over real gRPC
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("endpoint, expected", [
    ("unix:///run/user/1000/artzain/openshell.sock",
     ("unix", "/run/user/1000/artzain/openshell.sock")),
    ("http://127.0.0.1:18081", ("tcp", "127.0.0.1:18081")),
    ("127.0.0.1:18081", ("tcp", "127.0.0.1:18081")),
    ("localhost:18081", ("tcp", "localhost:18081")),
    ("[::1]:18081", ("tcp", "[::1]:18081")),
])
def test_endpoints_are_unix_or_loopback(endpoint, expected):
    assert servicer.parse_endpoint(endpoint) == expected


@pytest.mark.parametrize("endpoint", [
    "0.0.0.0:18081", "10.0.0.8:18081", "gateway.example:18081", "unix://relative.sock",
    "127.0.0.1", "127.0.0.1:0", "127.0.0.1:99999", "",
])
def test_other_endpoints_are_refused(endpoint):
    with pytest.raises(ValueError):
        servicer.parse_endpoint(endpoint)


def _call(channel, method, request, response_cls, metadata=None):
    rpc = channel.unary_unary(f"/{_wire.SERVICE}/{method}",
                              request_serializer=lambda m: m.SerializeToString(),
                              response_deserializer=response_cls.FromString)
    return rpc(request, timeout=5, metadata=metadata)


def _free_port():
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


_ENDPOINTS = ["tcp"] + (["unix"] if os.name == "posix" else [])


@pytest.mark.parametrize("kind", _ENDPOINTS)
def test_a_gateway_can_describe_and_evaluate_over_grpc(wire, kind, tmp_path):
    if kind == "unix":
        path = tmp_path / "run" / "openshell.sock"
        endpoint, target = f"unix://{path}", f"unix:{path}"
    else:
        port = _free_port()
        endpoint = target = f"127.0.0.1:{port}"
    decided = []

    def handle(request):
        decided.append(request)
        return {"allowed": False, "status_code": 403, "reason": "decision deny"}

    server = servicer.serve(endpoint, servicer=servicer.Servicer(handle=handle, wire=wire))
    try:
        with grpc.insecure_channel(target) as channel:
            manifest = _call(channel, "Describe", _describe(wire), wire.InterceptorManifest)
            assert manifest.extension.protocol_version.major == 1
            result = _call(channel, "Evaluate", _evaluation(wire, "validate", {"sandbox": "s1"}),
                           wire.InterceptorResult)
        assert result.allowed is False and result.status_code == "PERMISSION_DENIED"
        assert decided[0]["body"] == {"sandbox": "s1"}
        if kind == "unix":
            assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
            assert stat.S_IMODE(os.stat(path.parent).st_mode) == 0o700
    finally:
        server.stop(0)


def test_an_unverified_call_is_refused_over_grpc(wire, signed):
    private, verifier = signed
    port = _free_port()
    server = servicer.serve(f"127.0.0.1:{port}", servicer=servicer.Servicer(
        handle=lambda _r: {"allowed": True}, wire=wire, verifier=verifier))
    try:
        with grpc.insecure_channel(f"127.0.0.1:{port}") as channel:
            with pytest.raises(grpc.RpcError) as refused:
                _call(channel, "Describe", _describe(wire), wire.InterceptorManifest)
            assert refused.value.code() == grpc.StatusCode.UNAUTHENTICATED
            manifest = _call(channel, "Describe", _describe(wire), wire.InterceptorManifest,
                             metadata=[("authorization", _token(private))])
            assert manifest.bindings
    finally:
        server.stop(0)


@pytest.mark.skipif(os.name != "posix", reason="POSIX socket modes")
def test_the_socket_mode_setting_is_honoured(wire, tmp_path, monkeypatch):
    monkeypatch.setenv("OPENSHELL_SIDECAR_SOCKET_MODE", "660")
    path = tmp_path / "s" / "openshell.sock"
    server = servicer.serve(f"unix://{path}", servicer=servicer.Servicer(
        handle=lambda _r: {}, wire=wire))
    try:
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o660
    finally:
        server.stop(0)


# ---------------------------------------------------------------------------
# The sidecar process
# ---------------------------------------------------------------------------


def test_the_sidecar_serves_grpc_before_http(monkeypatch):
    from artzain.openshell import sidecar

    order = []

    class _Server:
        def __init__(self, address, handler):
            order.append("bind")

        def serve_forever(self):
            order.append("serve")

        def shutdown(self):
            pass

    class _Grpc:
        def stop(self, grace):
            order.append(f"grpc-stop-{grace}")

    monkeypatch.setenv("OPENSHELL_SIDECAR_GRPC", "127.0.0.1:18081")
    monkeypatch.setattr(sidecar, "warm", lambda: order.append("warm"))
    monkeypatch.setattr(sidecar, "start_grpc", lambda endpoint: order.append("grpc") or _Grpc())
    monkeypatch.setattr(sidecar, "ThreadingHTTPServer", _Server)
    sidecar.main()
    assert order == ["warm", "grpc", "bind", "serve", "grpc-stop-5"]


def test_grpc_settings_it_cannot_honour_stop_the_sidecar(monkeypatch, tmp_path):
    from artzain.openshell import sidecar

    monkeypatch.setenv("OPENSHELL_JWT_PUBLIC_KEY", str(tmp_path / "missing.pem"))
    monkeypatch.setenv("OPENSHELL_JWT_GATEWAY_ID", "gw")
    with pytest.raises(SystemExit, match="gateway token settings"):
        sidecar.start_grpc("127.0.0.1:18081")
    monkeypatch.delenv("OPENSHELL_JWT_PUBLIC_KEY")
    with pytest.raises(SystemExit, match="OPENSHELL_SIDECAR_GRPC"):
        sidecar.start_grpc("0.0.0.0:18081")


def test_without_grpc_installed_the_sidecar_says_what_to_install(monkeypatch):
    from artzain.openshell import sidecar

    monkeypatch.setitem(sys.modules, "grpc", None)  # as if grpcio were not installed
    with pytest.raises(SystemExit, match=r"artzain\[openshell\]"):
        sidecar.start_grpc("127.0.0.1:18081")
