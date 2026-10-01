"""The gateway-interceptor protocol messages, built at runtime.

The gateway calls the gRPC service
``openshell.gateway_interceptor.v1.GatewayInterceptor``. Its messages are
defined in OpenShell's ``proto/gateway_interceptor.proto`` and
``proto/extension.proto``. OpenShell's own Python package does not ship
stubs for them, and generated stubs would tie this package to one protobuf
and grpcio release. So the messages the sidecar needs are declared here with
the same packages, names and field numbers, and built into a private
descriptor pool when the servicer starts.

``SnapshotProviderProfiles`` and its messages are left out: the sidecar
advertises ``provider_profiles = false``, so the gateway never calls it.

``tests/test_openshell_servicer.py`` checks every message here, field by
field, against a descriptor set compiled from the pinned v0.1.2 protos.

Needs ``protobuf`` (the ``artzain[openshell]`` extra).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Iterable, Tuple

EXTENSION_PACKAGE = "openshell.extension.v1"
INTERCEPTOR_PACKAGE = "openshell.gateway_interceptor.v1"
SERVICE = f"{INTERCEPTOR_PACKAGE}.GatewayInterceptor"

#: GatewayInterceptorPhase values.
PHASE_UNSPECIFIED = 0
PHASE_MODIFY_OPERATION = 2
PHASE_VALIDATE = 3
PHASE_POST_COMMIT = 4

# (name, number, type, label, type_name, oneof index or None)
_Field = Tuple[str, int, str, str, str, Any]

_EXTENSION_MESSAGES = {
    "ProtocolVersion": [
        ("major", 1, "UINT32", "OPTIONAL", "", None),
        ("minor", 2, "UINT32", "OPTIONAL", "", None),
    ],
    "PeerMetadata": [
        ("protocol_version", 1, "MESSAGE", "OPTIONAL",
         f".{EXTENSION_PACKAGE}.ProtocolVersion", None),
        ("implementation_name", 2, "STRING", "OPTIONAL", "", None),
        ("implementation_version", 3, "STRING", "OPTIONAL", "", None),
        ("supported_capabilities", 4, "STRING", "REPEATED", "", None),
        ("required_capabilities", 5, "STRING", "REPEATED", "", None),
    ],
}

_I = f".{INTERCEPTOR_PACKAGE}"
_INTERCEPTOR_MESSAGES = {
    "DescribeRequest": [
        ("gateway", 1, "MESSAGE", "OPTIONAL", f".{EXTENSION_PACKAGE}.PeerMetadata", None),
    ],
    "InterceptorEvaluation": [
        ("interceptor_name", 1, "STRING", "OPTIONAL", "", None),
        ("binding_id", 2, "STRING", "OPTIONAL", "", None),
        ("service", 3, "STRING", "OPTIONAL", "", None),
        ("method", 4, "STRING", "OPTIONAL", "", None),
        ("principal", 5, "MESSAGE", "REPEATED", f"{_I}.InterceptorEvaluation.PrincipalEntry", None),
        ("modify_operation", 6, "MESSAGE", "OPTIONAL", f"{_I}.ModifyOperationEvaluation", 0),
        ("validate", 7, "MESSAGE", "OPTIONAL", f"{_I}.ValidateEvaluation", 0),
        ("post_commit", 8, "MESSAGE", "OPTIONAL", f"{_I}.PostCommitEvaluation", 0),
    ],
    "ModifyOperationEvaluation": [
        ("proposed_operation", 1, "MESSAGE", "OPTIONAL", ".google.protobuf.Struct", None),
    ],
    "ValidateEvaluation": [
        ("proposed_operation", 1, "MESSAGE", "OPTIONAL", ".google.protobuf.Struct", None),
        ("current_state", 2, "MESSAGE", "OPTIONAL", ".google.protobuf.Struct", None),
    ],
    "PostCommitEvaluation": [
        ("committed_response", 1, "MESSAGE", "OPTIONAL", ".google.protobuf.Struct", None),
    ],
    "InterceptorResult": [
        ("allowed", 1, "BOOL", "OPTIONAL", "", None),
        ("reason", 2, "STRING", "OPTIONAL", "", None),
        ("status_code", 3, "STRING", "OPTIONAL", "", None),
        ("patches", 4, "MESSAGE", "REPEATED", f"{_I}.JsonPatch", None),
        ("log_annotations", 5, "MESSAGE", "REPEATED",
         f"{_I}.InterceptorResult.LogAnnotationsEntry", None),
    ],
    "InterceptorManifest": [
        ("name", 1, "STRING", "OPTIONAL", "", None),
        ("bindings", 2, "MESSAGE", "REPEATED", f"{_I}.InterceptorBinding", None),
        ("failure_policy", 3, "STRING", "OPTIONAL", "", None),
        ("provider_profiles", 4, "BOOL", "OPTIONAL", "", None),
        ("expected_audience", 5, "STRING", "OPTIONAL", "", None),
        ("extension", 6, "MESSAGE", "OPTIONAL", f".{EXTENSION_PACKAGE}.PeerMetadata", None),
    ],
    "InterceptorBinding": [
        ("id", 1, "STRING", "OPTIONAL", "", None),
        ("selector", 2, "MESSAGE", "OPTIONAL", f"{_I}.InterceptorSelector", None),
        ("phases", 3, "ENUM", "REPEATED", f"{_I}.GatewayInterceptorPhase", None),
        ("failure_policy", 4, "STRING", "OPTIONAL", "", None),
    ],
    "InterceptorSelector": [
        ("rpc", 1, "STRING", "OPTIONAL", "", None),
        ("service", 2, "STRING", "OPTIONAL", "", None),
        ("method", 3, "STRING", "OPTIONAL", "", None),
    ],
    "JsonPatch": [
        ("op", 1, "STRING", "OPTIONAL", "", None),
        ("path", 2, "STRING", "OPTIONAL", "", None),
        ("value", 3, "MESSAGE", "OPTIONAL", ".google.protobuf.Value", None),
        ("from", 4, "STRING", "OPTIONAL", "", None),
    ],
}
#: Map fields, as protoc writes them: a nested ``<Field>Entry`` message.
_MAP_ENTRIES = {
    "InterceptorEvaluation": "PrincipalEntry",
    "InterceptorResult": "LogAnnotationsEntry",
}
_ONEOFS = {"InterceptorEvaluation": ["phase"]}
_PHASES = [
    ("GATEWAY_INTERCEPTOR_PHASE_UNSPECIFIED", PHASE_UNSPECIFIED),
    ("GATEWAY_INTERCEPTOR_PHASE_MODIFY_OPERATION", PHASE_MODIFY_OPERATION),
    ("GATEWAY_INTERCEPTOR_PHASE_VALIDATE", PHASE_VALIDATE),
    ("GATEWAY_INTERCEPTOR_PHASE_POST_COMMIT", PHASE_POST_COMMIT),
]


def _message(d: Any, name: str, fields: Iterable[_Field]) -> Any:
    msg = d.DescriptorProto(name=name)
    for oneof in _ONEOFS.get(name, []):
        msg.oneof_decl.add(name=oneof)
    for fname, number, ftype, label, type_name, oneof in fields:
        field = msg.field.add(
            name=fname,
            number=number,
            type=d.FieldDescriptorProto.Type.Value(f"TYPE_{ftype}"),
            label=d.FieldDescriptorProto.Label.Value(f"LABEL_{label}"),
        )
        if type_name:
            field.type_name = type_name
        if oneof is not None:
            field.oneof_index = oneof
    entry = _MAP_ENTRIES.get(name)
    if entry:
        nested = msg.nested_type.add(name=entry)
        nested.options.map_entry = True
        for fname, number in (("key", 1), ("value", 2)):
            nested.field.add(
                name=fname, number=number,
                type=d.FieldDescriptorProto.TYPE_STRING,
                label=d.FieldDescriptorProto.LABEL_OPTIONAL,
            )
    return msg


def file_descriptor_protos() -> list:
    """The two protocol files as ``FileDescriptorProto`` messages."""
    from google.protobuf import descriptor_pb2 as d

    ext = d.FileDescriptorProto(
        name="artzain/openshell/wire/extension.proto",
        package=EXTENSION_PACKAGE, syntax="proto3",
    )
    for name, fields in _EXTENSION_MESSAGES.items():
        ext.message_type.append(_message(d, name, fields))

    gi = d.FileDescriptorProto(
        name="artzain/openshell/wire/gateway_interceptor.proto",
        package=INTERCEPTOR_PACKAGE, syntax="proto3",
        dependency=["google/protobuf/struct.proto", ext.name],
    )
    phase = gi.enum_type.add(name="GatewayInterceptorPhase")
    for vname, number in _PHASES:
        phase.value.add(name=vname, number=number)
    for name, fields in _INTERCEPTOR_MESSAGES.items():
        gi.message_type.append(_message(d, name, fields))
    service = gi.service.add(name="GatewayInterceptor")
    service.method.add(name="Describe", input_type=f"{_I}.DescribeRequest",
                       output_type=f"{_I}.InterceptorManifest")
    service.method.add(name="Evaluate", input_type=f"{_I}.InterceptorEvaluation",
                       output_type=f"{_I}.InterceptorResult")
    return [ext, gi]


def load() -> SimpleNamespace:
    """Build the protocol into a private pool and return its message classes."""
    from google.protobuf import descriptor_pb2, descriptor_pool, message_factory, struct_pb2

    pool = descriptor_pool.DescriptorPool()
    struct_file = descriptor_pb2.FileDescriptorProto()
    struct_pb2.DESCRIPTOR.CopyToProto(struct_file)
    pool.Add(struct_file)
    for fdp in file_descriptor_protos():
        pool.Add(fdp)

    def cls(full_name: str) -> Any:
        return message_factory.GetMessageClass(pool.FindMessageTypeByName(full_name))

    names = list(_EXTENSION_MESSAGES)
    out = {name: cls(f"{EXTENSION_PACKAGE}.{name}") for name in names}
    out.update({name: cls(f"{INTERCEPTOR_PACKAGE}.{name}") for name in _INTERCEPTOR_MESSAGES})
    out["Struct"] = cls("google.protobuf.Struct")
    out["Value"] = cls("google.protobuf.Value")
    out["pool"] = pool
    return SimpleNamespace(**out)
