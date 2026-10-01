"""What the ArtzAIn sidecar decides for an OpenShell gateway, and how.

The gateway calls its interceptors in three phases: ``modify_operation`` and
``validate`` before a write commits, ``post_commit`` after it. This module is
the sidecar's answer to each call. It is pure: the Decision API call is the
``decide`` function passed in, and nothing here opens a socket or logs a
policy body or a token.

* ``validate`` on a bound method builds one decision request and allows only
  an ``allow`` from the Decision API. ``review``, ``deny``, a 503 and a failed
  call are all denies. A method outside the bound set is denied without a
  decision.
* ``modify_operation`` on ``CreateSandbox`` adds the compiled base policy
  when the request carries none. It never replaces an operator's policy.
* ``post_commit`` always allows and never decides: it cannot revoke a commit.
* An ``UpdateConfig`` with ``global: true`` is denied: a gateway-global
  policy replaces every sandbox policy.

Pinned to OpenShell v0.1.2.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from typing import Any, Callable, Dict, List, Mapping, Optional

logger = logging.getLogger("artzain.openshell")

PINNED_OPENSHELL = "v0.1.2"

#: Interceptor phases. ``post_commit`` cannot fail closed.
PHASE_MODIFY = "modify_operation"
PHASE_VALIDATE = "validate"
PHASE_POST = "post_commit"

#: The methods and phases the sidecar decides. The gateway registration binds
#: exactly these; any other bound method would be denied outright.
BOUND_VALIDATE = frozenset({
    "CreateSandbox",
    "UpdateConfig",
    "ApproveDraftChunk",
    "RejectDraftChunk",
    "ApproveAllDraftChunks",
    "EditDraftChunk",
    "AttachSandboxProvider",
    "DetachSandboxProvider",
})
BOUND_MODIFY = frozenset({"CreateSandbox"})
BOUND_POST = frozenset({"CreateSandbox", "UpdateConfig"})
PROVIDER_METHODS = frozenset({"AttachSandboxProvider", "DetachSandboxProvider"})

SEAL_CLASSES = frozenset({"FINDING", "CONFIG"})
SEAL_ACTIVITIES = frozenset({"PROPOSED", "APPROVED", "REJECTED", "LOADED"})
_CLASS_BY_UID = {4001: "NET", 4002: "HTTP", 2004: "FINDING", 5019: "CONFIG"}

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_SECRET_KEY = re.compile(r"(secret|token|credential|password|authorization)", re.I)

DecideFn = Callable[[Mapping[str, Any]], Mapping[str, Any]]
FetchFn = Callable[[str], Any]


def method_name(method: str) -> str:
    """``openshell.v1.OpenShell/CreateSandbox`` becomes ``CreateSandbox``."""
    text = str(method or "").strip()
    if "/" in text:
        text = text.rsplit("/", 1)[-1]
    if "." in text:
        text = text.rsplit(".", 1)[-1]
    return text


def _request_id(raw: Any) -> str:
    text = str(raw or "").strip()
    if _REQUEST_ID_RE.match(text):
        return text
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest() if text else ""
    return digest[:32]


def _strip_secrets(value: Any, depth: int = 0) -> Any:
    """Drop secret-shaped keys. Used before a decision payload is built."""
    if depth > 8:
        return None
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if _SECRET_KEY.search(str(key)):
                continue
            out[str(key)[:80]] = _strip_secrets(item, depth + 1)
        return out
    if isinstance(value, list):
        return [_strip_secrets(item, depth + 1) for item in value[:40]]
    if isinstance(value, str):
        return value[:500]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:200]


def _host_only(url: str) -> str:
    text = str(url or "")
    if "?" in text:
        text = text.split("?", 1)[0]
    # scheme://host[:port]/path becomes host
    stripped = text.split("://", 1)[-1]
    return stripped.split("/", 1)[0][:200]


def _decision_request(request: Mapping[str, Any], method: str,
                      body: Mapping[str, Any]) -> Dict[str, Any]:
    gateway_id = str(request.get("gateway_id") or "gateway")[:80]
    sandbox_id = str(
        request.get("sandbox_id")
        or body.get("sandbox_id")
        or body.get("sandbox")
        or body.get("name")
        or ""
    ).strip()
    target_id = sandbox_id or "pending"
    action = ("openshell_provider_attach" if method in PROVIDER_METHODS
              else "openshell_policy_change")
    spec = body.get("spec")
    diff = _strip_secrets({
        "method": method,
        "sandbox_id": sandbox_id,
        "policy": spec.get("policy") if isinstance(spec, dict) else body.get("policy"),
        "merge_operations": body.get("merge_operations") or body.get("mergeOperations"),
        "prover": request.get("prover") or body.get("prover"),
    })
    return {
        "agent_did": str(request.get("agent_did") or f"openshell:{gateway_id}")[:160],
        "action": action,
        "target": f"openshell:{gateway_id}:{target_id}"[:300],
        "surface": "openshell",
        "payload_kind": "external_content",
        "payload": json.dumps(diff, sort_keys=True, default=str)[:200000],
        "request_id": _request_id(request.get("request_id") or body.get("request_id")),
    }


def _deny(reason: str, *, status_code: int = 403) -> Dict[str, Any]:
    return {
        "allowed": False,
        "reason": reason,
        "status_code": status_code,
        "patches": [],
        "log_annotations": {},
    }


def _allow(reason: str, *, patches: Optional[List[Dict[str, Any]]] = None,
           annotations: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    return {
        "allowed": True,
        "reason": reason,
        "status_code": 200,
        "patches": patches or [],
        "log_annotations": annotations or {},
    }


def _create_patches(body: Mapping[str, Any],
                    base_policy: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """RFC 6902 patches that give a new sandbox the compiled base policy.

    *base_policy* is already compiled: the ``SandboxPolicy`` in the gateway's
    protobuf-JSON shape. The engine compiles and proves it; the sidecar only
    applies it.
    """
    spec = body.get("spec")
    if isinstance(spec, dict) and spec.get("policy"):
        return []
    if isinstance(spec, dict):
        return [{"op": "add", "path": "/spec/policy", "value": dict(base_policy)}]
    return [{"op": "add", "path": "/spec", "value": {"policy": dict(base_policy)}}]


def evaluate(request: Mapping[str, Any], *, decide: DecideFn,
             base_policy: Optional[Mapping[str, Any]] = None,
             fetch_policy: Optional[FetchFn] = None) -> Dict[str, Any]:
    """Fail-closed interceptor decision. Only ``outcome=allow`` proceeds.

    *request* is ``{method, phase, body, gateway_id, agent_did, sandbox_id,
    request_id, decision_id, prover}``; ``body`` is the operation (or, for
    ``post_commit``, the committed response). ``post_commit`` always allows
    and does not call ``decide``. ``review``, ``deny``, HTTP 503, and a decide
    failure are interceptor denies. The leaf, when there is one, is sealed by
    ``decide`` before this returns.
    """
    method = method_name(str(request.get("method") or ""))
    phase = str(request.get("phase") or PHASE_VALIDATE)
    body = request.get("body") if isinstance(request.get("body"), dict) else {}

    if phase == PHASE_POST:
        if method not in BOUND_POST:
            return _allow("post_commit is not bound for this method")
        annotations: Dict[str, str] = {}
        policy_hash = str(body.get("policy_hash") or body.get("policyHash") or "")
        decision_id = str(request.get("decision_id") or "")
        if policy_hash:
            annotations["policy_hash"] = policy_hash[:128]
        if decision_id:
            annotations["decision_id"] = decision_id[:64]
        return _allow("post_commit is not authoritative", annotations=annotations)

    if phase == PHASE_MODIFY:
        if method not in BOUND_MODIFY or not base_policy:
            return _allow("no compiled base to apply")
        spec = body.get("spec") if isinstance(body.get("spec"), dict) else {}
        if spec.get("policy"):
            return _allow("request already carries a policy")
        return _allow("applied compiled base policy",
                      patches=_create_patches(body, base_policy))

    if method not in BOUND_VALIDATE:
        return _deny(f"{method or 'unknown'} is not an interceptable binding")

    if method == "UpdateConfig" and (body.get("global") is True or body.get("global_") is True):
        return _deny("a gateway global policy replaces every sandbox policy")

    sandbox_id = str(
        request.get("sandbox_id") or body.get("sandbox_id") or body.get("sandbox") or ""
    ).strip()
    if fetch_policy is not None and sandbox_id and method == "UpdateConfig":
        try:
            fetched = fetch_policy(sandbox_id)
        except Exception as exc:  # noqa: BLE001 - fetch failure is a closed gate
            logger.warning("openshell effective-policy fetch failed: %s", type(exc).__name__)
            return _deny("effective policy fetch failed", status_code=503)
        if not isinstance(fetched, dict):
            return _deny("effective policy fetch failed", status_code=503)

    try:
        decision = dict(decide(_decision_request(request, method, body)))
    except Exception as exc:  # noqa: BLE001 - the gateway must not commit on a transport failure
        logger.warning("openshell decision call failed: %s", type(exc).__name__)
        return _deny("decision unavailable", status_code=503)

    status = int(decision.get("status_code") or decision.get("status") or 200)
    outcome = str(decision.get("outcome") or "")
    if status == 503 or outcome != "allow":
        reason = "decision review" if outcome == "review" else (
            "decision unavailable" if status == 503 or not outcome else "decision deny")
        code = 503 if status == 503 else 403
        return _deny(reason, status_code=code)
    annotations = {}
    if decision.get("decision_id"):
        annotations["decision_id"] = str(decision["decision_id"])[:64]
    return _allow("decision allow", annotations=annotations)


def join_target(sandbox_id: str, policy_hash: str) -> str:
    return f"openshell:{sandbox_id}:{policy_hash}"[:300]


def _class_name(event: Mapping[str, Any]) -> str:
    name = str(event.get("class") or event.get("class_name") or "").upper()
    if name:
        return name
    try:
        uid = int(event.get("class_uid") or 0)
    except (TypeError, ValueError):
        uid = 0
    return _CLASS_BY_UID.get(uid, "")


def classify_ocsf(event: Mapping[str, Any]) -> Dict[str, Any]:
    """Seal FINDING and CONFIG policy events. Leave packet allows in OpenShell's log.

    An event that already carries ``decision_id`` is correlation only: the
    pre-commit leaf is the authority, and this does not ask for a second one.
    """
    klass = _class_name(event)
    activity = str(event.get("activity") or "").upper()
    sandbox_id = str(event.get("sandbox_id") or "")
    policy_hash = str(event.get("policy_hash") or "")
    target = join_target(sandbox_id, policy_hash)
    if event.get("decision_id") and klass in SEAL_CLASSES:
        return {
            "disposition": "correlate",
            "decision_id": str(event["decision_id"])[:64],
            "target": target,
        }
    if klass in ("NET", "HTTP") and activity in ("DENIED", "DENY"):
        return {
            "disposition": "summarize",
            "summary": {
                "host": _host_only(str(event.get("host") or event.get("url") or "")),
                "binary": str(event.get("binary") or "")[:200],
                "reason": str(event.get("reason") or "")[:200],
                "count": 1,
            },
        }
    if klass in ("NET", "HTTP"):
        return {"disposition": "ignore"}
    if klass in SEAL_CLASSES and activity in SEAL_ACTIVITIES:
        return {
            "disposition": "seal",
            "decision": {
                "action": "openshell_ocsf",
                "target": target,
                "surface": "openshell",
                "payload_kind": "external_content",
                "payload": json.dumps({
                    "class": klass,
                    "activity": activity,
                    "sandbox_id": sandbox_id[:80],
                    "policy_hash": policy_hash[:128],
                }, sort_keys=True),
            },
        }
    return {"disposition": "ignore"}
