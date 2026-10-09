"""What the ArtzAIn sidecar decides for an OpenShell gateway, and how.

The gateway calls its interceptors in three phases: ``modify_operation`` and
``validate`` before a write commits, ``post_commit`` after it. This module is
the sidecar's answer to each call. The Decision API call is the ``decide``
function passed in, and nothing here opens a socket or logs a policy body or
a token. The only state is an :class:`OperationLedger`, in memory.

* One decision per operation. ``CreateSandbox`` and ``UpdateConfig`` are
  decided in ``modify_operation``, because that is the only phase that can
  change the write: on an allow it stamps the decision id onto the write as
  the annotation ``artzain.cognexuslabs.ai/decision-id``. ``validate`` then
  confirms that decision from the ledger without asking again. When it
  cannot confirm (another operation, an unknown or expired id, no ledger),
  it decides again: nothing is allowed without a decision. Every other bound
  method is decided in ``validate``.
* Every operator write the gateway can intercept is decided, each as what it
  is: its ``action`` names the kind of write, and its ``target`` names the
  sandbox, the provider, the provider profile or the gateway it is about.
  The payload carries names and ids; for a provider write, nothing else.
  ``SubmitPolicyAnalysis`` is the exception: a sandbox's own supervisor
  calls it every few seconds, so it is left unbound (``UNBOUND_CALLBACKS``).
* Only an ``allow`` from the Decision API proceeds. ``review``, ``deny``, a
  503 and a failed call are all denies. A refusal the engine sealed names
  its decision id in the reason, which the operator reads in a terminal. A
  method outside the bound set is denied without a decision. A 429 (the
  engine's rate limit) is a deny whose reason says so and how long to wait.
* The stamp goes on a sandbox-scoped write only. The gateway rejects
  annotations on a gateway-global ``UpdateConfig``, so a global setting
  write is decided in ``validate``.
* ``modify_operation`` on ``CreateSandbox`` also adds the compiled base
  policy when the request carries none. It never replaces an operator's
  policy. When the sidecar is meant to have a base policy and has none
  (``base_required``), a create that carries no policy is refused without
  a decision: it would start a sandbox on whatever its image holds.
* ``post_commit`` always allows and never decides: it cannot revoke a commit.
  It reads the stamp back from the committed write, which is what ties the
  committed policy hash to its decision.
* An ``UpdateConfig`` with ``global: true`` and a policy is denied without a
  decision: a gateway-global policy replaces every sandbox policy. One that
  writes a setting and no policy is decided as ``openshell_setting_change``.
* A sandbox is named by its uuid. The gateway's update and delete calls
  carry the sandbox's name and workspace, so the ledger remembers the uuid a
  create returned. A name it cannot resolve is decided as
  ``name:<workspace>/<name>``. An allowed delete forgets the name.

Pinned to OpenShell v0.1.2.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import re
import threading
import time
from collections import OrderedDict
from typing import Any, Callable, Dict, List, Mapping, NamedTuple, Optional, Protocol, Tuple

logger = logging.getLogger("artzain.openshell")

PINNED_OPENSHELL = "v0.1.2"

#: Interceptor phases. ``post_commit`` cannot fail closed.
PHASE_MODIFY = "modify_operation"
PHASE_VALIDATE = "validate"
PHASE_POST = "post_commit"

#: What a decision calls each kind of write (its ``action``).
ACTION_POLICY = "openshell_policy_change"
ACTION_SETTING = "openshell_setting_change"
ACTION_PROVIDER_ATTACH = "openshell_provider_attach"
ACTION_PROVIDER = "openshell_provider_change"
ACTION_SANDBOX_DELETE = "openshell_sandbox_delete"
ACTION_SERVICE = "openshell_service_change"
ACTION_SSH = "openshell_ssh_session"

#: Each method the sidecar decides, and its action. An ``UpdateConfig`` that
#: writes a setting and no policy is ``openshell_setting_change`` instead
#: (:func:`action_for`).
_ACTIONS: Dict[str, str] = {
    "CreateSandbox": ACTION_POLICY,
    "UpdateConfig": ACTION_POLICY,
    "ApproveDraftChunk": ACTION_POLICY,
    "RejectDraftChunk": ACTION_POLICY,
    "ApproveAllDraftChunks": ACTION_POLICY,
    "EditDraftChunk": ACTION_POLICY,
    "UndoDraftChunk": ACTION_POLICY,
    "ClearDraftChunks": ACTION_POLICY,
    "AttachSandboxProvider": ACTION_PROVIDER_ATTACH,
    "DetachSandboxProvider": ACTION_PROVIDER_ATTACH,
    "DeleteSandbox": ACTION_SANDBOX_DELETE,
    "ExposeService": ACTION_SERVICE,
    "DeleteService": ACTION_SERVICE,
    "CreateSshSession": ACTION_SSH,
    "RevokeSshSession": ACTION_SSH,
    "CreateProvider": ACTION_PROVIDER,
    "UpdateProvider": ACTION_PROVIDER,
    "ConfigureProviderRefresh": ACTION_PROVIDER,
    "RotateProviderCredential": ACTION_PROVIDER,
    "DeleteProviderRefresh": ACTION_PROVIDER,
    "DeleteProvider": ACTION_PROVIDER,
    "ImportProviderProfiles": ACTION_PROVIDER,
    "UpdateProviderProfiles": ACTION_PROVIDER,
    "DeleteProviderProfile": ACTION_PROVIDER,
}

#: The methods and phases the sidecar decides. The gateway registration binds
#: exactly these; any other bound method would be denied outright.
BOUND_VALIDATE = frozenset(_ACTIONS)
#: Decided in ``modify_operation``, where the decision id can be stamped.
BOUND_MODIFY = frozenset({"CreateSandbox", "UpdateConfig"})
BOUND_POST = frozenset({"CreateSandbox", "UpdateConfig"})
PROVIDER_METHODS = frozenset({"AttachSandboxProvider", "DetachSandboxProvider"})
#: Interceptable on v0.1.2 and left unbound on purpose. A sandbox's own
#: supervisor calls it on two ten-second timers (denial summaries and activity
#: counters), so deciding it would seal a leaf every few seconds per sandbox.
#: It changes no policy: a proposal it files still needs an approval, and
#: every approval is decided.
UNBOUND_CALLBACKS = frozenset({"SubmitPolicyAnalysis"})

#: Writes that name a provider, a provider profile, or nothing but the gateway.
_PROVIDER_WRITES = frozenset({
    "CreateProvider", "UpdateProvider", "ConfigureProviderRefresh",
    "RotateProviderCredential", "DeleteProviderRefresh", "DeleteProvider",
})
_PROFILE_WRITES = frozenset({
    "ImportProviderProfiles", "UpdateProviderProfiles", "DeleteProviderProfile",
})
_DRAFT_METHODS = frozenset({
    "ApproveDraftChunk", "RejectDraftChunk", "ApproveAllDraftChunks",
    "EditDraftChunk", "UndoDraftChunk", "ClearDraftChunks",
})
#: Writes whose ``name`` is something inside the sandbox, not the sandbox.
_SERVICE_METHODS = frozenset({"ExposeService", "DeleteService"})

#: The annotation that carries a decision id on a governed write.
STAMP_KEY = "artzain.cognexuslabs.ai/decision-id"
#: The gateway's own default workspace, used when a request names none.
DEFAULT_WORKSPACE = "default"

SEAL_CLASSES = frozenset({"FINDING", "CONFIG"})
SEAL_ACTIVITIES = frozenset({"PROPOSED", "APPROVED", "REJECTED", "LOADED"})
_CLASS_BY_UID = {4001: "NET", 4002: "HTTP", 2004: "FINDING", 5019: "CONFIG"}

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
#: A decision id is quoted to the operator and stamped onto the write.
_DECISION_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_INTEGER_RE = re.compile(r"^-?[0-9]{1,19}$")
_SECRET_KEY = re.compile(r"(secret|token|credential|password|authorization)", re.I)

DecideFn = Callable[[Mapping[str, Any]], Mapping[str, Any]]
FetchFn = Callable[[str], Any]

#: Put on a decision answer by the sidecar's own client, and by nothing else,
#: when the engine gave no answer or a 5xx (:func:`mark_engine_down`). It is
#: an object, so no JSON the engine sends can carry it: no answer can make a
#: write count as break-glass.
_ENGINE_DOWN = object()
_ENGINE_DOWN_KEY = "__engine_down__"
#: The refusal of a write ArtzAIn could not decide.
_UNAVAILABLE = "decision unavailable"


def mark_engine_down(answer: Dict[str, Any]) -> Dict[str, Any]:
    """Mark *answer* as the engine's absence: no answer, or a 5xx."""
    answer[_ENGINE_DOWN_KEY] = _ENGINE_DOWN
    return answer


def engine_down(answer: Any) -> bool:
    """Whether *answer* is marked as the engine's absence."""
    return isinstance(answer, Mapping) and answer.get(_ENGINE_DOWN_KEY) is _ENGINE_DOWN


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


# ---------------------------------------------------------------------------
# The ledger: what was decided, and which sandbox a name is
# ---------------------------------------------------------------------------


class OperationLedger:
    """In-memory record of this sidecar's recent allows and known sandboxes.

    * A decision made in ``modify_operation`` is remembered by its id for
      *ttl_seconds*, with the method, a digest of the operation as decided,
      and the sandbox it named. ``validate`` confirms against it, and
      ``post_commit`` finds the sandbox there.
    * A sandbox's uuid is remembered by workspace and name, from the create
      that returned it.

    * A write ArtzAIn sent to review is remembered by what the engine checks
      (agent, action, target and payload) for *review_ttl_seconds*, with the
      review's decision id, so the same write run again cites it
      (``context.cites_review``) and an approved review releases it.

    The maps are bounded: the oldest entry goes first. A restart empties
    them, which costs a second decision in ``validate``, an unresolved name
    or a second review, never an allow.
    """

    def __init__(self, *, ttl_seconds: float = 300.0, max_decisions: int = 4096,
                 max_sandboxes: int = 20000, review_ttl_seconds: float = 86400.0,
                 max_reviews: int = 1024,
                 now: Callable[[], float] = time.monotonic) -> None:
        self._ttl = ttl_seconds
        self._max_decisions = max_decisions
        self._max_sandboxes = max_sandboxes
        self._review_ttl = review_ttl_seconds
        self._max_reviews = max_reviews
        self._now = now
        self._lock = threading.Lock()
        self._decisions: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        self._sandboxes: "OrderedDict[Tuple[str, str], str]" = OrderedDict()
        self._reviews: "OrderedDict[str, Tuple[str, float]]" = OrderedDict()

    def remember_review(self, key: str, decision_id: str) -> None:
        """The review ArtzAIn opened for the write *key* names."""
        if not key or not decision_id:
            return
        with self._lock:
            self._reviews[key] = (decision_id, self._now() + self._review_ttl)
            self._reviews.move_to_end(key)
            while len(self._reviews) > self._max_reviews:
                self._reviews.popitem(last=False)

    def cited_review(self, key: str) -> str:
        """The review to cite for the write *key* names, unless it has expired."""
        with self._lock:
            entry = self._reviews.get(key)
            if entry is None:
                return ""
            if entry[1] < self._now():
                del self._reviews[key]
                return ""
            return entry[0]

    def forget_review(self, key: str) -> None:
        """Drop a review once it released its write: one approval, one retry."""
        with self._lock:
            self._reviews.pop(key, None)

    def remember(self, decision_id: str, *, method: str, digest: str,
                 sandbox_id: str = "", base_applied: bool = False) -> None:
        if not decision_id:
            return
        with self._lock:
            self._decisions[decision_id] = {
                "method": method,
                "digest": digest,
                "sandbox_id": sandbox_id,
                "base_applied": base_applied,
                "expires": self._now() + self._ttl,
            }
            self._decisions.move_to_end(decision_id)
            while len(self._decisions) > self._max_decisions:
                self._decisions.popitem(last=False)

    def decided(self, decision_id: str) -> Optional[Dict[str, Any]]:
        """The remembered allow for *decision_id*, unless it has expired."""
        with self._lock:
            entry = self._decisions.get(str(decision_id or ""))
            if entry is None:
                return None
            if entry["expires"] < self._now():
                del self._decisions[str(decision_id)]
                return None
            return dict(entry)

    def learn_sandbox(self, workspace: str, name: str, sandbox_id: str) -> None:
        if not name or not sandbox_id:
            return
        key = (workspace or DEFAULT_WORKSPACE, name)
        with self._lock:
            self._sandboxes[key] = sandbox_id
            self._sandboxes.move_to_end(key)
            while len(self._sandboxes) > self._max_sandboxes:
                self._sandboxes.popitem(last=False)

    def sandbox_id(self, workspace: str, name: str) -> str:
        with self._lock:
            return self._sandboxes.get((workspace or DEFAULT_WORKSPACE, name), "")

    def forget_sandbox(self, workspace: str, name: str) -> None:
        """Drop a name whose sandbox is being deleted.

        A later sandbox under the same name is another sandbox. Until its own
        create is seen it is decided by name, never as the old uuid.
        """
        with self._lock:
            self._sandboxes.pop((workspace or DEFAULT_WORKSPACE, name), None)


# ---------------------------------------------------------------------------
# What an operation is about: its action, its target and its facts
# ---------------------------------------------------------------------------


def _field(body: Mapping[str, Any], name: str) -> Any:
    """A request field by its proto name, in either spelling.

    The gateway sends protobuf-JSON (``allowMissing``); a caller of the HTTP
    route may send the proto's own names (``allow_missing``).
    """
    value = body.get(name)
    if value is None:
        head, *rest = name.split("_")
        value = body.get(head + "".join(part.capitalize() for part in rest))
    return value


def _text(value: Any, limit: int = 200) -> str:
    return value.strip()[:limit] if isinstance(value, str) else ""


def _whole(value: Any) -> Any:
    """A protobuf-JSON number as the integer it is (``8080.0``, ``"42"``)."""
    if isinstance(value, bool):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and _INTEGER_RE.match(value):
        return int(value)
    return value


def _workspace(body: Mapping[str, Any]) -> str:
    scope = _field(body, "workspace_scope")
    name = scope.get("workspace") if isinstance(scope, dict) else ""
    return str(name or DEFAULT_WORKSPACE)


def _is_global(body: Mapping[str, Any]) -> bool:
    return body.get("global") is True or body.get("global_") is True


def _setting_key(body: Mapping[str, Any]) -> str:
    return _text(_field(body, "setting_key"), 120)


def _carries_policy(body: Mapping[str, Any]) -> bool:
    return body.get("policy") is not None or bool(_field(body, "merge_operations"))


def is_setting_write(body: Mapping[str, Any]) -> bool:
    """An ``UpdateConfig`` that writes a setting and no policy."""
    return bool(_setting_key(body)) and not _carries_policy(body)


def action_for(method: str, body: Mapping[str, Any]) -> str:
    """The decision's ``action`` for a bound method."""
    if method == "UpdateConfig" and is_setting_write(body):
        return ACTION_SETTING
    return _ACTIONS.get(method, ACTION_POLICY)


def _setting_facts(body: Mapping[str, Any]) -> Dict[str, Any]:
    """The setting a write names, with its value as a plain value.

    A ``SettingValue`` is a one-of; a bytes value is named and not sent.
    """
    key = _setting_key(body)
    if not key:
        return {}
    facts: Dict[str, Any] = {"setting_key": key}
    if _field(body, "delete_setting") is True:
        facts["delete_setting"] = True
        return facts
    raw = _field(body, "setting_value")
    if isinstance(raw, dict):
        for kind in ("string_value", "bool_value", "int_value"):
            value = _field(raw, kind)
            if value is not None:
                facts["setting_value"] = _whole(value) if kind == "int_value" else value
                return facts
        if _field(raw, "bytes_value") is not None:
            facts["setting_value_kind"] = "bytes"
    elif isinstance(raw, (str, bool, int)):
        facts["setting_value"] = raw
    return facts


def _sandbox(request: Mapping[str, Any], method: str, body: Mapping[str, Any],
             ledger: Optional[OperationLedger]) -> Tuple[str, str, str, str]:
    """``(target segment, uuid, name, workspace)`` for the sandbox an operation names.

    The uuid is the one a create returned. A name the ledger cannot resolve is
    ``name:<workspace>/<name>``; an operation that names nothing is ``pending``.
    """
    workspace = _workspace(body)
    explicit = str(request.get("sandbox_id") or body.get("sandbox_id") or "").strip()
    named = body.get("sandbox")
    if not named and method not in _SERVICE_METHODS:
        named = body.get("name")
    name = str(named or "").strip()
    if explicit:
        return explicit, explicit, name, workspace
    if not name:
        return "pending", "", "", workspace
    known = ""
    if ledger is not None and method != "CreateSandbox":
        known = ledger.sandbox_id(workspace, name)
    if known:
        return known, known, name, workspace
    return f"name:{workspace}/{name}", "", name, workspace


def _provider_name(method: str, body: Mapping[str, Any]) -> Tuple[str, str]:
    """``(name, profile type)`` of the provider a provider write names."""
    provider = body.get("provider")
    if isinstance(provider, dict):
        metadata = provider.get("metadata")
        name = metadata.get("name") if isinstance(metadata, dict) else ""
        return _text(name), _text(provider.get("type"))
    if method == "DeleteProvider":
        return _text(body.get("name")), ""
    return _text(provider), ""


def _profile_ids(method: str, body: Mapping[str, Any]) -> List[str]:
    """The ids of the provider profiles a profile write names."""
    if method == "ImportProviderProfiles":
        items = body.get("profiles")
        items = items if isinstance(items, list) else []
    else:
        items = [body.get("profile")]
    ids = [_text(body.get("id"))] if method != "ImportProviderProfiles" else []
    for item in items:
        profile = item.get("profile") if isinstance(item, dict) else None
        ids.append(_text(profile.get("id")) if isinstance(profile, dict) else "")
    seen: List[str] = []
    for value in ids:
        if value and value not in seen:
            seen.append(value)
    return seen


def _sandbox_facts(request: Mapping[str, Any], method: str,
                   body: Mapping[str, Any]) -> Dict[str, Any]:
    """What a sandbox-scoped write says besides which sandbox it is."""
    facts: Dict[str, Any] = {}
    if method in ("CreateSandbox", "UpdateConfig"):
        if not (method == "UpdateConfig" and is_setting_write(body)):
            spec = body.get("spec")
            facts["policy"] = spec.get("policy") if isinstance(spec, dict) else body.get("policy")
            facts["merge_operations"] = _field(body, "merge_operations")
            facts["prover"] = request.get("prover") or body.get("prover")
        if method == "UpdateConfig":
            facts.update(_setting_facts(body))
        return facts
    if method in _DRAFT_METHODS:
        chunk = _text(_field(body, "chunk_id"))
        if chunk:
            facts["chunk_id"] = chunk
        if method == "RejectDraftChunk" and _text(body.get("reason"), 500):
            facts["reason"] = _text(body.get("reason"), 500)
        if method == "EditDraftChunk" and isinstance(_field(body, "proposed_rule"), dict):
            facts["proposed_rule"] = _field(body, "proposed_rule")
        if method == "ApproveAllDraftChunks":
            approvals = body.get("approvals")
            chunks = [_text(_field(item, "chunk_id")) for item in approvals
                      if isinstance(item, dict)] if isinstance(approvals, list) else []
            if chunks:
                facts["chunk_ids"] = [chunk for chunk in chunks if chunk]
            if _field(body, "include_security_flagged") is True:
                facts["include_security_flagged"] = True
        return facts
    if method in PROVIDER_METHODS:
        facts["provider"] = _text(body.get("provider"))
    if method in _SERVICE_METHODS:
        facts["service"] = _text(body.get("name"))
        if method == "ExposeService":
            facts["target_port"] = _whole(_field(body, "target_port"))
            if body.get("domain") is True:
                facts["domain"] = True
    return facts


def _subject(request: Mapping[str, Any], method: str, body: Mapping[str, Any],
             ledger: Optional[OperationLedger]) -> Tuple[str, Dict[str, Any]]:
    """``(target segment, facts)``: what a write is about, and what it says.

    The facts are names and ids. A provider write carries nothing else: no
    configuration, no credential key, no refresh material.
    """
    workspace = _workspace(body)
    if method in _PROVIDER_WRITES:
        name, kind = _provider_name(method, body)
        facts: Dict[str, Any] = {"workspace": workspace, "provider": name}
        if kind:
            facts["provider_type"] = kind
        target = f"provider:{workspace}/{name}"
    elif method in _PROFILE_WRITES:
        ids = _profile_ids(method, body)
        facts = {"workspace": workspace, "profiles": ids}
        target = (f"provider-profiles:{workspace}" if method == "ImportProviderProfiles"
                  else f"provider-profile:{workspace}/{ids[0] if ids else ''}")
    elif method == "RevokeSshSession":
        # The request holds a session token and nothing else. The gateway
        # leaves the token out before it calls, so no sandbox is named.
        target, facts = "ssh-session", {}
    elif method == "UpdateConfig" and _is_global(body):
        target, facts = "gateway", {"global": True, **_setting_facts(body)}
    else:
        target, sandbox_id, name, workspace = _sandbox(request, method, body, ledger)
        facts = {"sandbox_id": sandbox_id, "sandbox_name": name, "workspace": workspace,
                 **_sandbox_facts(request, method, body)}
    if _field(body, "allow_missing") is True:
        facts["allow_missing"] = True
    return target, facts


def _decision_request(request: Mapping[str, Any], method: str, body: Mapping[str, Any],
                      ledger: Optional[OperationLedger] = None) -> Dict[str, Any]:
    gateway_id = str(request.get("gateway_id") or "gateway")[:80]
    target, facts = _subject(request, method, body, ledger)
    diff = _strip_secrets({"method": method, **facts})
    return {
        "agent_did": str(request.get("agent_did") or f"openshell:{gateway_id}")[:160],
        "action": action_for(method, body),
        "target": f"openshell:{gateway_id}:{target}"[:300],
        "surface": "openshell",
        "payload_kind": "external_content",
        "payload": json.dumps(diff, sort_keys=True, default=str)[:200000],
        "request_id": _request_id(request.get("request_id") or body.get("request_id")),
    }


def _deny(reason: str, *, status_code: int = 403,
          annotations: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    return {
        "allowed": False,
        "reason": reason,
        "status_code": status_code,
        "patches": [],
        "log_annotations": annotations or {},
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


# ---------------------------------------------------------------------------
# Patches: the base policy and the decision stamp
# ---------------------------------------------------------------------------


def _create_patches(body: Mapping[str, Any],
                    base_policy: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """RFC 6902 patches that give a new sandbox the compiled base policy.

    *base_policy* is already compiled: the ``SandboxPolicy`` in the gateway's
    protobuf-JSON shape. The engine compiles and proves it; the sidecar only
    applies it.
    """
    spec = body.get("spec")
    if _create_carries_policy(body):
        return []
    if isinstance(spec, dict):
        return [{"op": "add", "path": "/spec/policy", "value": dict(base_policy)}]
    return [{"op": "add", "path": "/spec", "value": {"policy": dict(base_policy)}}]


def _create_carries_policy(body: Mapping[str, Any]) -> bool:
    """Whether a ``CreateSandbox`` brings a policy of its own."""
    spec = body.get("spec")
    return isinstance(spec, dict) and bool(spec.get("policy"))


def _base_missing(method: str, body: Mapping[str, Any],
                  base_policy: Optional[Mapping[str, Any]], base_required: bool) -> bool:
    """A create that needs the base policy when the sidecar has none."""
    return (base_required and not base_policy and method == "CreateSandbox"
            and not _create_carries_policy(body))


def stampable(method: str, body: Mapping[str, Any]) -> bool:
    """Whether the gateway accepts our annotation on this write.

    It does on a create and on a sandbox-scoped update. On a gateway-global
    update it rejects the whole write.
    """
    if method == "CreateSandbox":
        return True
    return method == "UpdateConfig" and not _is_global(body)


def _pointer(key: str) -> str:
    return key.replace("~", "~0").replace("/", "~1")


def _stamp_patch(body: Mapping[str, Any], decision_id: str) -> Dict[str, Any]:
    """``add`` replaces a value already under our key, so a caller cannot keep its own."""
    if isinstance(body.get("annotations"), dict):
        return {"op": "add", "path": f"/annotations/{_pointer(STAMP_KEY)}", "value": decision_id}
    return {"op": "add", "path": "/annotations", "value": {STAMP_KEY: decision_id}}


def stamped_decision_id(annotations: Any) -> str:
    """The decision id under our annotation key, or empty."""
    if not isinstance(annotations, dict):
        return ""
    return str(annotations.get(STAMP_KEY) or "").strip()


def _operation_digest(body: Mapping[str, Any], *, base_applied: bool = False) -> str:
    """A digest of the operation as the caller sent it.

    Our own additions are left out, so ``modify_operation`` (before them) and
    ``validate`` (after them) agree on an operation nothing else changed: the
    stamp, and the base policy when this sidecar added it.
    """
    view = copy.deepcopy(dict(body))
    annotations = view.get("annotations")
    if isinstance(annotations, dict):
        annotations.pop(STAMP_KEY, None)
        if not annotations:
            view.pop("annotations")
    if base_applied:
        spec = view.get("spec")
        if isinstance(spec, dict):
            spec.pop("policy", None)
            if not spec:
                view.pop("spec")
    text = json.dumps(view, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# The decision
# ---------------------------------------------------------------------------


def _refused_locally(method: str, body: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    """The one write the sidecar refuses without asking: a gateway-global policy.

    A gateway-global ``UpdateConfig`` that writes a setting and no policy is
    decided like any other write.
    """
    if method != "UpdateConfig" or not _is_global(body) or is_setting_write(body):
        return None
    if _carries_policy(body):
        return _deny("a gateway global policy replaces every sandbox policy")
    return _deny("a gateway global update that names no setting is refused")


def _decision_id(raw: Any) -> str:
    """A decision id fit to quote and to stamp, or empty."""
    text = str(raw or "").strip()
    return text if _DECISION_ID_RE.match(text) else ""


class _Decided(NamedTuple):
    #: The refusal, or None for an allow.
    denied: Optional[Dict[str, Any]]
    #: The engine's decision id, when it gave one.
    decision_id: str
    #: The engine gave no answer, or a 5xx (:func:`engine_down`).
    engine_down: bool
    #: What the engine was asked, when it was asked.
    asked: Optional[Dict[str, Any]]


def _decide(request: Mapping[str, Any], method: str, body: Mapping[str, Any], *,
            decide: DecideFn, fetch_policy: Optional[FetchFn],
            ledger: Optional[OperationLedger]) -> _Decided:
    """The engine's decision on one bound operation.

    A refusal the engine sealed names its decision, so the operator who reads
    it in a terminal can find the receipt.
    """
    sandbox_id = str(
        request.get("sandbox_id") or body.get("sandbox_id") or body.get("sandbox") or ""
    ).strip()
    if fetch_policy is not None and sandbox_id and method == "UpdateConfig":
        try:
            fetched = fetch_policy(sandbox_id)
        except Exception as exc:  # noqa: BLE001 - fetch failure is a closed gate
            logger.warning("openshell effective-policy fetch failed: %s", type(exc).__name__)
            return _Decided(_deny("effective policy fetch failed", status_code=503), "", False, None)
        if not isinstance(fetched, dict):
            return _Decided(_deny("effective policy fetch failed", status_code=503), "", False, None)

    asked = _decision_request(request, method, body, ledger)
    # A write ArtzAIn sent to review cites that review when it runs again: an
    # approved review releases it, a pending or denied one refuses it.
    review_key = _review_key(asked) if ledger is not None else ""
    cited = ledger.cited_review(review_key) if ledger is not None else ""
    if cited:
        asked["context"] = {"cites_review": cited}
    try:
        decision = dict(decide(asked))
    except Exception as exc:  # noqa: BLE001 - the gateway must not commit on a transport failure
        logger.warning("openshell decision call failed: %s", type(exc).__name__)
        return _Decided(_deny(_UNAVAILABLE, status_code=503), "", False, asked)

    status = int(decision.get("status_code") or decision.get("status") or 200)
    outcome = str(decision.get("outcome") or "")
    decision_id = _decision_id(decision.get("decision_id"))
    if status == 429:
        return _Decided(_deny(_rate_limit_reason(decision), status_code=429), "", False, asked)
    if status == 503 or not outcome:
        return _Decided(_deny(_UNAVAILABLE, status_code=503 if status == 503 else 403), "",
                        engine_down(decision), asked)
    if outcome != "allow":
        reason = "decision review" if outcome == "review" else "decision deny"
        if outcome == "review" and decision_id and ledger is not None:
            ledger.remember_review(review_key, decision_id)
        if not decision_id:
            return _Decided(_deny(reason), "", False, asked)
        said = f"{reason} ({decision_id})"
        if cited and outcome != "review":
            said += f"; review {cited} has not released this write"
        return _Decided(_deny(said, annotations={"decision_id": decision_id}), "", False, asked)
    if cited:
        ledger.forget_review(review_key)
    return _Decided(None, decision_id, False, asked)


# ---------------------------------------------------------------------------
# Break-glass: what ArtzAIn could not answer, when the host opened a window
# ---------------------------------------------------------------------------


class BreakGlassWindow(Protocol):
    """What :func:`evaluate` needs of :class:`artzain.openshell.breakglass.BreakGlass`."""

    def window(self) -> Optional[Dict[str, Any]]: ...

    def record_write(self, facts: Mapping[str, Any]) -> Optional[str]: ...


def _breakglass_covers(breakglass: Optional[BreakGlassWindow], method: str,
                       body: Mapping[str, Any]) -> bool:
    """Whether an open window may let this write through: a bound write that
    is not gateway-wide, with a window open now."""
    if breakglass is None or method not in BOUND_VALIDATE:
        return False
    if method == "UpdateConfig" and _is_global(body):
        return False
    return breakglass.window() is not None


def _breakglass_facts(request: Mapping[str, Any], method: str, body: Mapping[str, Any],
                      asked: Mapping[str, Any]) -> Dict[str, Any]:
    """The journal entry of a write allowed under break-glass: what ArtzAIn
    would have decided, and who asked. The caller's subject id, kind and
    provider, never a name (plan §9)."""
    principal = request.get("principal") if isinstance(request.get("principal"), Mapping) else {}
    who = {key: _text(principal.get(key)) for key in ("subject", "kind", "provider")
           if _text(principal.get(key))}
    return {
        "method": method,
        "action": asked["action"],
        "target": asked["target"],
        "payload_sha256": hashlib.sha256(str(asked["payload"]).encode("utf-8")).hexdigest(),
        "digest": _operation_digest(body),
        "principal": who,
        "request_id": asked["request_id"],
    }


def _review_key(asked: Mapping[str, Any]) -> str:
    """What a review is bound to, as the engine checks a citation: the agent,
    the action, the target and the payload (not the request id)."""
    bound = [asked.get("agent_did"), asked.get("action"), asked.get("target"),
             asked.get("payload")]
    return hashlib.sha256(json.dumps(bound, sort_keys=True).encode("utf-8")).hexdigest()


def _rate_limit_reason(decision: Mapping[str, Any]) -> str:
    """What the operator reads when the engine's rate limit refused the
    decision: the limit when it is known, and the seconds to wait."""
    def whole(name: str) -> int:
        value = decision.get(name)
        if isinstance(value, bool) or not isinstance(value, int):
            return 0
        return value if 0 < value < 10**9 else 0

    limit, wait = whole("limit_per_hour"), whole("retry_after")
    reason = "decision rate limit reached"
    if limit:
        reason += f" ({limit} per hour)"
    if wait:
        reason += f"; retry in {wait} s"
    return reason


def _confirmed(ledger: Optional[OperationLedger], method: str,
               body: Mapping[str, Any]) -> str:
    """The id of this operation's ``modify_operation`` allow, or empty."""
    if ledger is None:
        return ""
    decision_id = stamped_decision_id(body.get("annotations"))
    entry = ledger.decided(decision_id) if decision_id else None
    if not entry or entry["method"] != method:
        return ""
    if entry["digest"] != _operation_digest(body, base_applied=entry["base_applied"]):
        return ""
    return decision_id


def evaluate(request: Mapping[str, Any], *, decide: DecideFn,
             base_policy: Optional[Mapping[str, Any]] = None,
             fetch_policy: Optional[FetchFn] = None,
             ledger: Optional[OperationLedger] = None,
             base_required: bool = False,
             breakglass: Optional[BreakGlassWindow] = None) -> Dict[str, Any]:
    """Fail-closed interceptor decision. Only ``outcome=allow`` proceeds.

    *request* is ``{method, phase, body, gateway_id, agent_did, sandbox_id,
    request_id, decision_id, prover, principal}``; ``body`` is the operation
    (or, for ``post_commit``, the committed response). ``post_commit`` always
    allows and does not call ``decide``. ``review``, ``deny``, HTTP 503, HTTP
    429 and a decide failure are interceptor denies. The leaf, when there is
    one, is sealed by ``decide`` before this returns.

    With a *ledger*, a create or an update decided in ``modify_operation`` is
    confirmed in ``validate`` rather than decided twice.

    With *base_required* and no *base_policy*, a create that carries no
    policy is denied before any decision, in either pre-commit phase.

    With a *breakglass* window open, a write the engine could not answer
    (:func:`engine_down`) and that is not gateway-wide goes through: in
    ``validate``, only once its journal entry is in the file. It carries no
    decision stamp; its annotation ``break_glass`` names the window.
    """
    method = method_name(str(request.get("method") or ""))
    phase = str(request.get("phase") or PHASE_VALIDATE)
    body = request.get("body") if isinstance(request.get("body"), dict) else {}

    if phase == PHASE_POST:
        if method not in BOUND_POST:
            return _allow("post_commit is not bound for this method")
        annotations: Dict[str, str] = {}
        policy_hash = str(body.get("policy_hash") or body.get("policyHash") or "")
        decision_id = str(request.get("decision_id") or committed_decision_id(method, body))
        if policy_hash:
            annotations["policy_hash"] = policy_hash[:128]
        if decision_id:
            annotations["decision_id"] = decision_id[:64]
        return _allow("post_commit is not authoritative", annotations=annotations)

    if phase == PHASE_MODIFY:
        if method not in BOUND_MODIFY:
            return _allow("modify_operation is not bound for this method")
        refused = _refused_locally(method, body)
        if refused is not None:
            return refused
        if _base_missing(method, body, base_policy, base_required):
            return _deny("base policy unavailable", status_code=503)
        if not stampable(method, body):
            # A gateway-global setting write: the gateway takes no annotation
            # on it, so a decision here could not be confirmed in ``validate``
            # and the write would be decided twice.
            return _allow("decided in validate")
        decided = _decide(request, method, body, decide=decide,
                          fetch_policy=fetch_policy, ledger=ledger)
        denied, decision_id = decided.denied, decided.decision_id
        if denied is not None:
            if not (decided.engine_down and _breakglass_covers(breakglass, method, body)):
                return denied
            # Break-glass: the write goes on without a stamp, and ``validate``,
            # which always follows, journals it once.
        patches: List[Dict[str, Any]] = []
        base_applied = False
        if method == "CreateSandbox" and base_policy:
            base_patches = _create_patches(body, base_policy)
            base_applied = bool(base_patches)
            patches.extend(base_patches)
        if denied is not None:
            return _allow("break-glass: journaled in validate", patches=patches)
        if decision_id:
            patches.append(_stamp_patch(body, decision_id))
            if ledger is not None:
                _target, sandbox_id, _name, _ws = _sandbox(request, method, body, ledger)
                ledger.remember(decision_id, method=method,
                                digest=_operation_digest(body, base_applied=False),
                                sandbox_id=sandbox_id, base_applied=base_applied)
        notes = {"decision_id": decision_id} if decision_id else {}
        return _allow("decision allow", patches=patches, annotations=notes)

    if method not in BOUND_VALIDATE:
        return _deny(f"{method or 'unknown'} is not an interceptable binding")
    refused = _refused_locally(method, body)
    if refused is not None:
        return refused

    if method in BOUND_MODIFY and stampable(method, body):
        confirmed = _confirmed(ledger, method, body)
        if confirmed:
            return _allow("decided in modify_operation",
                          annotations={"decision_id": confirmed})

    if _base_missing(method, body, base_policy, base_required):
        return _deny("base policy unavailable", status_code=503)
    decided = _decide(request, method, body, decide=decide,
                      fetch_policy=fetch_policy, ledger=ledger)
    denied, decision_id = decided.denied, decided.decision_id
    window_id = ""
    if denied is not None:
        if not (decided.engine_down and decided.asked is not None
                and _breakglass_covers(breakglass, method, body)):
            return denied
        assert breakglass is not None
        window_id = breakglass.record_write(
            _breakglass_facts(request, method, body, decided.asked)) or ""
        if not window_id:
            return _deny(f"{_UNAVAILABLE}; break-glass write not journaled", status_code=503)
    if method == "DeleteSandbox" and ledger is not None:
        _target, _uuid, name, workspace = _sandbox(request, method, body, ledger)
        ledger.forget_sandbox(workspace, name)
    if window_id:
        logger.warning("break-glass write allowed: %s (window %s)", method, window_id)
        return _allow(f"break-glass write (window {window_id})",
                      annotations={"break_glass": window_id})
    return _allow("decision allow",
                  annotations={"decision_id": decision_id} if decision_id else {})


def committed_decision_id(method: str, committed: Mapping[str, Any]) -> str:
    """The decision id stamped on a committed write, read from its response.

    An update's response carries the sandbox's annotations; a create's
    carries the sandbox, with them under its metadata.
    """
    if method == "CreateSandbox":
        sandbox = committed.get("sandbox")
        metadata = sandbox.get("metadata") if isinstance(sandbox, dict) else None
        annotations = metadata.get("annotations") if isinstance(metadata, dict) else None
        return stamped_decision_id(annotations)
    return stamped_decision_id(committed.get("annotations"))


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
