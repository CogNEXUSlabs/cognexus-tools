"""Every operator write an OpenShell gateway can intercept gets a decision.

Until now the sidecar decided eight methods and refused the rest outright, so
a delete, a service exposure, an SSH session and every provider write
committed with no receipt (they could not be bound without refusing them all).
A gateway-global *setting* write was refused along with global policies, so
``proposal_approval_mode=manual`` could not be set on a bound gateway.

Each decision names what it is about:

* its **action** says the kind of write;
* its **target** is the sandbox, the provider, the provider profile or the
  gateway the write names, never a sandbox that happens to share a name;
* its **payload** carries names and ids, and for a provider write nothing
  else.

The request shapes are the ones in OpenShell v0.1.2's ``openshell.proto``, in
the protobuf-JSON form the gateway sends (lowerCamelCase, numbers as
doubles). The delete and the setting writes are the payloads recorded in the
wire spike.
"""

from __future__ import annotations

import copy
import json

import pytest

from artzain.openshell import interceptor as osi

SANDBOX_ID = "1e04e83f-6de7-4f86-b466-2e945af3e724"
DECISION = "01JABCDEFGHJKMNPQRSTVWXYZ0"
WS = {"workspaceScope": {"workspace": "default"}}

#: The writes ``routes.rs`` lets an interceptor see on v0.1.2.
INTERCEPTABLE = {
    "CreateSandbox", "DeleteSandbox",
    "AttachSandboxProvider", "DetachSandboxProvider", "CreateProvider",
    "ImportProviderProfiles", "UpdateProviderProfiles", "UpdateProvider",
    "ConfigureProviderRefresh", "RotateProviderCredential", "DeleteProviderRefresh",
    "DeleteProvider", "DeleteProviderProfile",
    "CreateSshSession", "ExposeService", "DeleteService", "RevokeSshSession",
    "UpdateConfig", "SubmitPolicyAnalysis", "ApproveDraftChunk", "RejectDraftChunk",
    "ApproveAllDraftChunks", "EditDraftChunk", "UndoDraftChunk", "ClearDraftChunks",
}

PROVIDER = {"metadata": {"name": "gh", "workspace": "default"}, "type": "github",
            "config": {"endpoint": "https://ghe.internal.example"},
            "credentialExpirationTimes": {"GH_PAT": "2027-01-01T00:00:00Z"}}
PROFILE = {"profile": {"id": "acme-llm", "displayName": "Acme LLM",
                       "endpoints": [{"host": "llm.internal.example", "port": 443.0}],
                       "credentials": [{"name": "ACME_KEY"}]},
           "source": "profiles/acme.yaml"}
RULE = {"name": "allow_api_github_com_443",
        "endpoints": [{"host": "api.github.com", "port": 443.0}]}

#: method, the operation, the action, the target after ``openshell:gw-a:``, and
#: what the payload holds besides the method.
CASES = [
    ("DeleteSandbox", {"allowMissing": True, "name": "s1", **WS},
     "openshell_sandbox_delete", SANDBOX_ID,
     {"sandbox_id": SANDBOX_ID, "sandbox_name": "s1", "workspace": "default",
      "allow_missing": True}),
    ("ExposeService",
     {"sandbox": "s1", "name": "web", "targetPort": 8080.0, "domain": True, **WS},
     "openshell_service_change", SANDBOX_ID,
     {"sandbox_id": SANDBOX_ID, "sandbox_name": "s1", "workspace": "default",
      "service": "web", "target_port": 8080, "domain": True}),
    ("DeleteService", {"sandbox": "s1", "name": "web", "allowMissing": True, **WS},
     "openshell_service_change", SANDBOX_ID,
     {"sandbox_id": SANDBOX_ID, "sandbox_name": "s1", "workspace": "default",
      "service": "web", "allow_missing": True}),
    ("CreateSshSession", {"sandbox": "s1", **WS},
     "openshell_ssh_session", SANDBOX_ID,
     {"sandbox_id": SANDBOX_ID, "sandbox_name": "s1", "workspace": "default"}),
    # The gateway omits the session token (a secret field) before it calls.
    ("RevokeSshSession", {"allowMissing": True},
     "openshell_ssh_session", "ssh-session", {"allow_missing": True}),
    ("CreateProvider", {"provider": PROVIDER, **WS},
     "openshell_provider_change", "provider:default/gh",
     {"workspace": "default", "provider": "gh", "provider_type": "github"}),
    ("UpdateProvider",
     {"provider": PROVIDER, "clearCredentialExpirationKeys": ["GH_PAT"], **WS},
     "openshell_provider_change", "provider:default/gh",
     {"workspace": "default", "provider": "gh", "provider_type": "github"}),
    ("ConfigureProviderRefresh",
     {"provider": "gh", "credentialKey": "GH_PAT",
      "strategy": "PROVIDER_CREDENTIAL_REFRESH_STRATEGY_OAUTH2",
      "secretMaterialKeys": ["client_secret"], **WS},
     "openshell_provider_change", "provider:default/gh",
     {"workspace": "default", "provider": "gh"}),
    ("RotateProviderCredential", {"provider": "gh", "credentialKey": "GH_PAT", **WS},
     "openshell_provider_change", "provider:default/gh",
     {"workspace": "default", "provider": "gh"}),
    ("DeleteProviderRefresh",
     {"provider": "gh", "credentialKey": "GH_PAT", "allowMissing": True, **WS},
     "openshell_provider_change", "provider:default/gh",
     {"workspace": "default", "provider": "gh", "allow_missing": True}),
    ("DeleteProvider", {"name": "gh", "allowMissing": True, **WS},
     "openshell_provider_change", "provider:default/gh",
     {"workspace": "default", "provider": "gh", "allow_missing": True}),
    ("ImportProviderProfiles",
     {"profiles": [PROFILE, {"profile": {"id": "other-llm"}, "source": "x.yaml"}], **WS},
     "openshell_provider_change", "provider-profiles:default",
     {"workspace": "default", "profiles": ["acme-llm", "other-llm"]}),
    ("UpdateProviderProfiles",
     {"id": "acme-llm", "profile": PROFILE, "expectedResourceVersion": "3", **WS},
     "openshell_provider_change", "provider-profile:default/acme-llm",
     {"workspace": "default", "profiles": ["acme-llm"]}),
    ("DeleteProviderProfile", {"id": "acme-llm", "allowMissing": True, **WS},
     "openshell_provider_change", "provider-profile:default/acme-llm",
     {"workspace": "default", "profiles": ["acme-llm"], "allow_missing": True}),
    ("UndoDraftChunk", {"sandbox": "s1", "chunkId": "c-7", **WS},
     "openshell_policy_change", SANDBOX_ID,
     {"sandbox_id": SANDBOX_ID, "sandbox_name": "s1", "workspace": "default",
      "chunk_id": "c-7"}),
    ("ClearDraftChunks", {"sandbox": "s1", **WS},
     "openshell_policy_change", SANDBOX_ID,
     {"sandbox_id": SANDBOX_ID, "sandbox_name": "s1", "workspace": "default"}),
    # Bound before this change, but the decision did not say which chunk,
    # which rule or which provider it was about.
    ("ApproveDraftChunk",
     {"sandbox": "s1", "chunkId": "c-7", "reviewToken": "rt-opaque", **WS},
     "openshell_policy_change", SANDBOX_ID,
     {"sandbox_id": SANDBOX_ID, "sandbox_name": "s1", "workspace": "default",
      "chunk_id": "c-7"}),
    ("RejectDraftChunk",
     {"sandbox": "s1", "chunkId": "c-7", "reason": "too broad", **WS},
     "openshell_policy_change", SANDBOX_ID,
     {"sandbox_id": SANDBOX_ID, "sandbox_name": "s1", "workspace": "default",
      "chunk_id": "c-7", "reason": "too broad"}),
    ("ApproveAllDraftChunks",
     {"sandbox": "s1", "includeSecurityFlagged": True,
      "approvals": [{"chunkId": "c-7", "reviewToken": "rt-1"}, {"chunkId": "c-8"}], **WS},
     "openshell_policy_change", SANDBOX_ID,
     {"sandbox_id": SANDBOX_ID, "sandbox_name": "s1", "workspace": "default",
      "chunk_ids": ["c-7", "c-8"], "include_security_flagged": True}),
    ("EditDraftChunk", {"sandbox": "s1", "chunkId": "c-7", "proposedRule": RULE, **WS},
     "openshell_policy_change", SANDBOX_ID,
     {"sandbox_id": SANDBOX_ID, "sandbox_name": "s1", "workspace": "default",
      "chunk_id": "c-7", "proposed_rule": RULE}),
    ("AttachSandboxProvider",
     {"sandbox": "s1", "provider": "gh", "expectedResourceVersion": "2", **WS},
     "openshell_provider_attach", SANDBOX_ID,
     {"sandbox_id": SANDBOX_ID, "sandbox_name": "s1", "workspace": "default",
      "provider": "gh"}),
    ("DetachSandboxProvider", {"sandbox": "s1", "provider": "gh", **WS},
     "openshell_provider_attach", SANDBOX_ID,
     {"sandbox_id": SANDBOX_ID, "sandbox_name": "s1", "workspace": "default",
      "provider": "gh"}),
]


def _call(phase, body, method="UpdateConfig"):
    return {"method": f"openshell.v1.OpenShell/{method}", "phase": phase,
            "body": copy.deepcopy(body), "gateway_id": "gw-a"}


class _Engine:
    def __init__(self, outcome="allow", decision_id=DECISION, status_code=200):
        self.answer = {"outcome": outcome, "decision_id": decision_id,
                       "status_code": status_code}
        self.requests = []

    def __call__(self, payload):
        self.requests.append(dict(payload))
        return dict(self.answer)


def _never(_payload):
    raise AssertionError("decide must not run")


@pytest.fixture
def ledger():
    known = osi.OperationLedger()
    known.learn_sandbox("default", "s1", SANDBOX_ID)
    return known


def _facts(request):
    return json.loads(request["payload"])


# ---------------------------------------------------------------------------
# What is bound
# ---------------------------------------------------------------------------


def test_the_sidecar_decides_every_interceptable_write_but_the_sandbox_callback():
    assert osi.BOUND_VALIDATE | osi.UNBOUND_CALLBACKS == INTERCEPTABLE
    assert osi.UNBOUND_CALLBACKS == {"SubmitPolicyAnalysis"}
    assert not osi.BOUND_VALIDATE & osi.UNBOUND_CALLBACKS
    assert osi.BOUND_MODIFY <= osi.BOUND_VALIDATE
    assert osi.BOUND_POST <= osi.BOUND_VALIDATE


def test_every_case_below_covers_a_bound_method_and_none_is_left_out():
    covered = {case[0] for case in CASES} | {"CreateSandbox", "UpdateConfig"}
    assert covered == set(osi.BOUND_VALIDATE)


def test_the_sandbox_callback_is_refused_if_someone_binds_it():
    """A sandbox's supervisor calls it on a timer. Deciding each call would
    seal a leaf every few seconds per sandbox, so the sidecar does not serve
    it; bound by mistake, it is refused and never allowed unseen."""
    out = osi.evaluate(_call("validate", {"name": "s1", "analysisMode": "mechanistic", **WS},
                             "SubmitPolicyAnalysis"), decide=_never)
    assert out["allowed"] is False
    assert "not an interceptable binding" in out["reason"]


# ---------------------------------------------------------------------------
# One decision per write, named for what it is
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("method,body,action,target,facts", CASES,
                         ids=[case[0] for case in CASES])
def test_each_write_is_decided_as_what_it_is(ledger, method, body, action, target, facts):
    engine = _Engine()
    out = osi.evaluate(_call("validate", body, method), decide=engine, ledger=ledger)
    assert out["allowed"] is True
    assert len(engine.requests) == 1
    sent = engine.requests[0]
    assert sent["action"] == action
    assert sent["target"] == f"openshell:gw-a:{target}"
    assert sent["surface"] == "openshell"
    assert _facts(sent) == {"method": method, **facts}


@pytest.mark.parametrize("method,body,action,target,facts", CASES,
                         ids=[case[0] for case in CASES])
def test_a_deny_refuses_each_write(ledger, method, body, action, target, facts):
    out = osi.evaluate(_call("validate", body, method), decide=_Engine("deny"),
                       ledger=ledger)
    assert out["allowed"] is False and out["status_code"] == 403


@pytest.mark.parametrize("method", sorted(set(INTERCEPTABLE) - {"CreateSandbox", "UpdateConfig"}))
def test_only_creates_and_updates_are_decided_in_modify_operation(method):
    out = osi.evaluate(_call("modify_operation", {"sandbox": "s1", **WS}, method),
                       decide=_never)
    assert out["allowed"] is True and out["patches"] == []


def test_a_provider_write_sends_names_and_nothing_else(ledger):
    engine = _Engine()
    for method, body, _action, _target, _facts_ in CASES:
        if _action == "openshell_provider_change":
            osi.evaluate(_call("validate", body, method), decide=engine, ledger=ledger)
    sent = " ".join(request["payload"] for request in engine.requests)
    for private in ("internal.example", "GH_PAT", "ACME_KEY", "client_secret",
                    "profiles/acme.yaml", "OAUTH2", "Acme LLM"):
        assert private not in sent


def test_a_provider_is_not_mistaken_for_the_sandbox_that_shares_its_name():
    known = osi.OperationLedger()
    known.learn_sandbox("default", "gh", SANDBOX_ID)
    engine = _Engine()
    osi.evaluate(_call("validate", {"name": "gh", **WS}, "DeleteProvider"),
                 decide=engine, ledger=known)
    assert engine.requests[0]["target"] == "openshell:gw-a:provider:default/gh"
    assert SANDBOX_ID not in engine.requests[0]["payload"]


def test_a_service_is_not_mistaken_for_the_sandbox_it_belongs_to(ledger):
    ledger.learn_sandbox("default", "web", "00000000-0000-0000-0000-000000000000")
    engine = _Engine()
    osi.evaluate(_call("validate", {"sandbox": "s1", "name": "web", **WS}, "ExposeService"),
                 decide=engine, ledger=ledger)
    assert engine.requests[0]["target"] == f"openshell:gw-a:{SANDBOX_ID}"


def test_a_service_call_that_names_no_sandbox_does_not_borrow_the_service_name(ledger):
    ledger.learn_sandbox("default", "web", "00000000-0000-0000-0000-000000000000")
    engine = _Engine()
    osi.evaluate(_call("validate", {"name": "web", **WS}, "DeleteService"),
                 decide=engine, ledger=ledger)
    assert engine.requests[0]["target"] == "openshell:gw-a:pending"
    assert _facts(engine.requests[0])["sandbox_name"] == ""


def test_a_provider_in_another_workspace_is_another_target():
    engine = _Engine()
    osi.evaluate(_call("validate", {"name": "gh", "workspaceScope": {"workspace": "team-b"}},
                       "DeleteProvider"), decide=engine)
    assert engine.requests[0]["target"] == "openshell:gw-a:provider:team-b/gh"


def test_a_session_token_never_reaches_the_decision(ledger):
    engine = _Engine()
    osi.evaluate(_call("validate", {"token": "sess-secret-value", "allowMissing": False},
                       "RevokeSshSession"), decide=engine, ledger=ledger)
    assert "sess-secret-value" not in json.dumps(engine.requests[0])


def test_a_review_token_never_reaches_the_decision(ledger):
    engine = _Engine()
    for method, body, *_rest in CASES:
        if "Approve" in method:
            osi.evaluate(_call("validate", body, method), decide=engine, ledger=ledger)
    assert "rt-" not in " ".join(request["payload"] for request in engine.requests)


def test_an_unknown_sandbox_is_named_not_guessed():
    engine = _Engine()
    osi.evaluate(_call("validate", {"name": "s9", **WS}, "DeleteSandbox"),
                 decide=engine, ledger=osi.OperationLedger())
    assert engine.requests[0]["target"] == "openshell:gw-a:name:default/s9"
    assert _facts(engine.requests[0])["sandbox_id"] == ""


# ---------------------------------------------------------------------------
# A delete ends what the sidecar knows about the name
# ---------------------------------------------------------------------------


def test_an_allowed_delete_forgets_the_sandbox_name(ledger):
    osi.evaluate(_call("validate", {"name": "s1", **WS}, "DeleteSandbox"),
                 decide=_Engine(), ledger=ledger)
    # A sandbox created later under the same name is another sandbox. Until
    # its own create is seen, it is decided by name, never as the old uuid.
    assert ledger.sandbox_id("default", "s1") == ""


def test_a_refused_delete_keeps_the_sandbox_name(ledger):
    osi.evaluate(_call("validate", {"name": "s1", **WS}, "DeleteSandbox"),
                 decide=_Engine("deny"), ledger=ledger)
    assert ledger.sandbox_id("default", "s1") == SANDBOX_ID


def test_a_delete_in_one_workspace_leaves_the_other_alone(ledger):
    ledger.learn_sandbox("team-b", "s1", "22222222-2222-2222-2222-222222222222")
    osi.evaluate(_call("validate", {"name": "s1", **WS}, "DeleteSandbox"),
                 decide=_Engine(), ledger=ledger)
    assert ledger.sandbox_id("team-b", "s1") == "22222222-2222-2222-2222-222222222222"


# ---------------------------------------------------------------------------
# UpdateConfig: a policy, or a setting
# ---------------------------------------------------------------------------

MANUAL = {"global": True, "settingKey": "proposal_approval_mode",
          "settingValue": {"stringValue": "manual"}}
AUTO = {"global": True, "settingKey": "proposal_approval_mode",
        "settingValue": {"stringValue": "auto"}}


def test_a_global_setting_write_is_decided_once_as_a_setting_change():
    engine = _Engine()
    modified = osi.evaluate(_call("modify_operation", MANUAL), decide=engine,
                            ledger=osi.OperationLedger())
    assert modified["allowed"] is True and modified["patches"] == []
    assert engine.requests == []  # nothing to stamp, so validate decides
    out = osi.evaluate(_call("validate", MANUAL), decide=engine, ledger=osi.OperationLedger())
    assert out["allowed"] is True
    assert len(engine.requests) == 1
    sent = engine.requests[0]
    assert sent["action"] == "openshell_setting_change"
    assert sent["target"] == "openshell:gw-a:gateway"
    assert _facts(sent) == {"method": "UpdateConfig", "global": True,
                            "setting_key": "proposal_approval_mode",
                            "setting_value": "manual"}


def test_an_auto_approve_attempt_is_sent_for_a_decision_not_dropped_locally():
    engine = _Engine("deny")
    out = osi.evaluate(_call("validate", AUTO), decide=engine)
    assert out["allowed"] is False
    assert len(engine.requests) == 1
    assert _facts(engine.requests[0])["setting_value"] == "auto"


@pytest.mark.parametrize("body", [
    {"global": True, "policy": {"version": 1.0}},
    {"global": True, "mergeOperations": [{"addRule": {"ruleName": "r"}}]},
    {"global": True, "policy": {"version": 1.0}, "settingKey": "ocsf_json_enabled",
     "settingValue": {"boolValue": True}},
    {"global": True, "mergeOperations": [{"addRule": {"ruleName": "r"}}],
     "settingKey": "ocsf_json_enabled", "settingValue": {"boolValue": True}},
    # An empty policy is still a policy: it would replace every sandbox's.
    {"global": True, "policy": {}, "settingKey": "ocsf_json_enabled",
     "settingValue": {"boolValue": True}},
    {"global": True},
])
@pytest.mark.parametrize("phase", ["modify_operation", "validate"])
def test_a_global_policy_is_still_refused_without_a_decision(body, phase):
    out = osi.evaluate(_call(phase, body), decide=_never, ledger=osi.OperationLedger())
    assert out["allowed"] is False and "global" in out["reason"]


def test_a_sandbox_setting_write_is_a_setting_change_stamped_like_any_update(ledger):
    body = {"sandbox": "s1", "settingKey": "agent_policy_proposals_enabled",
            "settingValue": {"boolValue": True}, **WS}
    engine = _Engine()
    out = osi.evaluate(_call("modify_operation", body), decide=engine, ledger=ledger)
    assert out["patches"] == [
        {"op": "add", "path": "/annotations", "value": {osi.STAMP_KEY: DECISION}}]
    sent = engine.requests[0]
    assert sent["action"] == "openshell_setting_change"
    assert sent["target"] == f"openshell:gw-a:{SANDBOX_ID}"
    assert _facts(sent) == {
        "method": "UpdateConfig", "sandbox_id": SANDBOX_ID, "sandbox_name": "s1",
        "workspace": "default", "setting_key": "agent_policy_proposals_enabled",
        "setting_value": True}
    stamped = {**body, "annotations": {osi.STAMP_KEY: DECISION}}
    again = osi.evaluate(_call("validate", stamped), decide=_never, ledger=ledger)
    assert again["reason"] == "decided in modify_operation"


def test_deleting_a_setting_says_so():
    engine = _Engine()
    osi.evaluate(_call("validate", {"global": True, "settingKey": "proposal_approval_mode",
                                    "deleteSetting": True}), decide=engine)
    assert _facts(engine.requests[0]) == {
        "method": "UpdateConfig", "global": True,
        "setting_key": "proposal_approval_mode", "delete_setting": True}


@pytest.mark.parametrize("value,sent", [
    ({"stringValue": "1.3"}, "1.3"),
    ({"boolValue": False}, False),
    ({"intValue": "42"}, 42),
    ({"intValue": 42.0}, 42),
])
def test_a_setting_value_is_sent_as_its_plain_value(value, sent):
    engine = _Engine()
    osi.evaluate(_call("validate", {"global": True, "settingKey": "k", "settingValue": value}),
                 decide=engine)
    got = _facts(engine.requests[0])["setting_value"]
    assert got == sent and type(got) is type(sent)


def test_a_port_is_sent_as_the_whole_number_it_is(ledger):
    # Protobuf-JSON carries every number as a double.
    engine = _Engine()
    osi.evaluate(_call("validate", {"sandbox": "s1", "name": "web", "targetPort": 8080.0, **WS},
                       "ExposeService"), decide=engine, ledger=ledger)
    assert type(_facts(engine.requests[0])["target_port"]) is int
    assert '"target_port": 8080,' in engine.requests[0]["payload"]


def test_a_bytes_setting_value_is_not_sent():
    engine = _Engine()
    osi.evaluate(_call("validate", {"global": True, "settingKey": "k",
                                    "settingValue": {"bytesValue": "c2VjcmV0"}}),
                 decide=engine)
    facts = _facts(engine.requests[0])
    assert "c2VjcmV0" not in engine.requests[0]["payload"]
    assert facts["setting_value_kind"] == "bytes" and "setting_value" not in facts


def test_a_policy_update_that_also_names_a_setting_is_a_policy_change_that_shows_it(ledger):
    body = {"sandbox": "s1", "policy": {"version": 1.0},
            "settingKey": "proposal_approval_mode",
            "settingValue": {"stringValue": "auto"}, **WS}
    engine = _Engine()
    osi.evaluate(_call("validate", body), decide=engine, ledger=ledger)
    sent = engine.requests[0]
    assert sent["action"] == "openshell_policy_change"
    facts = _facts(sent)
    assert facts["setting_key"] == "proposal_approval_mode"
    assert facts["setting_value"] == "auto"


def test_a_policy_update_keeps_its_action_and_its_payload(ledger):
    body = {"sandbox": "s1", "mergeOperations": [{"addRule": {"ruleName": "r"}}], **WS}
    engine = _Engine()
    osi.evaluate(_call("validate", body), decide=engine, ledger=ledger)
    sent = engine.requests[0]
    assert sent["action"] == "openshell_policy_change"
    assert _facts(sent) == {
        "method": "UpdateConfig", "sandbox_id": SANDBOX_ID, "sandbox_name": "s1",
        "workspace": "default", "policy": None,
        "merge_operations": [{"addRule": {"ruleName": "r"}}], "prover": None}


def test_snake_case_operations_read_the_same(ledger):
    engine = _Engine()
    osi.evaluate(_call("validate", {"sandbox": "s1", "name": "web", "target_port": 8080,
                                    "workspace_scope": {"workspace": "default"}},
                       "ExposeService"), decide=engine, ledger=ledger)
    assert _facts(engine.requests[0])["target_port"] == 8080
    engine = _Engine()
    osi.evaluate(_call("validate", {"global": True, "setting_key": "k",
                                    "setting_value": {"string_value": "v"}}), decide=engine)
    assert _facts(engine.requests[0])["setting_value"] == "v"


# ---------------------------------------------------------------------------
# The refusal names its decision
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("outcome", ["deny", "review"])
def test_a_refusal_carries_the_decision_id_to_the_operator(outcome):
    out = osi.evaluate(_call("validate", AUTO), decide=_Engine(outcome))
    assert out["allowed"] is False
    assert out["reason"] == f"decision {outcome} ({DECISION})"
    assert out["log_annotations"] == {"decision_id": DECISION}


def test_a_refusal_with_no_decision_says_only_that():
    out = osi.evaluate(_call("validate", AUTO), decide=_Engine("deny", decision_id=""))
    assert out["reason"] == "decision deny" and out["log_annotations"] == {}
    down = osi.evaluate(_call("validate", AUTO),
                        decide=_Engine("deny", decision_id=DECISION, status_code=503))
    assert down["reason"] == "decision unavailable" and down["status_code"] == 503


def test_a_decision_id_in_a_reason_is_only_ever_an_id():
    # The reason reaches the operator's terminal as written.
    out = osi.evaluate(_call("validate", AUTO),
                       decide=_Engine("deny", decision_id="01J\x1b[31m) rm -rf\nline two"))
    assert out["reason"] == "decision deny"
    assert out["log_annotations"] == {}
