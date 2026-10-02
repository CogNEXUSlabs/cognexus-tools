"""One decision per OpenShell operation, tied to the write it allowed.

A create or an update is decided in ``modify_operation``, the only phase
that can change the write, and the decision id is stamped onto it as an
annotation. ``validate`` confirms that decision without asking again, and
``post_commit`` reads the stamp back, with the committed policy hash, to
report the projection. A sandbox is named by the uuid its create returned.

The payloads are the ones an OpenShell v0.1.2 gateway sent in the wire
spike: protobuf-JSON, with numbers as doubles. Before this change the
decision was made in ``validate``, which cannot stamp; ``post_commit`` then
had no decision id, and no projection was ever reported from a real gateway.
"""

from __future__ import annotations

import copy

import pytest

from artzain.openshell import interceptor as osi
from artzain.openshell import sidecar
from artzain.openshell.state import GatewayLedger

SANDBOX_ID = "1e04e83f-6de7-4f86-b466-2e945af3e724"
POLICY_HASH = "0402e6704bbdf5abf519e4bfbfb526efb467fc40aeebb8e3b74eb8cdc6b69e74"
DECISION = "01JABCDEFGHJKMNPQRSTVWXYZ0"  # 26 characters, as the engine issues

UPDATE = {
    "mergeOperations": [{"addRule": {
        "rule": {"binaries": [{"path": "/usr/bin/curl"}],
                 "endpoints": [{"host": "api.github.com", "port": 443.0, "ports": [443.0]}],
                 "name": "allow_api_github_com_443"},
        "ruleName": "allow_api_github_com_443"}}],
    "sandbox": "s1",
    "workspaceScope": {"workspace": "default"},
}
CREATE = {"name": "s1", "spec": {"command": ["sleep", "infinity"]},
          "workspaceScope": {"workspace": "default"}}
CREATED = {"sandbox": {
    "metadata": {"annotations": {osi.STAMP_KEY: DECISION, "internal.openshell.ai/auth-epoch": "1"},
                 "id": SANDBOX_ID, "name": "s1", "resourceVersion": "1", "workspace": "default"},
    "spec": {"command": ["sleep", "infinity"]},
    "status": {"phase": "SANDBOX_PHASE_PROVISIONING"},
}}
BASE = {"version": 1.0, "networkPolicies": {"artzain": {"name": "artzain"}}}


def _call(phase, body, method="UpdateConfig"):
    return {"method": f"openshell.v1.OpenShell/{method}", "phase": phase,
            "body": copy.deepcopy(body), "gateway_id": "gw-a"}


class _Engine:
    def __init__(self, outcome="allow", decision_id=DECISION):
        self.outcome, self.decision_id, self.requests = outcome, decision_id, []

    def __call__(self, payload):
        self.requests.append(dict(payload))
        return {"outcome": self.outcome, "decision_id": self.decision_id, "status_code": 200}


def _as_validated(body, patches):
    """The operation as the gateway shows it to ``validate``: our patches applied."""
    out = copy.deepcopy(body)
    for patch in patches:
        parts = [p.replace("~1", "/").replace("~0", "~") for p in patch["path"].split("/")[1:]]
        node = out
        for part in parts[:-1]:
            node = node[part]
        node[parts[-1]] = copy.deepcopy(patch["value"])
    return out


@pytest.fixture
def ledger():
    return osi.OperationLedger()


@pytest.fixture(autouse=True)
def _fresh_sidecar_ledger(monkeypatch):
    monkeypatch.setattr(sidecar, "_LEDGER", GatewayLedger(gateway_id="gw-a"))
    monkeypatch.setenv("OPENSHELL_GATEWAY_ID", "gw-a")


# ---------------------------------------------------------------------------
# modify_operation decides and stamps
# ---------------------------------------------------------------------------


def test_an_update_is_decided_in_modify_operation_and_stamped(ledger):
    engine = _Engine()
    out = osi.evaluate(_call("modify_operation", UPDATE), decide=engine, ledger=ledger)
    assert out["allowed"] is True
    assert len(engine.requests) == 1
    assert out["patches"] == [
        {"op": "add", "path": "/annotations", "value": {osi.STAMP_KEY: DECISION}}]
    assert out["log_annotations"] == {"decision_id": DECISION}


def test_a_create_is_decided_in_modify_operation_and_stamped(ledger):
    engine = _Engine()
    out = osi.evaluate(_call("modify_operation", CREATE, "CreateSandbox"),
                       decide=engine, ledger=ledger)
    assert out["allowed"] is True and len(engine.requests) == 1
    assert out["patches"] == [
        {"op": "add", "path": "/annotations", "value": {osi.STAMP_KEY: DECISION}}]


def test_the_stamp_replaces_a_value_the_caller_put_under_our_key(ledger):
    body = {**UPDATE, "annotations": {osi.STAMP_KEY: "01FORGED", "team": "blue"}}
    out = osi.evaluate(_call("modify_operation", body), decide=_Engine(), ledger=ledger)
    path = "/annotations/artzain.cognexuslabs.ai~1decision-id"
    assert out["patches"] == [{"op": "add", "path": path, "value": DECISION}]
    validated = _as_validated(body, out["patches"])
    assert validated["annotations"] == {osi.STAMP_KEY: DECISION, "team": "blue"}


def test_a_create_gets_the_base_policy_and_the_stamp(ledger):
    out = osi.evaluate(_call("modify_operation", CREATE, "CreateSandbox"),
                       decide=_Engine(), base_policy=BASE, ledger=ledger)
    assert out["patches"] == [
        {"op": "add", "path": "/spec/policy", "value": BASE},
        {"op": "add", "path": "/annotations", "value": {osi.STAMP_KEY: DECISION}},
    ]


@pytest.mark.parametrize("outcome, status", [("deny", 403), ("review", 403)])
def test_a_denied_operation_is_denied_in_modify_operation(ledger, outcome, status):
    out = osi.evaluate(_call("modify_operation", UPDATE), decide=_Engine(outcome), ledger=ledger)
    assert out["allowed"] is False and out["status_code"] == status
    assert out["patches"] == []
    assert ledger.decided(DECISION) is None


def test_a_global_update_is_denied_in_modify_operation_without_a_decision(ledger):
    def never(_payload):
        raise AssertionError("decide must not run")

    out = osi.evaluate(_call("modify_operation", {"global": True, "policy": {"version": 1.0}}),
                       decide=never, ledger=ledger)
    assert out["allowed"] is False and "global" in out["reason"]


def test_the_gateway_takes_no_annotation_on_a_global_write():
    # It rejects the whole write: "annotations are only supported for
    # sandbox-scoped updates" (wire notes, Q3).
    assert osi.stampable("UpdateConfig", {"sandbox": "s1"}) is True
    assert osi.stampable("UpdateConfig", {"global": True, "settingKey": "k"}) is False
    assert osi.stampable("CreateSandbox", {"name": "s1"}) is True
    assert osi.stampable("ApproveDraftChunk", {"sandbox": "s1"}) is False


def test_other_methods_are_not_decided_in_modify_operation(ledger):
    def never(_payload):
        raise AssertionError("decide must not run")

    out = osi.evaluate(_call("modify_operation", {"sandbox": "s1"}, "ApproveDraftChunk"),
                       decide=never, ledger=ledger)
    assert out["allowed"] is True and out["patches"] == []


# ---------------------------------------------------------------------------
# validate confirms, and never allows without a decision
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("method, body", [("UpdateConfig", UPDATE), ("CreateSandbox", CREATE)])
def test_validate_confirms_the_modify_decision_without_deciding_again(ledger, method, body):
    engine = _Engine()
    modified = osi.evaluate(_call("modify_operation", body, method), decide=engine, ledger=ledger)
    validated = _as_validated(body, modified["patches"])
    out = osi.evaluate(_call("validate", validated, method), decide=engine, ledger=ledger)
    assert out["allowed"] is True
    assert out["reason"] == "decided in modify_operation"
    assert out["log_annotations"] == {"decision_id": DECISION}
    assert len(engine.requests) == 1


def test_validate_confirms_a_create_whose_base_the_gateway_rewrote(ledger):
    engine = _Engine()
    modified = osi.evaluate(_call("modify_operation", CREATE, "CreateSandbox"),
                            decide=engine, base_policy=BASE, ledger=ledger)
    validated = _as_validated(CREATE, modified["patches"])
    # The gateway re-encodes the patched write; its form of the policy may differ.
    validated["spec"]["policy"] = {"version": 1, "networkPolicies": {"artzain": {"name": "artzain",
                                                                               "endpoints": []}}}
    out = osi.evaluate(_call("validate", validated, "CreateSandbox"), decide=engine, ledger=ledger)
    assert out["reason"] == "decided in modify_operation"
    assert len(engine.requests) == 1


def test_validate_decides_again_when_the_operation_changed(ledger):
    engine = _Engine()
    modified = osi.evaluate(_call("modify_operation", UPDATE), decide=engine, ledger=ledger)
    validated = _as_validated(UPDATE, modified["patches"])
    validated["mergeOperations"][0]["addRule"]["rule"]["endpoints"][0]["host"] = "evil.example"
    out = osi.evaluate(_call("validate", validated), decide=engine, ledger=ledger)
    assert out["reason"] == "decision allow"
    assert len(engine.requests) == 2
    assert "evil.example" in engine.requests[1]["payload"]


def test_validate_decides_again_for_another_method(ledger):
    engine = _Engine()
    modified = osi.evaluate(_call("modify_operation", UPDATE), decide=engine, ledger=ledger)
    validated = _as_validated(UPDATE, modified["patches"])
    osi.evaluate(_call("validate", validated, "CreateSandbox"), decide=engine, ledger=ledger)
    assert len(engine.requests) == 2


@pytest.mark.parametrize("annotations", [
    None, {}, {osi.STAMP_KEY: "01NEVERISSUED"}, {osi.STAMP_KEY: ""},
])
def test_validate_decides_when_the_stamp_is_missing_or_unknown(ledger, annotations):
    engine = _Engine()
    body = dict(UPDATE) if annotations is None else {**UPDATE, "annotations": annotations}
    out = osi.evaluate(_call("validate", body), decide=engine, ledger=ledger)
    assert out["allowed"] is True and out["reason"] == "decision allow"
    assert len(engine.requests) == 1


def test_a_denied_fallback_decision_is_a_deny(ledger):
    out = osi.evaluate(_call("validate", {**UPDATE, "annotations": {osi.STAMP_KEY: "01X"}}),
                       decide=_Engine("deny"), ledger=ledger)
    assert out["allowed"] is False


def test_an_expired_decision_is_not_confirmed():
    clock = [1000.0]
    ledger = osi.OperationLedger(ttl_seconds=300, now=lambda: clock[0])
    engine = _Engine()
    modified = osi.evaluate(_call("modify_operation", UPDATE), decide=engine, ledger=ledger)
    validated = _as_validated(UPDATE, modified["patches"])
    clock[0] += 301
    osi.evaluate(_call("validate", validated), decide=engine, ledger=ledger)
    assert len(engine.requests) == 2


def test_without_a_ledger_validate_decides(ledger):
    engine = _Engine()
    modified = osi.evaluate(_call("modify_operation", UPDATE), decide=engine, ledger=ledger)
    validated = _as_validated(UPDATE, modified["patches"])
    osi.evaluate(_call("validate", validated), decide=engine)
    assert len(engine.requests) == 2


def test_the_ledger_is_bounded():
    ledger = osi.OperationLedger(max_decisions=3, max_sandboxes=2)
    for n in range(5):
        ledger.remember(f"d{n}", method="UpdateConfig", digest="x")
        ledger.learn_sandbox("default", f"s{n}", f"id{n}")
    assert [bool(ledger.decided(f"d{n}")) for n in range(5)] == [False, False, True, True, True]
    assert [ledger.sandbox_id("default", f"s{n}") for n in range(5)] == ["", "", "", "id3", "id4"]


# ---------------------------------------------------------------------------
# Sandboxes are named by uuid
# ---------------------------------------------------------------------------


def test_an_unresolved_name_is_decided_as_a_name(ledger):
    engine = _Engine()
    osi.evaluate(_call("modify_operation", UPDATE), decide=engine, ledger=ledger)
    assert engine.requests[0]["target"] == "openshell:gw-a:name:default/s1"
    assert '"sandbox_name": "s1"' in engine.requests[0]["payload"]


def test_a_create_is_decided_by_name_until_it_has_a_uuid(ledger):
    engine = _Engine()
    ledger.learn_sandbox("default", "s1", "an-older-sandbox-of-this-name")
    osi.evaluate(_call("modify_operation", CREATE, "CreateSandbox"), decide=engine, ledger=ledger)
    assert engine.requests[0]["target"] == "openshell:gw-a:name:default/s1"
    unnamed = {"spec": {"command": ["sleep"]}, "workspaceScope": {"workspace": "default"}}
    osi.evaluate(_call("modify_operation", unnamed, "CreateSandbox"), decide=engine, ledger=ledger)
    assert engine.requests[1]["target"] == "openshell:gw-a:pending"


def test_a_committed_create_teaches_the_uuid():
    engine = _Engine()
    sidecar.handle_evaluate(_call("post_commit", CREATED, "CreateSandbox"), decide=engine)
    sidecar.handle_evaluate(_call("modify_operation", UPDATE), decide=engine)
    sidecar.handle_evaluate(
        _call("validate", {"sandbox": "s1", "workspaceScope": {"workspace": "default"}},
              "ApproveDraftChunk"), decide=engine)
    assert [r["target"] for r in engine.requests] == [f"openshell:gw-a:{SANDBOX_ID}"] * 2
    assert f'"sandbox_id": "{SANDBOX_ID}"' in engine.requests[0]["payload"]


def test_the_same_name_in_another_workspace_is_another_sandbox():
    engine = _Engine()
    sidecar.handle_evaluate(_call("post_commit", CREATED, "CreateSandbox"), decide=engine)
    other = {**UPDATE, "workspaceScope": {"workspace": "team-b"}}
    sidecar.handle_evaluate(_call("modify_operation", other), decide=engine)
    assert engine.requests[0]["target"] == "openshell:gw-a:name:team-b/s1"


# ---------------------------------------------------------------------------
# post_commit reads the stamp back and reports the projection
# ---------------------------------------------------------------------------


@pytest.fixture
def reports(monkeypatch):
    sent = []
    monkeypatch.setattr(sidecar, "http_report_projection",
                        lambda payload: sent.append(dict(payload)) or True)
    return sent


def _committed_update(decision_id=DECISION):
    return {"annotations": {osi.STAMP_KEY: decision_id, "internal.openshell.ai/auth-epoch": "1"},
            "policyHash": POLICY_HASH, "version": 1.0}


def test_a_committed_update_is_reported_with_its_decision_and_sandbox(reports):
    engine = _Engine()
    sidecar.handle_evaluate(_call("post_commit", CREATED, "CreateSandbox"), decide=engine)
    modified = sidecar.handle_evaluate(_call("modify_operation", UPDATE), decide=engine)
    sidecar.handle_evaluate(_call("validate", _as_validated(UPDATE, modified["patches"])),
                            decide=engine)
    out = sidecar.handle_evaluate(_call("post_commit", _committed_update()), decide=engine)
    assert out["allowed"] is True
    assert out["log_annotations"] == {"policy_hash": POLICY_HASH, "decision_id": DECISION}
    assert reports == [{"sandbox_id": SANDBOX_ID, "policy_hash": POLICY_HASH,
                        "decision_id": DECISION, "method": "UpdateConfig"}]
    assert len(engine.requests) == 1  # one decision for the whole operation


def test_post_commit_never_decides(reports):
    def never(_payload):
        raise AssertionError("post_commit must not decide")

    sidecar.handle_evaluate(_call("post_commit", _committed_update()), decide=never)
    sidecar.handle_evaluate(_call("post_commit", CREATED, "CreateSandbox"), decide=never)


def test_a_committed_create_carries_its_decision_in_the_gateway_log(reports):
    # A create's stamp comes back under the sandbox's metadata, not at the top.
    out = sidecar.handle_evaluate(_call("post_commit", CREATED, "CreateSandbox"),
                                  decide=_Engine())
    assert out["log_annotations"] == {"decision_id": DECISION}


def test_a_committed_create_reports_nothing_without_a_hash(reports):
    # A create's response has no policy hash yet: its configuration is pending admission.
    sidecar.handle_evaluate(_call("post_commit", CREATED, "CreateSandbox"), decide=_Engine())
    assert reports == []


def test_an_update_to_an_unresolved_sandbox_is_not_reported(reports):
    engine = _Engine()
    sidecar.handle_evaluate(_call("modify_operation", UPDATE), decide=engine)
    sidecar.handle_evaluate(_call("post_commit", _committed_update()), decide=engine)
    assert reports == []


@pytest.mark.parametrize("committed", [
    {"policyHash": POLICY_HASH, "version": 1.0},
    {"annotations": {"team": "blue"}, "policyHash": POLICY_HASH},
    {"annotations": {osi.STAMP_KEY: "01NOTOURS0000000000000000A"}, "policyHash": POLICY_HASH},
    {"annotations": {osi.STAMP_KEY: DECISION}},
    {"settingsRevision": "1"},
])
def test_a_write_this_sidecar_cannot_tie_to_a_decision_is_not_reported(reports, committed):
    engine = _Engine()
    sidecar.handle_evaluate(_call("post_commit", CREATED, "CreateSandbox"), decide=engine)
    sidecar.handle_evaluate(_call("modify_operation", UPDATE), decide=engine)
    out = sidecar.handle_evaluate(_call("post_commit", committed), decide=engine)
    assert out["allowed"] is True
    assert reports == []


def test_a_failed_report_still_allows(monkeypatch):
    def boom(_payload):
        raise RuntimeError("down")

    monkeypatch.setattr(sidecar, "http_report_projection", boom)
    engine = _Engine()
    sidecar.handle_evaluate(_call("post_commit", CREATED, "CreateSandbox"), decide=engine)
    sidecar.handle_evaluate(_call("modify_operation", UPDATE), decide=engine)
    out = sidecar.handle_evaluate(_call("post_commit", _committed_update()), decide=engine)
    assert out["allowed"] is True
