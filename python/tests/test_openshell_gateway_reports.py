"""What the sidecar knows of its gateway's sandboxes, and what it tells the engine.

The gateway names a sandbox by name in every call but the create's answer, so
the sidecar remembers each uuid. That memory was the process's own: after a
restart an update to an older sandbox was decided by name and its projection
was not reported. And the inventory the sidecar served never worked against
the real OpenShell SDK (``SandboxClient()`` with no endpoint, ``list_all()``
with no workspace).

* The sidecar's sandboxes (names, ids, effective policy hashes) are kept in a
  private state file and read back at the next start.
* The inventory is what the sidecar has seen commit, sent as partial until it
  is known to be every sandbox; or, where listing is switched on, a real
  listing through ``SandboxClient.from_active_cluster()`` and
  ``list_all(workspace=...)``.
* With a gateway credential, a :class:`~artzain.openshell.sidecar.Reporter`
  sends the engine a heartbeat every minute and the inventory every five
  minutes and on change.
"""

from __future__ import annotations

import copy
import json
import os
import stat
import sys
import time
import types

import pytest

import artzain
from artzain.openshell import interceptor as osi
from artzain.openshell import sidecar
from artzain.openshell.journal import Journal
from artzain.openshell.state import GatewayLedger

SANDBOX_ID = "1e04e83f-6de7-4f86-b466-2e945af3e724"
OTHER_ID = "7c9a1d52-0b1e-4c57-9f0e-3a2f6f1f2b10"
POLICY_HASH = "0402e6704bbdf5abf519e4bfbfb526efb467fc40aeebb8e3b74eb8cdc6b69e74"
DECISION = "01JABCDEFGHJKMNPQRSTVWXYZ0"
SECOND = "01JABCDEFGHJKMNPQRSTVWXYZ1"

UPDATE = {
    "mergeOperations": [{"addRule": {"rule": {"name": "r"}, "ruleName": "r"}}],
    "sandbox": "s1",
    "workspaceScope": {"workspace": "default"},
}
CREATED = {"sandbox": {
    "metadata": {"annotations": {osi.STAMP_KEY: DECISION}, "id": SANDBOX_ID, "name": "s1",
                 "workspace": "default"},
    "status": {"phase": "SANDBOX_PHASE_PROVISIONING"},
}}


def _call(phase, body, method="UpdateConfig"):
    return {"method": f"openshell.v1.OpenShell/{method}", "phase": phase,
            "body": copy.deepcopy(body)}


def _as_validated(body, patches):
    out = copy.deepcopy(body)
    for patch in patches:
        parts = [p.replace("~1", "/").replace("~0", "~") for p in patch["path"].split("/")[1:]]
        node = out
        for part in parts[:-1]:
            node = node[part]
        node[parts[-1]] = copy.deepcopy(patch["value"])
    return out


class _Engine:
    def __init__(self, decision_id=DECISION):
        self.decision_id, self.requests = decision_id, []

    def __call__(self, payload):
        self.requests.append(dict(payload))
        return {"outcome": "allow", "decision_id": self.decision_id, "status_code": 200}


@pytest.fixture(autouse=True)
def _sidecar_env(monkeypatch):
    monkeypatch.setenv("OPENSHELL_GATEWAY_ID", "gw-a")
    for name in ("OPENSHELL_SIDECAR_LIST_WORKSPACES", "OPENSHELL_SIDECAR_STATE",
                 "OPENSHELL_REGISTRATION_DIGEST", "ARTZAIN_DECISION_URL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("COGNEXUS_API_KEY", "cnxg_sidecar_test_credential")
    monkeypatch.setattr(sidecar, "_LEDGER", GatewayLedger(gateway_id="gw-a"))
    monkeypatch.setattr(sidecar, "_LATENCY", sidecar.LatencyWindow())
    monkeypatch.setattr(sidecar, "_UNDELIVERED", sidecar.Counter())
    monkeypatch.setattr(sidecar, "_JOURNAL", Journal())
    monkeypatch.setattr(sidecar, "_CLIENT", None)


@pytest.fixture
def reports(monkeypatch):
    sent = []
    monkeypatch.setattr(sidecar, "http_report_projection",
                        lambda payload: sent.append(dict(payload)) or True)
    return sent


@pytest.fixture
def state(tmp_path):
    return str(tmp_path / "sidecar" / "gw-a.json")


def _governed_update(ledger, engine, decision_id=DECISION):
    """One update through the three phases, as the gateway calls them."""
    modified = sidecar.handle_evaluate(_call("modify_operation", UPDATE), decide=engine,
                                       ledger=ledger)
    sidecar.handle_evaluate(_call("validate", _as_validated(UPDATE, modified["patches"])),
                            decide=engine, ledger=ledger)
    return sidecar.handle_evaluate(
        _call("post_commit", {"annotations": {osi.STAMP_KEY: decision_id},
                              "policyHash": POLICY_HASH, "version": 1.0}),
        decide=engine, ledger=ledger)


# ---------------------------------------------------------------------------
# The state file
# ---------------------------------------------------------------------------


def test_a_restarted_sidecar_still_knows_its_sandboxes(state):
    first = GatewayLedger(state_path=state, gateway_id="gw-a")
    first.learn_sandbox("default", "s1", SANDBOX_ID)
    first.learn_sandbox("lab", "s1", OTHER_ID)
    first.note_policy_hash(SANDBOX_ID, POLICY_HASH)

    second = GatewayLedger(state_path=state, gateway_id="gw-a")
    assert second.sandbox_id("default", "s1") == SANDBOX_ID
    assert second.sandbox_id("lab", "s1") == OTHER_ID
    assert second.policy_hash(SANDBOX_ID) == POLICY_HASH and second.policy_hash(OTHER_ID) == ""
    assert second.sandboxes() == first.sandboxes() == [
        {"workspace": "default", "name": "s1", "id": SANDBOX_ID,
         "effective_policy_hash": POLICY_HASH},
        {"workspace": "lab", "name": "s1", "id": OTHER_ID, "effective_policy_hash": ""},
    ]


def test_a_governed_update_after_a_restart_reports_its_projection(state, reports):
    """Before the state file, the restarted sidecar decided this update by
    name and reported no projection, so the engine never learned the hash."""
    before = GatewayLedger(state_path=state, gateway_id="gw-a")
    sidecar.handle_evaluate(_call("post_commit", CREATED, "CreateSandbox"), decide=_Engine(),
                            ledger=before)

    after, engine = GatewayLedger(state_path=state, gateway_id="gw-a"), _Engine(SECOND)
    _governed_update(after, engine, SECOND)

    assert engine.requests[0]["target"] == f"openshell:gw-a:{SANDBOX_ID}"
    assert reports == [{"sandbox_id": SANDBOX_ID, "policy_hash": POLICY_HASH,
                        "decision_id": SECOND, "method": "UpdateConfig"}]
    assert after.policy_hash(SANDBOX_ID) == POLICY_HASH


def test_without_a_state_file_a_restart_loses_the_name(reports):
    before = GatewayLedger(gateway_id="gw-a")
    sidecar.handle_evaluate(_call("post_commit", CREATED, "CreateSandbox"), decide=_Engine(),
                            ledger=before)
    after, engine = GatewayLedger(gateway_id="gw-a"), _Engine(SECOND)
    _governed_update(after, engine, SECOND)
    assert engine.requests[0]["target"] == "openshell:gw-a:name:default/s1"
    assert reports == []


def test_a_forgotten_sandbox_stays_forgotten_after_a_restart(state):
    first = GatewayLedger(state_path=state, gateway_id="gw-a")
    first.learn_sandbox("default", "s1", SANDBOX_ID)
    first.note_policy_hash(SANDBOX_ID, POLICY_HASH)
    first.forget_sandbox("default", "s1")
    assert first.policy_hash(SANDBOX_ID) == ""
    second = GatewayLedger(state_path=state, gateway_id="gw-a")
    assert second.sandboxes() == [] and second.policy_hash(SANDBOX_ID) == ""


def test_a_name_that_is_another_sandbox_now_does_not_keep_the_old_hash(state):
    ledger = GatewayLedger(state_path=state, gateway_id="gw-a")
    ledger.learn_sandbox("default", "s1", SANDBOX_ID)
    ledger.note_policy_hash(SANDBOX_ID, POLICY_HASH)
    ledger.learn_sandbox("default", "s1", OTHER_ID)
    assert ledger.sandboxes() == [{"workspace": "default", "name": "s1", "id": OTHER_ID,
                                   "effective_policy_hash": ""}]
    assert ledger.policy_hash(SANDBOX_ID) == ""


def test_a_hash_is_kept_only_for_a_sandbox_the_ledger_knows():
    ledger = GatewayLedger(gateway_id="gw-a")
    ledger.note_policy_hash("never-seen", POLICY_HASH)
    ledger.note_policy_hash("", POLICY_HASH)
    assert ledger.policy_hash("never-seen") == "" and ledger.revision == 0
    ledger.learn_sandbox("default", "s1", SANDBOX_ID)
    ledger.note_policy_hash(SANDBOX_ID, POLICY_HASH)
    # A write that reported no hash does not erase the one that is known.
    ledger.note_policy_hash(SANDBOX_ID, "")
    assert ledger.policy_hash(SANDBOX_ID) == POLICY_HASH


def test_the_state_file_holds_names_ids_and_hashes_and_nothing_else(state):
    ledger = GatewayLedger(state_path=state, gateway_id="gw-a")
    ledger.learn_sandbox("default", "s1", SANDBOX_ID)
    ledger.note_policy_hash(SANDBOX_ID, POLICY_HASH)
    ledger.remember(DECISION, method="UpdateConfig", digest="d" * 64, sandbox_id=SANDBOX_ID)
    with open(state, encoding="utf-8") as fh:
        document = json.load(fh)
    assert document == {"version": 1, "gateway_id": "gw-a", "complete": False, "sandboxes": [
        {"workspace": "default", "name": "s1", "id": SANDBOX_ID,
         "effective_policy_hash": POLICY_HASH}]}
    assert not os.path.exists(state + ".new")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_the_state_file_and_its_folder_are_the_owners_alone(state):
    previous = os.umask(0)
    try:
        ledger = GatewayLedger(state_path=state, gateway_id="gw-a")
        ledger.learn_sandbox("default", "s1", SANDBOX_ID)
        ledger.learn_sandbox("default", "s2", OTHER_ID)  # replaced, not reopened
    finally:
        os.umask(previous)
    assert stat.S_IMODE(os.stat(state).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(os.path.dirname(state)).st_mode) == 0o700


@pytest.mark.parametrize("content", [
    b"not json", b"[]",
    b'{"version": 2, "gateway_id": "gw-a", "complete": true, "sandboxes": '
    b'[{"workspace": "default", "name": "s1", "id": "from-a-later-format"}]}',
    b'{"version": 1, "gateway_id": "gw-other", "sandboxes": '
    b'[{"workspace": "default", "name": "s1", "id": "theirs"}]}',
    b"\xff\xfe",
])
def test_a_state_file_that_is_not_this_gateways_is_not_read(state, content):
    os.makedirs(os.path.dirname(state))
    with open(state, "wb") as fh:
        fh.write(content)
    ledger = GatewayLedger(state_path=state, gateway_id="gw-a")
    assert ledger.sandboxes() == [] and ledger.complete is False
    ledger.learn_sandbox("default", "s1", SANDBOX_ID)  # and the sidecar carries on
    assert GatewayLedger(state_path=state, gateway_id="gw-a").sandbox_id("default", "s1") == (
        SANDBOX_ID)


def test_entries_that_are_not_sandboxes_are_left_out(state):
    os.makedirs(os.path.dirname(state))
    with open(state, "w", encoding="utf-8") as fh:
        json.dump({"version": 1, "gateway_id": "gw-a", "complete": True, "sandboxes": [
            "s1", {"name": "s2"}, {"id": "x"}, {"name": 7, "id": "x"},
            {"name": "s1", "id": SANDBOX_ID, "effective_policy_hash": 12},
            {"workspace": "", "name": "s3", "id": OTHER_ID, "effective_policy_hash": "h"},
        ]}, fh)
    ledger = GatewayLedger(state_path=state, gateway_id="gw-a")
    assert ledger.sandboxes() == [
        {"workspace": "default", "name": "s1", "id": SANDBOX_ID, "effective_policy_hash": ""},
        {"workspace": "default", "name": "s3", "id": OTHER_ID, "effective_policy_hash": "h"}]
    assert ledger.complete is True


@pytest.mark.parametrize("stored, read", [(True, True), (False, False), ("yes", False),
                                          (1, False), (None, False)])
def test_complete_is_read_back_only_when_it_is_true(state, stored, read):
    os.makedirs(os.path.dirname(state))
    with open(state, "w", encoding="utf-8") as fh:
        json.dump({"version": 1, "gateway_id": "gw-a", "complete": stored, "sandboxes": [
            {"workspace": "default", "name": "s1", "id": SANDBOX_ID}]}, fh)
    assert GatewayLedger(state_path=state, gateway_id="gw-a").complete is read


def test_marking_the_ledger_complete_survives_a_restart(state):
    first = GatewayLedger(state_path=state, gateway_id="gw-a")
    first.learn_sandbox("default", "s1", SANDBOX_ID)
    assert GatewayLedger(state_path=state, gateway_id="gw-a").complete is False
    first.mark_complete()
    assert GatewayLedger(state_path=state, gateway_id="gw-a").complete is True


def test_a_state_file_that_cannot_be_written_costs_only_the_memory(tmp_path, caplog):
    blocker = tmp_path / "a-file"
    blocker.write_text("x")
    ledger = GatewayLedger(state_path=str(blocker / "state.json"), gateway_id="gw-a")
    with caplog.at_level("WARNING", logger="artzain.openshell.state"):
        ledger.learn_sandbox("default", "s1", SANDBOX_ID)
        ledger.learn_sandbox("default", "s2", OTHER_ID)
    assert ledger.sandbox_id("default", "s1") == SANDBOX_ID
    assert len([r for r in caplog.records if "state not written" in r.getMessage()]) == 1


def test_a_state_write_another_program_holds_up_is_not_lost(state, artzain_held_replace,
                                                              caplog):
    """Windows refuses the rename while another program has the state file
    open. It was given up at once, and the sandbox's name was not kept."""
    ledger = GatewayLedger(state_path=state, gateway_id="gw-a")
    ledger.learn_sandbox("default", "s0", OTHER_ID)
    refused = artzain_held_replace(3)
    with caplog.at_level("WARNING", logger="artzain.openshell.state"):
        ledger.learn_sandbox("default", "s1", SANDBOX_ID)
    assert GatewayLedger(state_path=state, gateway_id="gw-a").sandbox_id("default", "s1") == (
        SANDBOX_ID)
    assert len(refused) == 3 and "state not written" not in caplog.text
    assert os.listdir(os.path.dirname(state)) == ["gw-a.json"]


@pytest.mark.skipif(sys.platform != "win32", reason="Windows sharing rules")
def test_a_state_file_another_program_has_open_is_replaced_once_it_lets_go(state, monkeypatch):
    """No stand-in: a file opened with Python's ``open()`` on Windows cannot be
    renamed over until it is closed (seen 2 Oct 2026, a virus scanner reading
    the file a test had just written)."""
    ledger = GatewayLedger(state_path=state, gateway_id="gw-a")
    ledger.learn_sandbox("default", "s0", OTHER_ID)
    held = open(state, "rb")
    real, refused = os.replace, []

    def replace(source, target):
        try:
            real(source, target)
        except PermissionError:
            refused.append(target)
            held.close()  # the other program lets go
            raise

    monkeypatch.setattr(os, "replace", replace)
    try:
        ledger.learn_sandbox("default", "s1", SANDBOX_ID)
    finally:
        held.close()
    assert refused  # a virus scanner may refuse it again after the hold is gone
    assert GatewayLedger(state_path=state, gateway_id="gw-a").sandbox_id("default", "s1") == (
        SANDBOX_ID)


def test_the_revision_moves_only_when_something_changed():
    ledger = GatewayLedger(gateway_id="gw-a")
    assert ledger.revision == 0
    ledger.learn_sandbox("default", "s1", SANDBOX_ID)
    ledger.learn_sandbox("default", "s1", SANDBOX_ID)
    assert ledger.revision == 1
    ledger.note_policy_hash(SANDBOX_ID, POLICY_HASH)
    ledger.note_policy_hash(SANDBOX_ID, POLICY_HASH)
    assert ledger.revision == 2
    ledger.forget_sandbox("default", "never-there")
    assert ledger.revision == 2
    ledger.mark_complete()
    ledger.mark_complete()
    assert ledger.revision == 3
    ledger.forget_sandbox("default", "s1")
    assert ledger.revision == 4


def test_the_oldest_sandbox_goes_first_and_its_hash_with_it():
    ledger = GatewayLedger(gateway_id="gw-a", max_sandboxes=2)
    for n in range(3):
        ledger.learn_sandbox("default", f"s{n}", f"id{n}")
        ledger.note_policy_hash(f"id{n}", f"hash{n}")
    assert [entry["id"] for entry in ledger.sandboxes()] == ["id1", "id2"]
    assert ledger.policy_hash("id0") == ""


# ---------------------------------------------------------------------------
# What a committed write teaches the ledger
# ---------------------------------------------------------------------------


def test_a_committed_update_leaves_its_hash_in_the_ledger(reports):
    ledger, engine = GatewayLedger(gateway_id="gw-a"), _Engine()
    sidecar.handle_evaluate(_call("post_commit", CREATED, "CreateSandbox"), decide=engine,
                            ledger=ledger)
    assert ledger.sandboxes()[0]["effective_policy_hash"] == ""  # a create reports none
    _governed_update(ledger, engine)
    assert ledger.sandboxes() == [{"workspace": "default", "name": "s1", "id": SANDBOX_ID,
                                   "effective_policy_hash": POLICY_HASH}]


def test_an_allowed_delete_takes_the_sandbox_out_of_the_ledger():
    ledger = GatewayLedger(gateway_id="gw-a")
    ledger.learn_sandbox("default", "s1", SANDBOX_ID)
    out = sidecar.handle_evaluate(
        _call("validate", {"name": "s1", "workspaceScope": {"workspace": "default"}},
              "DeleteSandbox"), decide=_Engine(), ledger=ledger)
    assert out["allowed"] is True and ledger.sandboxes() == []


# ---------------------------------------------------------------------------
# The snapshot
# ---------------------------------------------------------------------------


def _ledger_with(*pairs, complete=False):
    ledger = GatewayLedger(gateway_id="gw-a")
    for name, sandbox_id, policy_hash in pairs:
        ledger.learn_sandbox("default", name, sandbox_id)
        ledger.note_policy_hash(sandbox_id, policy_hash)
    if complete:
        ledger.mark_complete()
    return ledger


def test_a_snapshot_of_what_the_sidecar_has_seen_is_partial():
    ledger = _ledger_with(("s1", SANDBOX_ID, POLICY_HASH), ("s2", OTHER_ID, ""))
    assert sidecar.snapshot(ledger) == {
        "gateway_id": "gw-a", "partial": True,
        "sandboxes": [
            {"id": SANDBOX_ID, "name": "s1", "phase": "", "command": "", "base_policy_hash": "",
             "effective_policy_hash": POLICY_HASH, "provider_profiles": []},
            {"id": OTHER_ID, "name": "s2", "phase": "", "command": "", "base_policy_hash": "",
             "effective_policy_hash": "", "provider_profiles": []},
        ]}


def test_a_snapshot_is_whole_once_the_ledger_is_complete():
    ledger = _ledger_with(("s1", SANDBOX_ID, POLICY_HASH), complete=True)
    assert sidecar.snapshot(ledger)["partial"] is False


def test_an_unknown_hash_is_sent_empty_and_never_guessed():
    current = sidecar.snapshot(_ledger_with(("s1", SANDBOX_ID, "")))
    assert current["sandboxes"][0]["effective_policy_hash"] == ""
    assert current["sandboxes"][0]["base_policy_hash"] == ""


def test_more_than_200_sandboxes_are_sent_as_the_first_200_partial():
    ledger = GatewayLedger(gateway_id="gw-a")
    for n in range(201):
        ledger.learn_sandbox("default", f"s{n}", f"id{n}")
    ledger.mark_complete()
    current = sidecar.snapshot(ledger)
    assert len(current["sandboxes"]) == 200 and current["partial"] is True
    assert current["sandboxes"][0]["id"] == "id0" and current["sandboxes"][-1]["id"] == "id199"


def test_a_listing_is_whole_and_replaces_what_the_ledger_held():
    ledger = _ledger_with(("s1", SANDBOX_ID, POLICY_HASH), ("gone", "id-gone", "h"))
    asked = []

    def lister(workspaces):
        asked.append(list(workspaces))
        return {"default": [{"id": SANDBOX_ID, "name": "s1", "phase": "Ready"},
                            {"id": OTHER_ID, "name": "older", "phase": "Provisioning"},
                            {"id": "", "name": "no-id", "phase": "Ready"}]}

    current = sidecar.snapshot(ledger, workspaces=["default"], lister=lister)
    assert asked == [["default"]]
    assert current["partial"] is False and "error" not in current
    assert [(e["id"], e["name"], e["phase"], e["effective_policy_hash"])
            for e in current["sandboxes"]] == [
        (SANDBOX_ID, "s1", "Ready", POLICY_HASH), (OTHER_ID, "older", "Provisioning", "")]
    # The listing fills the name -> uuid map, and what it does not list is gone.
    assert ledger.sandbox_id("default", "older") == OTHER_ID
    assert ledger.sandbox_id("default", "gone") == "" and ledger.policy_hash("id-gone") == ""
    # The same listing again changes nothing, so nothing is written again.
    revision = ledger.revision
    sidecar.snapshot(ledger, workspaces=["default"], lister=lister)
    assert ledger.revision == revision


def test_a_whole_snapshot_lists_only_the_workspaces_that_were_listed():
    ledger = _ledger_with(("s1", SANDBOX_ID, POLICY_HASH))
    ledger.learn_sandbox("lab", "x", OTHER_ID)
    current = sidecar.snapshot(
        ledger, workspaces=["default"],
        lister=lambda _ws: {"default": [{"id": SANDBOX_ID, "name": "s1", "phase": "Ready"}]})
    assert [e["id"] for e in current["sandboxes"]] == [SANDBOX_ID]
    assert ledger.sandbox_id("lab", "x") == OTHER_ID  # not listed is not forgotten


@pytest.mark.parametrize("failure, named", [
    (RuntimeError("gateway unreachable"), "RuntimeError"),
    (ImportError("no openshell"), "openshell_sdk_missing"),
])
def test_a_listing_that_fails_leaves_what_the_sidecar_has_seen_as_partial(failure, named):
    ledger = _ledger_with(("s1", SANDBOX_ID, POLICY_HASH), complete=True)

    def lister(_workspaces):
        raise failure

    current = sidecar.snapshot(ledger, workspaces=["default"], lister=lister)
    assert current["partial"] is False  # the ledger is complete without the listing
    assert current["error"] == named
    assert [e["id"] for e in current["sandboxes"]] == [SANDBOX_ID]
    incomplete = _ledger_with(("s1", SANDBOX_ID, POLICY_HASH))
    assert sidecar.snapshot(incomplete, workspaces=["default"], lister=lister)["partial"] is True


def test_the_listing_uses_the_operators_client_and_names_each_workspace(monkeypatch):
    """``SandboxClient()`` takes an endpoint and ``list_all()`` a workspace: the
    earlier inventory called both with nothing and failed on every read."""
    calls = []

    class Ref:
        def __init__(self, sandbox_id, name, phase):
            self.id, self.name = sandbox_id, name
            self.status = types.SimpleNamespace(phase=phase, current_policy_version=3)

    class SandboxClient:
        def __init__(self, endpoint):
            raise AssertionError("the client is built from the active cluster")

        @classmethod
        def from_active_cluster(cls):
            calls.append("from_active_cluster")
            return object.__new__(cls)

        def list_all(self, *, workspace):
            calls.append(("list_all", workspace))
            return [Ref(SANDBOX_ID, "s1", "Ready")] if workspace == "default" else []

    package = types.ModuleType("openshell")
    module = types.ModuleType("openshell.sandbox")
    module.SandboxClient = SandboxClient
    monkeypatch.setitem(sys.modules, "openshell", package)
    monkeypatch.setitem(sys.modules, "openshell.sandbox", module)

    assert sidecar.sdk_list(["default", "lab"]) == {
        "default": [{"id": SANDBOX_ID, "name": "s1", "phase": "Ready"}], "lab": []}
    assert calls == ["from_active_cluster", ("list_all", "default"), ("list_all", "lab")]


def test_listing_is_off_unless_workspaces_are_named(monkeypatch):
    assert sidecar.list_workspaces() == []
    monkeypatch.setenv("OPENSHELL_SIDECAR_LIST_WORKSPACES", " default, lab ,,default ")
    assert sidecar.list_workspaces() == ["default", "lab"]

    def never(_workspaces):
        raise AssertionError("not asked to list")

    monkeypatch.delenv("OPENSHELL_SIDECAR_LIST_WORKSPACES")
    assert sidecar.snapshot(_ledger_with(("s1", SANDBOX_ID, "")), lister=never)["partial"] is True


def test_the_inventory_route_calls_a_partial_snapshot_degraded(monkeypatch):
    monkeypatch.setattr(sidecar, "_LEDGER", _ledger_with(("s1", SANDBOX_ID, POLICY_HASH)))
    answer = sidecar.inventory()
    assert answer["gateway_id"] == "gw-a" and answer["degraded"] is True
    assert answer["error"] == "partial_inventory" and len(answer["sandboxes"]) == 1
    sidecar._LEDGER.mark_complete()
    assert sidecar.inventory() == {"gateway_id": "gw-a", "degraded": False,
                                   "sandboxes": answer["sandboxes"]}
    assert sidecar.sdk_inventory is sidecar.inventory


# ---------------------------------------------------------------------------
# The heartbeat's numbers
# ---------------------------------------------------------------------------


def test_latency_percentiles_are_nearest_rank():
    window = sidecar.LatencyWindow(size=4)
    assert window.percentile(0.5) is None
    window.add(10.4)
    assert (window.percentile(0.5), window.percentile(0.95)) == (10, 10)
    for value in (20, 30, 40, 50):  # the first sample falls out of a window of four
        window.add(value)
    assert (window.percentile(0.5), window.percentile(0.95)) == (30, 50)
    window.add(-5)
    assert window.percentile(0.01) == 0


def test_a_decision_round_trip_is_timed(monkeypatch):
    monkeypatch.setenv("ARTZAIN_DECISION_URL", "https://engine.example")
    monkeypatch.setattr(sidecar, "_post_engine",
                        lambda *a, **k: {"outcome": "allow", "decision_id": DECISION})
    sidecar.http_decide({"request_id": "r"})
    assert sidecar._LATENCY.percentile(0.5) is not None

    def down(*_a, **_k):
        raise TimeoutError("slow")

    fresh = sidecar.LatencyWindow()
    monkeypatch.setattr(sidecar, "_LATENCY", fresh)
    monkeypatch.setattr(sidecar, "_post_engine", down)
    assert sidecar.http_decide({"request_id": "r"})["outcome"] == "deny"
    assert fresh.percentile(0.5) is None  # a call that got no answer is not a round trip


def test_a_projection_report_that_fails_is_counted(monkeypatch):
    monkeypatch.setenv("ARTZAIN_DECISION_URL", "https://engine.example")

    def down(*_a, **_k):
        raise ConnectionError("down")

    monkeypatch.setattr(sidecar, "_post_engine", down)
    assert sidecar.http_report_projection({"sandbox_id": "s"}) is False
    assert sidecar._UNDELIVERED.value == 1


# ---------------------------------------------------------------------------
# The reporter
# ---------------------------------------------------------------------------


class _Wire:
    """The engine as the reporter sees it, and a clock the test moves."""

    def __init__(self):
        self.now = 1000.0
        self.posts = []
        self.fail = set()
        self.answers = {}

    def clock(self):
        return self.now

    def post(self, path, payload):
        name = path.rsplit("/", 1)[-1]
        self.posts.append((name, copy.deepcopy(payload)))
        if name in self.fail:
            raise ConnectionError("down")
        return self.answers.get(name, {})

    def sent(self, name=None):
        return [post for post in self.posts if name in (None, post[0])]

    def names(self):
        return [name for name, _payload in self.posts]


@pytest.fixture
def wire():
    return _Wire()


def _reporter(wire, ledger=None):
    return sidecar.Reporter(ledger or GatewayLedger(gateway_id="gw-a"), post=wire.post,
                            clock=wire.clock, latency=sidecar.LatencyWindow(),
                            undelivered=sidecar.Counter())


def test_the_first_turn_sends_a_heartbeat_and_the_inventory(wire):
    ledger = _ledger_with(("s1", SANDBOX_ID, POLICY_HASH))
    reporter = _reporter(wire, ledger)
    wait = reporter.step()
    assert wire.names() == ["heartbeat", "inventory"]
    assert wire.sent("inventory")[0][1] == {
        "sandboxes": sidecar.snapshot(ledger)["sandboxes"], "partial": True}
    assert wait == 60.0


def test_a_heartbeat_goes_every_minute_and_the_inventory_every_five(wire):
    reporter = _reporter(wire)
    reporter.step()
    for second in range(1, 601):
        wire.now = 1000.0 + second
        reporter.step()
    assert wire.names().count("heartbeat") == 11   # at 0, 60, ... 600
    assert wire.names().count("inventory") == 3    # at 0, 300, 600


def test_a_change_sends_the_inventory_a_few_seconds_later(wire):
    ledger = GatewayLedger(gateway_id="gw-a")
    reporter = _reporter(wire, ledger)
    reporter.step()
    wire.now += 20
    ledger.learn_sandbox("default", "s1", SANDBOX_ID)
    assert reporter.step() == 5.0 and wire.names().count("inventory") == 1
    wire.now += 3
    ledger.note_policy_hash(SANDBOX_ID, POLICY_HASH)  # a burst is one snapshot
    reporter.step()
    assert wire.names().count("inventory") == 1
    wire.now += 2
    reporter.step()
    assert wire.names().count("inventory") == 2
    assert wire.sent("inventory")[-1][1]["sandboxes"][0]["effective_policy_hash"] == POLICY_HASH
    wire.now += 30
    reporter.step()
    assert wire.names().count("inventory") == 2  # nothing changed since


def test_the_heartbeat_says_what_is_running(wire, monkeypatch):
    monkeypatch.setenv("OPENSHELL_REGISTRATION_DIGEST", "AB" * 32)
    monkeypatch.setattr(sidecar, "_openshell_version", lambda: "0.1.2")
    reporter = _reporter(wire)
    reporter._latency.add(40)
    reporter._latency.add(180)
    reporter.step()
    assert wire.sent("heartbeat")[0][1] == {
        "sidecar_version": artzain.__version__, "openshell_version": "0.1.2",
        "registration_digest": "ab" * 32, "decide_p50_ms": 40, "decide_p95_ms": 180,
        "undelivered_reports": 0}


def test_a_heartbeat_leaves_out_what_it_does_not_know(wire, monkeypatch):
    monkeypatch.setenv("OPENSHELL_REGISTRATION_DIGEST", "not a digest")
    monkeypatch.setattr(sidecar, "_openshell_version", lambda: "")
    reporter = _reporter(wire)
    reporter.step()
    assert wire.sent("heartbeat")[0][1] == {"sidecar_version": artzain.__version__,
                                            "undelivered_reports": 0}


@pytest.fixture
def gateway_binary(monkeypatch):
    """``openshell-gateway`` on this host's PATH, answering as the test says.

    The installed OpenShell SDK says 0.1.2; the ``[openshell]`` extra does not
    install it, so on a connected gateway it is usually not there at all."""
    said = {"path": "/usr/bin/openshell-gateway", "stdout": "openshell-gateway 0.1.3\n",
            "stderr": "", "code": 0, "raises": None, "runs": []}

    def which(name):
        return said["path"] if name == "openshell-gateway" else None

    def run(argv, **kwargs):
        said["runs"].append((argv, kwargs))
        if said["raises"] is not None:
            raise said["raises"]
        return sidecar.subprocess.CompletedProcess(argv, said["code"], stdout=said["stdout"],
                                                   stderr=said["stderr"])

    monkeypatch.setattr(sidecar.shutil, "which", which)
    monkeypatch.setattr(sidecar.subprocess, "run", run)
    monkeypatch.setattr(sidecar, "_sdk_openshell_version", lambda: "0.1.2")
    monkeypatch.setitem(sidecar._gateway_version, "at", None)
    monkeypatch.setitem(sidecar._gateway_version, "value", "")
    return said


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_the_heartbeat_reports_the_gateways_own_version(gateway_binary, stream):
    """The engine tells a gateway's owner about OpenShell advisories by the
    version the heartbeat reports, so it is the gateway's, not the SDK's."""
    gateway_binary["stdout"] = ""
    gateway_binary[stream] = "openshell-gateway 0.1.3 (abc1234)\n"
    assert sidecar._openshell_version() == "0.1.3"
    [(argv, kwargs)] = gateway_binary["runs"]
    assert argv == ["/usr/bin/openshell-gateway", "--version"]
    assert kwargs.get("timeout") and not kwargs.get("shell")


def test_without_the_gateways_binary_the_sdk_version_is_reported(gateway_binary, monkeypatch):
    gateway_binary["path"] = None
    assert sidecar._openshell_version() == "0.1.2"
    assert gateway_binary["runs"] == []
    monkeypatch.setitem(sidecar._gateway_version, "at", None)
    monkeypatch.setattr(sidecar, "_sdk_openshell_version", lambda: "")
    assert sidecar._openshell_version() == ""


@pytest.mark.parametrize("how", ["exit 1", "no version", "timeout", "cannot run"])
def test_a_gateway_that_does_not_say_falls_back_to_the_sdk(gateway_binary, how):
    if how == "exit 1":
        gateway_binary["code"] = 1
    elif how == "no version":
        gateway_binary["stdout"] = "openshell-gateway (development build)\n"
    elif how == "timeout":
        gateway_binary["raises"] = sidecar.subprocess.TimeoutExpired("openshell-gateway", 10)
    else:
        gateway_binary["raises"] = PermissionError("not executable")
    assert sidecar._openshell_version() == "0.1.2"


def test_the_gateways_version_is_asked_again_after_ten_minutes(gateway_binary, monkeypatch):
    """The package can be upgraded under a running sidecar: the heartbeat
    catches up within ten minutes, without a command a minute."""
    clock = {"now": 1000.0}
    monkeypatch.setattr(sidecar.time, "monotonic", lambda: clock["now"])
    assert sidecar._openshell_version() == "0.1.3"
    gateway_binary["stdout"] = "openshell-gateway 0.1.4\n"
    clock["now"] += sidecar.GATEWAY_VERSION_SECONDS - 1
    assert sidecar._openshell_version() == "0.1.3"
    assert len(gateway_binary["runs"]) == 1
    clock["now"] += 1
    assert sidecar._openshell_version() == "0.1.4"
    assert len(gateway_binary["runs"]) == 2
    assert sidecar.GATEWAY_VERSION_SECONDS == 600


def test_a_failed_ask_is_kept_as_long_as_an_answer(gateway_binary, monkeypatch):
    clock = {"now": 1000.0}
    monkeypatch.setattr(sidecar.time, "monotonic", lambda: clock["now"])
    gateway_binary["code"] = 1
    assert sidecar._openshell_version() == "0.1.2"
    gateway_binary["code"] = 0
    clock["now"] += 60
    assert sidecar._openshell_version() == "0.1.2"
    assert len(gateway_binary["runs"]) == 1


def test_failed_reports_are_counted_until_a_heartbeat_gets_through(wire):
    reporter = _reporter(wire)
    wire.fail = {"heartbeat", "inventory"}
    reporter.step()                      # both fail; the inventory is counted
    reporter._undelivered.add()          # and a projection report failed too
    wire.now += 60
    reporter.step()                      # the heartbeat fails again
    assert [p["undelivered_reports"] for _n, p in wire.sent("heartbeat")] == [0, 2]
    wire.fail = set()
    wire.now += 60
    reporter.step()
    assert wire.sent("heartbeat")[-1][1]["undelivered_reports"] == 2
    wire.now += 60
    reporter.step()
    assert wire.sent("heartbeat")[-1][1]["undelivered_reports"] == 0


def test_a_failed_report_waits_for_its_next_turn(wire):
    reporter = _reporter(wire)
    wire.fail = {"heartbeat", "inventory"}
    assert reporter.step() == 60.0
    wire.now += 30
    reporter.step()
    assert wire.names() == ["heartbeat", "inventory"]  # not retried in between


def test_the_engine_may_ask_for_another_interval_within_bounds(wire):
    wire.answers = {"heartbeat": {"next_heartbeat_seconds": 120},
                    "inventory": {"next_inventory_seconds": 5}}
    reporter = _reporter(wire)
    assert reporter.step() == 30.0       # the inventory's 5 s is held to 30 s
    wire.now += 30
    reporter.step()
    assert wire.names() == ["heartbeat", "inventory", "inventory"]
    wire.now += 60                       # a minute in: the engine asked for two
    reporter.step()
    assert wire.names().count("heartbeat") == 1
    wire.now += 30
    reporter.step()
    assert wire.names().count("heartbeat") == 2
    for bad in ({"next_heartbeat_seconds": "soon"}, {"next_heartbeat_seconds": True}, []):
        assert sidecar._interval(bad, "next_heartbeat_seconds", 60.0) == 60.0
    assert sidecar._interval({"n": 99999}, "n", 60.0) == 3600.0


def test_a_listing_made_for_the_inventory_is_not_a_change_to_send_again(wire, monkeypatch):
    ledger = GatewayLedger(gateway_id="gw-a")
    reporter = sidecar.Reporter(
        ledger, post=wire.post, clock=wire.clock, latency=sidecar.LatencyWindow(),
        undelivered=sidecar.Counter(),
        lister=lambda _ws: {"default": [{"id": SANDBOX_ID, "name": "s1", "phase": "Ready"}]})
    monkeypatch.setenv("OPENSHELL_SIDECAR_LIST_WORKSPACES", "default")
    reporter.step()
    assert wire.sent("inventory")[0][1]["partial"] is False
    for _ in range(3):
        wire.now += 10
        reporter.step()
    assert wire.names().count("inventory") == 1


def test_the_loop_stops_when_asked_and_survives_a_bad_turn(wire, monkeypatch):
    import threading

    reporter = _reporter(wire)
    turns = []

    def step():
        turns.append(1)
        if len(turns) == 1:
            raise RuntimeError("a bad turn")
        stop.set()
        return 60.0

    stop = threading.Event()
    monkeypatch.setattr(reporter, "step", step)
    monkeypatch.setattr(sidecar, "INVENTORY_CHANGE_DELAY_SECONDS", 0.01)
    thread = threading.Thread(target=reporter.run, args=(stop,))
    thread.start()
    thread.join(timeout=10)
    assert not thread.is_alive() and len(turns) == 2


def test_reports_are_sent_only_with_a_gateway_credential(monkeypatch):
    ledger = GatewayLedger(gateway_id="gw-a")
    assert sidecar.reporter_for_environment(ledger) is None  # no engine URL
    monkeypatch.setenv("ARTZAIN_DECISION_URL", "https://engine.example/api/v1/decisions")
    assert isinstance(sidecar.reporter_for_environment(ledger), sidecar.Reporter)
    monkeypatch.setenv("COGNEXUS_API_KEY", "cnx_an_account_key")
    assert sidecar.reporter_for_environment(ledger) is None


def test_the_engine_call_keeps_the_deadline_it_is_given(monkeypatch):
    waits = []

    class Client:
        def request(self, method, target, *, headers, body=None, deadline,
                    retry_on_reset=False):
            waits.append(deadline - time.monotonic())
            assert (method, body, headers["Content-Type"]) == (
                "POST", b"{}", "application/json")
            return 200, {}, b"{}"

    monkeypatch.setattr(sidecar, "_client", lambda: Client())
    monkeypatch.setenv("OPENSHELL_SIDECAR_DECIDE_TIMEOUT_MS", "1200")
    sidecar._post_engine("https://engine.example/x", "k", {}, retry_on_reset=False)
    sidecar._post_engine("https://engine.example/x", "k", {}, retry_on_reset=False,
                         timeout=10.0)
    assert 1.0 < waits[0] <= 1.2 and 9.0 < waits[1] <= 10.0


def test_a_report_goes_to_the_engine_with_its_own_deadline(monkeypatch):
    monkeypatch.setenv("ARTZAIN_DECISION_URL", "https://engine.example/api/v1/decisions")
    seen = {}

    def post(target, key, payload, *, retry_on_reset, timeout=None):
        seen.update(target=target, key=key, retry=retry_on_reset, timeout=timeout)
        return {"ok": True}

    monkeypatch.setattr(sidecar, "_post_engine", post)
    assert sidecar._report("/api/v1/openshell/heartbeat", {}) == {"ok": True}
    assert seen == {"target": "https://engine.example/api/v1/openshell/heartbeat",
                    "key": "cnxg_sidecar_test_credential", "retry": False, "timeout": 10.0}
    monkeypatch.delenv("ARTZAIN_DECISION_URL")
    with pytest.raises(RuntimeError):
        sidecar._report("/api/v1/openshell/heartbeat", {})
