"""The sidecar cites an approved review when the same write runs again.

When ArtzAIn answers ``review`` for a gateway write, the write is refused
until an operator approves it in the Review Queue. The sidecar remembers the
review's decision id for that exact write (action, target and payload), and
when the operator runs the same write again it sends
``context.cites_review``: the engine releases a write its approved review is
bound to, and refuses it while the review is pending or after it was denied.

* An approval releases one retry: once a citing write is allowed, the
  sidecar forgets the review, and the same write later is decided afresh.
* A refused citation is kept, and the refusal says the review has not
  released the write; the record expires after a day.
* Nothing is cited without a ledger, and a different write cites nothing.
"""

from __future__ import annotations

import json

import pytest

from artzain.openshell import interceptor, sidecar
from artzain.openshell.interceptor import OperationLedger
from artzain.openshell.state import GatewayLedger

PROPOSALS = {"settingKey": "agent_policy_proposals_enabled", "global": True,
             "settingValue": {"boolValue": True}}
REVIEW_ID = "01KRVW00000000000000000000"
LATER_ID = "01KNEXTDENY000000000000000"


class _Engine:
    """Answers each decision in turn from *outcomes*, and records what it was sent."""

    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)
        self.sent = []

    def __call__(self, payload):
        self.sent.append(dict(payload))
        outcome, decision_id = self.outcomes.pop(0)
        return {"outcome": outcome, "decision_id": decision_id, "status_code": 200}


def _run(engine, ledger, body=None, *, method="UpdateConfig", phase="validate"):
    return interceptor.evaluate(
        {"method": f"openshell.v1.OpenShell/{method}", "phase": phase,
         "body": body if body is not None else dict(PROPOSALS), "gateway_id": "gw-a"},
        decide=engine, ledger=ledger)


def _cited(sent):
    return (sent.get("context") or {}).get("cites_review")


class _Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def test_a_reviewed_write_cites_its_review_when_it_runs_again():
    ledger = OperationLedger()
    engine = _Engine(("review", REVIEW_ID), ("allow", LATER_ID))
    first = _run(engine, ledger)
    assert first["allowed"] is False and first["reason"] == f"decision review ({REVIEW_ID})"
    assert "context" not in engine.sent[0]
    again = _run(engine, ledger)
    assert again["allowed"] is True
    assert _cited(engine.sent[1]) == REVIEW_ID
    # The same write, as the engine checks it: everything but the context.
    first_sent, second_sent = engine.sent
    for field in ("agent_did", "action", "target", "payload", "surface", "payload_kind"):
        assert first_sent[field] == second_sent[field], field


def test_an_approval_releases_one_retry():
    ledger = OperationLedger()
    engine = _Engine(("review", REVIEW_ID), ("allow", LATER_ID), ("review", "01KNEXT0000000000000000000"))
    _run(engine, ledger)
    assert _run(engine, ledger)["allowed"] is True
    _run(engine, ledger)
    assert _cited(engine.sent[2]) is None  # decided afresh: a new review, not the old one


def test_a_refused_citation_is_kept_and_the_refusal_says_why():
    ledger = OperationLedger()
    engine = _Engine(("review", REVIEW_ID), ("deny", LATER_ID), ("allow", "01KTHIRD000000000000000000"))
    _run(engine, ledger)
    refused = _run(engine, ledger)
    assert refused["allowed"] is False
    assert refused["reason"] == (f"decision deny ({LATER_ID}); review {REVIEW_ID} has not "
                                 "released this write")
    assert refused["log_annotations"] == {"decision_id": LATER_ID}
    # Still pending, say: the next run cites it again, and goes through once approved.
    assert _run(engine, ledger)["allowed"] is True
    assert _cited(engine.sent[2]) == REVIEW_ID


def test_a_different_write_cites_nothing():
    ledger = OperationLedger()
    engine = _Engine(("review", REVIEW_ID), ("review", LATER_ID), ("review", "01KTHIRD000000000000000000"))
    _run(engine, ledger)
    _run(engine, ledger, {**PROPOSALS, "settingValue": {"stringValue": "true"}})
    _run(engine, ledger, {**PROPOSALS, "settingKey": "ocsf_json_enabled"})
    assert [_cited(s) for s in engine.sent] == [None, None, None]


def test_without_a_ledger_nothing_is_cited():
    engine = _Engine(("review", REVIEW_ID), ("review", LATER_ID))
    _run(engine, None)
    _run(engine, None)
    assert _cited(engine.sent[1]) is None


def test_a_review_is_remembered_for_a_day():
    clock = _Clock()
    ledger = OperationLedger(now=clock)
    engine = _Engine(("review", REVIEW_ID), ("deny", LATER_ID), ("review", "01KTHIRD000000000000000000"))
    _run(engine, ledger)
    clock.t += 86_399
    _run(engine, ledger)
    assert _cited(engine.sent[1]) == REVIEW_ID
    clock.t += 2
    _run(engine, ledger)
    assert _cited(engine.sent[2]) is None


def test_the_reviews_remembered_are_bounded():
    ledger = OperationLedger(max_reviews=2)
    outcomes = [("review", f"01KREV{i:020d}") for i in range(3)] + [("review", LATER_ID)] * 3
    engine = _Engine(*outcomes)
    for value in ("a", "b", "c"):
        _run(engine, ledger, {**PROPOSALS, "settingValue": {"stringValue": value}})
    # Newest first: each run opens a review of its own, which would push out
    # an older one before it is checked.
    for value in ("c", "b", "a"):
        _run(engine, ledger, {**PROPOSALS, "settingValue": {"stringValue": value}})
    assert [_cited(s) for s in engine.sent[3:]] == ["01KREV00000000000000000002",
                                                   "01KREV00000000000000000001", None]


def test_a_review_without_a_decision_id_is_not_remembered():
    ledger = OperationLedger()
    engine = _Engine(("review", ""), ("review", LATER_ID))
    assert _run(engine, ledger)["reason"] == "decision review"
    _run(engine, ledger)
    assert _cited(engine.sent[1]) is None


def test_a_sandbox_write_decided_in_modify_operation_cites_too():
    ledger = OperationLedger()
    body = {"settingKey": "agent_policy_proposals_enabled", "sandbox": "s1",
            "workspaceScope": {"workspace": "default"}, "settingValue": {"boolValue": True}}
    engine = _Engine(("review", REVIEW_ID), ("allow", LATER_ID))
    assert _run(engine, ledger, body, phase="modify_operation")["allowed"] is False
    assert _run(engine, ledger, body, phase="modify_operation")["allowed"] is True
    assert _cited(engine.sent[1]) == REVIEW_ID


def test_the_sidecar_cites_through_its_own_ledger(monkeypatch):
    monkeypatch.setenv("OPENSHELL_GATEWAY_ID", "gw-a")
    monkeypatch.setattr(sidecar, "_LEDGER", GatewayLedger(gateway_id="gw-a"))
    monkeypatch.setattr(sidecar, "_BASE", None)
    engine = _Engine(("review", REVIEW_ID), ("allow", LATER_ID))
    request = {"method": "openshell.v1.OpenShell/UpdateConfig", "phase": "validate",
               "body": dict(PROPOSALS)}
    assert sidecar.handle_evaluate(dict(request), decide=engine)["allowed"] is False
    assert sidecar.handle_evaluate(dict(request), decide=engine)["allowed"] is True
    assert _cited(engine.sent[1]) == REVIEW_ID
    assert json.loads(engine.sent[1]["payload"])["setting_key"] == "agent_policy_proposals_enabled"


def test_the_refusal_still_names_its_decision_for_the_connect_command():
    """``artzain connect openshell`` reads the decision id out of a refusal."""
    from artzain.openshell import connect

    ledger = OperationLedger()
    engine = _Engine(("review", REVIEW_ID), ("deny", LATER_ID))
    _run(engine, ledger)
    reason = _run(engine, ledger)["reason"]
    assert connect._DECISION_ID.search(reason).group(1) == LATER_ID


@pytest.mark.parametrize("outcome", ["deny", "review"])
def test_an_ordinary_refusal_reads_as_before(outcome):
    engine = _Engine((outcome, REVIEW_ID))
    assert _run(engine, OperationLedger())["reason"] == f"decision {outcome} ({REVIEW_ID})"
