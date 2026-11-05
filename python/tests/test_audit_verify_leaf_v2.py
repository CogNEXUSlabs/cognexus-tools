"""Leaf version 2 signs the lineage fields. Version 1 leaves still verify.

A version 1 body is the frozen field set. A version 2 body adds
``leaf_version`` and the lineage fields. Changing any of those fields
changes the hash the verifier recomputes, so the leaf fails.
"""

from __future__ import annotations

import hashlib
import json

from artzain.audit_verify import _LEAF_BODY_FIELDS, _leaf_hash

_LINEAGE = (
    "parent_decision_ids",
    "session_id",
    "trace_id",
    "span_id",
    "tool_call_id",
    "on_behalf_of",
    "model_id",
    "approver_did",
    "surface",
    "product",
    "payload_kind",
)


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _v1() -> dict:
    return {
        "leaf_id": "L" + "0" * 25,
        "decision_id": "D" + "0" * 25,
        "created_at": "2026-11-04T00:00:00+00:00",
        "user_id": 1,
        "team_id": None,
        "agent_did": "agent-x",
        "action": "send_email",
        "target": "crm:1",
        "outcome": "allow",
        "payload_sha256": "a" * 64,
        "votes": [],
        "bundle_version": "builtin:v0",
        "resolution": "builtin/strict-v0",
        "prev_leaf_hash": "0" * 64,
    }


def _v2() -> dict:
    body = dict(_v1())
    body["leaf_version"] = 2
    body["parent_decision_ids"] = ["01PARENTDECISION00000000000"]
    body["session_id"] = "sess-1"
    body["trace_id"] = "a" * 32
    body["span_id"] = "b" * 16
    body["tool_call_id"] = "call-1"
    body["on_behalf_of"] = "alice"
    body["model_id"] = "model-a"
    body["approver_did"] = "reviewer:7"
    body["surface"] = "sdk"
    body["product"] = "morestore@1"
    body["payload_kind"] = "tool_call"
    return body


def test_a_v1_leaf_still_hashes_the_frozen_field_set():
    record = _v1()
    record["product"] = "morestore@1"
    record["leaf_version"] = 1
    assert set(_v1()) == set(_LEAF_BODY_FIELDS)
    assert _leaf_hash(record) == hashlib.sha256(_canonical(_v1())).hexdigest()


def test_a_v2_leaf_hashes_the_lineage_fields():
    body = _v2()
    assert _leaf_hash(body) == hashlib.sha256(_canonical(body)).hexdigest()


def test_changing_any_lineage_field_breaks_the_v2_hash():
    original = _leaf_hash(_v2())
    for key in _LINEAGE:
        changed = _v2()
        if key == "parent_decision_ids":
            changed[key] = ["01OTHERDECISION000000000000"]
        else:
            changed[key] = changed[key] + "-x"
        assert _leaf_hash(changed) != original, key
