"""The verifier's Evidence Root pin and its published record move together.

``security/evidence_root.json`` is publication channel 1 of the root's
fingerprint (ceremony runbook, section 4). The pin the verifier ships is a
literal in ``artzain.audit_verify``. Nothing read the file, so a pin could
land with no published record beside it, or the record could say one key
while the verifier pinned another. These checks close both: while the file
is absent nothing is pinned, and once it exists it is consistent with itself
and its fingerprint is one the verifier pins.

The file lives at the engine repository's root. A checkout without that root
(the public mirror, an unpacked sdist) has no record to compare and skips.
The rule itself, ``record_problems``, is exercised below with made-up
values; the ``TEST`` key used there is a throwaway and not a real root.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Optional

import pytest

import artzain.audit_verify as av

_REPO = Path(__file__).resolve().parents[2]
_RECORD = _REPO / "security" / "evidence_root.json"
_IN_ENGINE_REPO = (_REPO / "application" / "security").is_dir() and (
    _REPO / "pypi-package" / "src" / "artzain").is_dir()

_BOOTSTRAP_STATUS = "bootstrap root, to be retired by a hardware ceremony"


def record_problems(record: Optional[dict[str, Any]], current: Optional[str],
                    pinned: tuple[str, ...]) -> list[str]:
    """Why *record* (``None`` when the file is absent) and the pins disagree."""
    if record is None:
        if current is not None or pinned:
            return ["a fingerprint is pinned but security/evidence_root.json does not exist"]
        return []
    problems: list[str] = []
    public_key = record.get("public_key") or ""
    fingerprint = record.get("fingerprint") or ""
    if record.get("format") != "cognexus-evidence-root":
        problems.append("format is not cognexus-evidence-root")
    if "PRIVATE KEY" in json.dumps(record):
        problems.append("the record holds a private key")
    if av._canonical_pem(public_key) != public_key:
        problems.append("public_key is not in canonical PEM form")
    if hashlib.sha256(public_key.encode("ascii", "replace")).hexdigest() != fingerprint:
        problems.append("fingerprint is not the SHA-256 of public_key")
    if record.get("key_id") != fingerprint[:16]:
        problems.append("key_id is not the first 16 hex of the fingerprint")
    if fingerprint not in pinned:
        problems.append("the record's fingerprint is not one the verifier pins")
    if (pinned[-1] if pinned else None) != current:
        problems.append("the current pin is not the last entry of the pinned set")
    if record.get("custody") == "software" and (
            record.get("status") != _BOOTSTRAP_STATUS
            or not record.get("hardware_ceremony_target")):
        problems.append("a software root's record lacks the bootstrap label or its target date")
    return problems


@pytest.mark.skipif(not _IN_ENGINE_REPO, reason="not the engine repository: no record to compare")
def test_the_pin_and_the_published_record_agree():
    record = json.loads(_RECORD.read_text(encoding="utf-8")) if _RECORD.exists() else None
    assert record_problems(record, av.EVIDENCE_ROOT_FINGERPRINT,
                           tuple(av.EVIDENCE_ROOT_FINGERPRINTS)) == []


# ---------------------------------------------------------------------------
# The rule, against made-up values
# ---------------------------------------------------------------------------

#: TEST key, generated for this file and used nowhere else. Not a root.
_TEST_PEM = ("-----BEGIN PUBLIC KEY-----\n"
             "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n"
             "-----END PUBLIC KEY-----\n")
_TEST_FP = hashlib.sha256(_TEST_PEM.encode("ascii")).hexdigest()


def _record(**changes: Any) -> dict[str, Any]:
    base = {"format": "cognexus-evidence-root", "format_version": 1, "algorithm": "ed25519",
            "fingerprint": _TEST_FP, "key_id": _TEST_FP[:16], "public_key": _TEST_PEM,
            "ceremony_date": "2026-11-15"}
    base.update(changes)
    return base


def test_nothing_pinned_and_no_record_is_consistent():
    assert record_problems(None, None, ()) == []


def test_a_record_with_its_fingerprint_pinned_is_consistent():
    assert record_problems(_record(), _TEST_FP, (_TEST_FP,)) == []
    labelled = _record(custody="software", status=_BOOTSTRAP_STATUS,
                       hardware_ceremony_target="2027-02-15")
    assert record_problems(labelled, _TEST_FP, (_TEST_FP,)) == []


def test_a_retired_root_keeps_its_place_before_the_current_pin():
    newer = "ab" * 32
    assert record_problems(_record(), newer, (_TEST_FP, newer)) == []


@pytest.mark.parametrize("record, current, pinned, expected", [
    (None, _TEST_FP, (_TEST_FP,), "does not exist"),
    (None, None, (_TEST_FP,), "does not exist"),
    (_record(), None, (), "not one the verifier pins"),
    (_record(), "cd" * 32, ("cd" * 32,), "not one the verifier pins"),
    (_record(fingerprint="ef" * 32, key_id="ef" * 8), "ef" * 32, ("ef" * 32,),
     "not the SHA-256 of public_key"),
    (_record(key_id="0" * 16), _TEST_FP, (_TEST_FP,), "key_id"),
    (_record(public_key=_TEST_PEM.replace("\n", "\r\n")), _TEST_FP, (_TEST_FP,), "canonical"),
    (_record(format="something-else"), _TEST_FP, (_TEST_FP,), "format"),
    (_record(), None, (_TEST_FP,), "last entry"),
    (_record(custody="software"), _TEST_FP, (_TEST_FP,), "bootstrap label"),
    (_record(custody="software", status=_BOOTSTRAP_STATUS), _TEST_FP, (_TEST_FP,),
     "bootstrap label"),
    (_record(note="-----BEGIN PRIVATE KEY-----"), _TEST_FP, (_TEST_FP,), "private key"),
])
def test_each_way_the_pin_and_the_record_can_drift_is_named(record, current, pinned, expected):
    assert any(expected in problem for problem in record_problems(record, current, pinned))
