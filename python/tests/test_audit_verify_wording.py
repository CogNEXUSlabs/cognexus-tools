"""What ``artzain audit verify`` says under its verdict, and how it labels a
warning (auditor journey plan, WP 2.5; decision D8, approved 13 November
2026).

The verdict line keeps its machine-read token (``VERIFIED, SELF-ATTESTED``)
and its text. Under it, one line says in plain words what held, and one says
what the keys are tied to. Each warning on the text path starts
``Expected:`` (what a filtered export always shows) or ``Check:`` (something
to act on); one this release does not know reads ``Check:``. The result's
``warnings`` and the ``--json`` output keep the warning text as it was, so a
script that reads them sees no change.
"""

from __future__ import annotations

import contextlib
import io
import json

import pytest

import artzain.audit_verify as av
from artzain import cli
from artzain.audit_verify import VerifyResult, warning_label

_HELD = "Every entry matches its hash and links to the one before, and each seal covers its entries."
_SELF = ("The signatures check against keys in this bundle; nothing yet ties those keys to the "
         "CogNEXUS Labs Evidence Root.")


def _run(monkeypatch, result: VerifyResult, *argv):
    monkeypatch.setattr(av, "verify_bundle", lambda *a, **k: result)
    out = io.StringIO()
    with contextlib.redirect_stdout(out), pytest.raises(SystemExit) as exit_:
        cli.main(["audit", "verify", "b.zip", *argv])
    return exit_.value.code, out.getvalue().splitlines()


def _intact(**fields) -> VerifyResult:
    res = VerifyResult(ok=True, attestation="SELF-ATTESTED", leaves_checked=5, seals_checked=1,
                       signatures_checked=6)
    for k, v in fields.items():
        setattr(res, k, v)
    return res


def test_a_self_attested_bundle_says_what_held_and_what_the_keys_are_tied_to(monkeypatch):
    code, lines = _run(monkeypatch, _intact())

    assert code == 0
    i = lines.index("VERIFIED, SELF-ATTESTED: leaf hashes, chain links, Merkle roots and signatures intact.")
    assert " ".join(lines[i + 1:i + 5]) == f"{_HELD} {_SELF}"
    assert i + 5 == len(lines) or lines[i + 5].startswith("  self-attested because")
    assert all(len(line) <= 90 for line in lines)


def test_without_cryptography_the_second_line_says_no_signature_was_checked(monkeypatch):
    code, lines = _run(monkeypatch, _intact(signatures_skipped=True, signatures_checked=0))

    i = lines.index("VERIFIED, SELF-ATTESTED: leaf hashes, chain links, Merkle roots intact.")
    assert " ".join(lines[i + 1:i + 4]) == (
        f"{_HELD} No signature was checked: install 'artzain[verify]' and run again before relying on this.")


def test_an_attested_bundle_names_the_evidence_root_as_cognexus_labs(monkeypatch):
    code, lines = _run(monkeypatch, _intact(attestation="ATTESTED"))

    i = lines.index("VERIFIED, ATTESTED: leaf hashes, chain links, Merkle roots and signatures intact.")
    assert " ".join(lines[i + 1:i + 3]) == _HELD
    assert lines[i + 3] == "The signing keys chain to the CogNEXUS Labs Evidence Root, certified at signing time."


def test_a_failed_bundle_gets_no_explanation_lines(monkeypatch):
    res = VerifyResult()
    res._fail(3, "chain linkage broken")
    code, lines = _run(monkeypatch, res)

    assert code == 1
    assert not any(line.startswith(("Every entry", "The signatures check")) for line in lines)
    assert lines[-1] == "FAILED at seq 3: chain linkage broken"


@pytest.mark.parametrize("warning", [
    av._PER_RECORD_SUMMARIES["seq_gaps"].format(n=3),
    av._PER_RECORD_SUMMARIES["seal_chain_gaps"].format(n=1),
    av._PER_RECORD_SUMMARIES["partial_seals"].format(n=2),
    av._PER_RECORD_SUMMARIES["partial_seals_proved"].format(n=4),
    av._SEAL_CHAIN_GAPS_COVERING.format(n="1,204"),
    av._seq_gap_detail(2, 4),
    av._seal_chain_gap_detail("01JZX4SEAL", covering=False),
    av._seal_chain_gap_detail("01JZX4SEAL", covering=True),
    av._partial_seal_detail("S0", 3, 9, proved=False),
    av._partial_seal_detail("S0", 3, 8, proved=True),
    av._handover_unregistered_warning("aaaa", "bbbb", ["bbbb"]),
    av._handover_unregistered_warning("aaaa", "bbbb", ["aaaa", "bbbb"]),
])
def test_what_a_filtered_export_always_shows_is_expected(warning):
    assert warning_label(warning) == "Expected"


@pytest.mark.parametrize("warning", [
    "cryptography not installed; signatures not verified (pip install 'artzain[verify]')",
    "signed manifest not verified (cryptography missing); its records are still compared",
    "signed manifest present but not verified (cryptography missing)",
    "signed manifest key 0123456789abcdef is not in the bundle, so custody is not verified",
    "certified bundle without a signed manifest",
    "key handovers are checked for self-consistency only; the manifest is not trusted",
    "key 0123456789abcdef: no handover names it (second process, or not authorized)",
    "key handover aaaa->bbbb not verified (cryptography missing)",
    "a warning a later release adds",
])
def test_anything_else_is_a_check(warning):
    assert warning_label(warning) == "Check"


def test_the_text_path_labels_each_warning(monkeypatch):
    seq = av._PER_RECORD_SUMMARIES["seq_gaps"].format(n=3)
    custody = "certified bundle without a signed manifest"
    code, lines = _run(monkeypatch, _intact(warnings=[seq, custody]))

    assert f"  Expected: {seq}" in lines
    assert f"  Check: {custody}" in lines
    assert not any(line.startswith("  ! ") for line in lines)


def test_json_keeps_the_warning_text_as_it_was(monkeypatch):
    custody = "certified bundle without a signed manifest"
    code, lines = _run(monkeypatch, _intact(warnings=[custody]), "--json")

    body = json.loads("\n".join(lines))
    assert body["warnings"] == [custody]
    assert "warning_labels" not in body and "explanation" not in body
