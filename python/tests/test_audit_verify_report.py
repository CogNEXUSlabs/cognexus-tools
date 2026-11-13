"""Report mode: ``artzain audit verify --report`` (auditor journey plan,
WP 2.6).

A plain run stops at the first failure and names it. A report run keeps
going: every failing leaf, every failing seal, and every check of the signed
manifest's record set, companions and profile folder, each listed with its
seq. The verdict rule is the same (any failure fails the bundle), and so are
``ok``, ``error``, ``first_bad_seq`` and the exit code; only the list is new.
The list is ``VerifyResult.failures``, a property, so the result's fields and
the captured outcomes do not move.
"""

from __future__ import annotations

import contextlib
import dataclasses
import io
import json

import pytest

from artzain import cli
from artzain.audit_verify import VerifyResult, verify_bundle

from .test_audit_verify import (  # noqa: TID252 - the tamper matrix's own helpers
    _read_leaves,
    _write_leaves,
)
from .test_audit_verify_profile_files import _HAVE_CRYPTO, _bundle, _Signer  # noqa: TID252

requires_crypto = pytest.mark.skipif(not _HAVE_CRYPTO, reason="cryptography not installed")

_LEAF = "leaf_hash mismatch (record tampered)"
_MAPPING = "profile file eu-ai-act/mapping.md altered (digest mismatch)"


@pytest.fixture()
def signer():
    if not _HAVE_CRYPTO:
        pytest.skip("cryptography not installed")
    return _Signer()


def _tampered(tmp_path, signer, *, seqs=(2, 4), mapping=True, seal=False):
    """A profile bundle with the leaves at *seqs* edited (their stored hash
    kept), the profile's mapping edited when *mapping*, and the seal's
    Merkle root edited when *seal*."""
    d = _bundle(tmp_path, signer)
    leaves = _read_leaves(d)
    for leaf in leaves:
        if leaf["seq"] in seqs:
            leaf["target"] = "crm:edited"
    _write_leaves(d, leaves)
    if mapping:
        (d / "eu-ai-act" / "mapping.md").write_bytes(b"# edited\n")
    if seal:
        path = d / "seals.jsonl"
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        rows[0]["merkle_root"] = "0" * 64
        path.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows), encoding="utf-8")
    return d


def _cli(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), pytest.raises(SystemExit) as exit_:
        cli.main(["audit", "verify", *argv])
    return exit_.value.code, out.getvalue()


def test_the_list_is_a_property_not_a_field():
    assert "failures" not in {f.name for f in dataclasses.fields(VerifyResult)}
    assert VerifyResult().failures == []


@requires_crypto
def test_a_plain_run_stops_at_the_first_failure_and_lists_only_it(tmp_path, signer):
    result = verify_bundle(_tampered(tmp_path, signer))

    assert not result.ok
    assert (result.first_bad_seq, result.error) == (2, _LEAF)
    assert result.failures == [(2, _LEAF)]


@requires_crypto
def test_a_report_run_lists_every_failing_leaf_and_the_altered_profile_file(tmp_path, signer):
    result = verify_bundle(_tampered(tmp_path, signer), report=True)

    assert result.failures == [(2, _LEAF), (4, _LEAF), (None, _MAPPING)]


@requires_crypto
def test_a_report_run_lists_a_failing_seal_after_the_leaves(tmp_path, signer):
    result = verify_bundle(_tampered(tmp_path, signer, seqs=(3,), mapping=False, seal=True), report=True)

    seqs = [seq for seq, _ in result.failures]
    errors = [error for _, error in result.failures]
    assert errors[0] == _LEAF and seqs[0] == 3
    assert any(e.startswith("seal_hash mismatch for seal") for e in errors[1:]), errors


@requires_crypto
def test_the_verdict_the_first_failure_and_the_attestation_are_a_plain_run_s(tmp_path, signer):
    d = _tampered(tmp_path, signer)
    plain = verify_bundle(d)
    report = verify_bundle(d, report=True)

    assert (report.ok, report.error, report.first_bad_seq, report.attestation) == \
        (plain.ok, plain.error, plain.first_bad_seq, plain.attestation) == (False, _LEAF, 2, None)


@requires_crypto
def test_an_intact_bundle_reads_the_same_in_either_mode(tmp_path, signer):
    d = _bundle(tmp_path, signer)
    plain = verify_bundle(d)
    report = verify_bundle(d, report=True)

    assert plain.ok and report.failures == []
    assert dataclasses.asdict(report) == dataclasses.asdict(plain)


@requires_crypto
def test_the_cli_report_prints_the_count_and_every_failure(tmp_path, signer):
    d = _tampered(tmp_path, signer)
    code, plain = _cli(str(d))
    code_report, report = _cli(str(d), "--report")

    assert code == code_report == 1
    # The counts above count every leaf that held, so only the verdict line
    # and what follows it are compared.
    assert plain.splitlines()[-1] == f"FAILED at seq 2: {_LEAF}"
    assert report.splitlines()[-6:] == [
        f"FAILED at seq 2: {_LEAF}",
        "",
        "3 failures:",
        f"  FAILED at seq 2: {_LEAF}",
        f"  FAILED at seq 4: {_LEAF}",
        f"  FAILED: {_MAPPING}",
    ]
    assert "failures:" not in plain


@requires_crypto
def test_the_cli_report_on_an_intact_bundle_prints_what_a_plain_run_does(tmp_path, signer):
    d = _bundle(tmp_path, signer)

    assert _cli(str(d), "--report") == _cli(str(d))


@requires_crypto
def test_the_json_report_carries_the_list_and_a_plain_json_run_does_not(tmp_path, signer):
    d = _tampered(tmp_path, signer)
    code, plain = _cli(str(d), "--json")
    code_report, report = _cli(str(d), "--json", "--report")

    assert code == code_report == 1
    assert "failures" not in json.loads(plain)
    body = json.loads(report)
    assert body["failures"] == [
        {"seq": 2, "error": _LEAF}, {"seq": 4, "error": _LEAF}, {"seq": None, "error": _MAPPING},
    ]
    assert {k: v for k, v in body.items() if k != "failures"}.keys() == json.loads(plain).keys()
