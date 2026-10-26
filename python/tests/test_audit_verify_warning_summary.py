"""The verifier's report on a tenant-filtered evidence bundle.

A hosted (multi-tenant) export carries one tenant's leaves out of a chain the
tenants share, so there is a seq gap between nearly every pair of leaves, and
every seal that covers one of them is only partially present. The verifier
printed one warning per gap and one or two per seal: about 10,800 lines on a
real export before the verdict. Each of those kinds is now one line carrying
the count, the per-record lines move to ``warning_details`` (printed with
``--verbose``), and the counts are fields of the result. The verdict, the exit
status and every other warning are unchanged.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from artzain.audit_verify import _merkle_root, verify_bundle

from .test_audit_verify import (  # noqa: TID252 - the tamper matrix's own builders
    _GENESIS,
    _HAVE_CRYPTO,
    _canonical,
    _genuine_leaf,
    _inclusion_path,
    _read_leaves,
    _run_cli,
    _signed_manifest,
    _Signer,
    _write_leaves,
    _write_proofs,
)

pytestmark = pytest.mark.skipif(not _HAVE_CRYPTO, reason="cryptography not installed")

#: One tenant's seqs out of 8 sealer batches of 4 (seq 1..32). No two are
#: adjacent, so each pair has a gap between them: 8 leaves, 7 gaps.
_PRESENT = (2, 4, 6, 11, 18, 20, 27, 30)
_BATCH = 4
_BATCHES = 8
#: Batches whose leaves ship an inclusion proof each. The others are "root
#: not recomputed".
_PROVED = (0, 1, 2)

_GAP = ("seq gap {}->{} (range/tenant-filtered export; linkage across the gap "
        "not checkable offline)")
_CHAIN_GAP = "seal chain gap before {} (earlier seal not in this bundle)"
_PARTIAL = ("seal {} only partially present ({}/{} leaves) — boundary of a "
            "filtered export, root not recomputed")
_PARTIAL_PROVED = ("seal {} only partially present ({}/{} leaves) — boundary of a "
                   "filtered export; every present leaf proved included under its "
                   "merkle_root")

_SEQ_GAPS = ("{} seq gaps (tenant- or range-filtered export; chain linkage across "
             "the gaps not checkable offline)")
_SEAL_CHAIN_GAPS = "{} seal chain gaps (earlier seals not in this bundle)"
_PARTIAL_SEALS = ("{} seals only partially present — boundaries of a filtered "
                  "export, roots not recomputed")
_PARTIAL_SEALS_PROVED = ("{} seals only partially present — boundaries of a filtered "
                         "export; every present leaf proved included under its "
                         "seal's merkle_root")


@pytest.fixture()
def signer():
    return _Signer()


def _tenant_bundle(tmp_path: Path, signer: _Signer, *, present=_PRESENT,
                   batch: int = _BATCH, batches: int = _BATCHES,
                   proved=_PROVED, name: str = "tenant") -> Path:
    """One tenant's export of a chain the tenants share.

    The chain holds ``batch * batches`` leaves, sealed in batches of
    ``batch``, every seal chained to the one before it. Only the ``present``
    seqs ship, with the seals that cover at least one of them, so a seal
    whose batch holds none of this tenant's leaves is absent and the next
    shipped seal opens a seal chain gap. Leaves under the batches in
    ``proved`` carry their inclusion proof. The manifest is signed and binds
    the present set, as a hosted export's does.
    """
    base_ts = datetime(2026, 6, 17, 19, 0, 0, tzinfo=timezone.utc)
    chain, prev = [], _GENESIS
    for seq in range(1, batch * batches + 1):
        body = {
            "leaf_id": f"L{seq:025d}", "decision_id": f"D{seq:025d}",
            "created_at": (base_ts + timedelta(seconds=seq)).isoformat(),
            "user_id": 1 if seq in present else 2, "team_id": None,
            "agent_did": "agent-x", "action": "send_email", "target": "crm:1",
            "outcome": "allow",
            "payload_sha256": hashlib.sha256(str(seq).encode()).hexdigest(),
            "votes": [{"name": "pi", "verdict": "allow", "severity": "none"}],
            "bundle_version": "builtin:v0", "resolution": "builtin/strict-v0",
            "prev_leaf_hash": prev,
        }
        lh = hashlib.sha256(_canonical(body)).hexdigest()
        rec = dict(body)
        rec.update(seq=seq, leaf_hash=lh, sig=signer.sign(lh.encode("ascii")),
                   signer_key_id=signer.key_id, seal_id=f"S{(seq - 1) // batch}")
        chain.append(rec)
        prev = lh

    seals, proofs, prev_seal = [], [], _GENESIS
    for b in range(batches):
        members = chain[b * batch:(b + 1) * batch]
        hashes = [leaf["leaf_hash"] for leaf in members]
        body = {
            "seal_id": f"S{b}", "first_seq": b * batch + 1, "last_seq": (b + 1) * batch,
            "merkle_root": _merkle_root(hashes), "prev_seal_hash": prev_seal,
            "sealed_at": (base_ts + timedelta(minutes=b)).isoformat(),
        }
        sh = hashlib.sha256(_canonical(body)).hexdigest()
        prev_seal = sh
        mine = [leaf for leaf in members if leaf["seq"] in present]
        if not mine:
            continue  # nothing of this tenant's under it: not exported
        seal = dict(body)
        seal.update(seal_hash=sh, sig=signer.sign(sh.encode("ascii")),
                    signer_key_id=signer.key_id)
        seals.append(seal)
        if b in proved:
            proofs += [{"seq": leaf["seq"], "seal_id": f"S{b}",
                        "index": leaf["seq"] - 1 - b * batch,
                        "path": _inclusion_path(hashes, leaf["seq"] - 1 - b * batch)}
                       for leaf in mine]

    leaves = [leaf for leaf in chain if leaf["seq"] in present]
    d = tmp_path / name
    d.mkdir()
    _write_leaves(d, leaves)
    (d / "seals.jsonl").write_text(
        "".join(json.dumps(s, sort_keys=True) + "\n" for s in seals), encoding="utf-8")
    (d / "keys.json").write_text(json.dumps(
        [{"key_id": signer.key_id, "public_key_pem": signer.public_key_pem, "scope": "audit"}]),
        encoding="utf-8")
    if proofs:
        _write_proofs(d, proofs)
    (d / "manifest.json").write_text(json.dumps(_signed_manifest(
        signer, min(present), max(present), len(present), seal_count=len(seals),
        leaves=leaves, proofs=proofs or None)), encoding="utf-8")
    return d


#: The per-record lines the verifier printed for ``_tenant_bundle``, in the
#: order it printed them: the gaps (step 1), then seal by seal (step 4).
_PER_RECORD = [
    _GAP.format(2, 4), _GAP.format(4, 6), _GAP.format(6, 11), _GAP.format(11, 18),
    _GAP.format(18, 20), _GAP.format(20, 27), _GAP.format(27, 30),
    _PARTIAL_PROVED.format("S0", 2, 4),
    _PARTIAL_PROVED.format("S1", 1, 4),
    _PARTIAL_PROVED.format("S2", 1, 4),
    _CHAIN_GAP.format("S4"),
    _PARTIAL.format("S4", 2, 4),
    _CHAIN_GAP.format("S6"),
    _PARTIAL.format("S6", 1, 4),
    _PARTIAL.format("S7", 1, 4),
]

_SUMMARY = [
    _SEQ_GAPS.format(7),
    _PARTIAL_SEALS_PROVED.format(3),
    _SEAL_CHAIN_GAPS.format(2),
    _PARTIAL_SEALS.format(3),
]


def _count(warnings: list[str], needle: str) -> int:
    return sum(1 for w in warnings if needle in w)


def test_each_repeated_kind_is_one_line_with_its_count(tmp_path, signer):
    r = verify_bundle(_tenant_bundle(tmp_path, signer))
    assert r.ok, r.error
    assert (r.leaves_checked, r.seals_checked) == (8, 6)
    # One line per kind, at the place the first of its kind used to be.
    assert r.warnings == _SUMMARY, r.warnings
    assert _count(r.warnings, "seq gap") == 1
    assert _count(r.warnings, "seal chain gap") == 1
    assert _count(r.warnings, "root not recomputed") == 0
    assert _count(r.warnings, "roots not recomputed") == 1
    assert _count(r.warnings, "proved included") == 1


def test_the_counts_are_fields_and_the_per_record_lines_are_kept(tmp_path, signer):
    r = verify_bundle(_tenant_bundle(tmp_path, signer))
    assert (r.seq_gaps, r.seal_chain_gaps, r.partial_seals, r.partial_seals_proved) \
        == (7, 2, 3, 3)
    # Word for word what the verifier printed one per line, in that order.
    assert r.warning_details == _PER_RECORD


def test_the_verdict_and_the_rest_of_the_result_are_unchanged(tmp_path, signer):
    r = verify_bundle(_tenant_bundle(tmp_path, signer))
    assert r.ok and r.error is None and r.first_bad_seq is None
    assert r.attestation == "SELF-ATTESTED"
    assert r.attestation_reasons == ["no certificate chain in bundle"]
    # 8 leaves, 6 seals and the manifest.
    assert r.signatures_checked == 15 and not r.signatures_skipped


def test_counts_use_thousands_separators(tmp_path, signer):
    d = tmp_path / "wide"
    d.mkdir()
    _write_leaves(d, [_genuine_leaf(signer, seq) for seq in range(1, 2003, 2)])
    (d / "seals.jsonl").write_text("", encoding="utf-8")
    (d / "keys.json").write_text(json.dumps(
        [{"key_id": signer.key_id, "public_key_pem": signer.public_key_pem, "scope": "audit"}]),
        encoding="utf-8")
    (d / "manifest.json").write_text(json.dumps({"leaf_count": 1001}), encoding="utf-8")
    r = verify_bundle(d)
    assert r.ok, r.error
    assert r.warnings == [_SEQ_GAPS.format("1,000")]
    assert r.seq_gaps == 1000 and len(r.warning_details) == 1000
    assert r.warning_details[0] == _GAP.format(1, 3)
    assert r.warning_details[-1] == _GAP.format(1999, 2001)


def test_a_single_record_keeps_its_own_line(tmp_path, signer):
    """One gap and one partial seal: the specific line says more than a count
    of one would, so it stays, and nothing moves to ``warning_details``."""
    d = _tenant_bundle(tmp_path, signer, present=(1, 2, 5, 6), batch=8, batches=1,
                       proved=())
    r = verify_bundle(d)
    assert r.ok, r.error
    assert r.warnings == [_GAP.format(2, 5), _PARTIAL.format("S0", 4, 8)]
    assert (r.seq_gaps, r.seal_chain_gaps, r.partial_seals, r.partial_seals_proved) \
        == (1, 0, 1, 0)
    assert r.warning_details == []


def test_a_contiguous_bundle_reports_none(tmp_path, signer):
    d = _tenant_bundle(tmp_path, signer, present=(1, 2, 3, 4), batch=4, batches=1)
    r = verify_bundle(d)
    assert r.ok, r.error
    assert r.warnings == []
    assert (r.seq_gaps, r.seal_chain_gaps, r.partial_seals, r.partial_seals_proved) \
        == (0, 0, 0, 0)
    assert r.warning_details == []


def test_a_failure_still_reports_the_gaps_before_it(tmp_path, signer):
    """The fail path is unchanged: same error, same first bad seq, and the
    gaps seen before the failure are still reported, now as one line."""
    d = _tenant_bundle(tmp_path, signer)
    leaves = _read_leaves(d)
    next(leaf for leaf in leaves if leaf["seq"] == 27)["target"] = "crm:edited"
    _write_leaves(d, leaves)
    r = verify_bundle(d)
    assert not r.ok
    assert r.first_bad_seq == 27
    assert r.error == "leaf_hash mismatch at seq 27 (record tampered)"
    assert r.attestation is None
    # 2->4, 4->6, 6->11, 11->18, 18->20; seq 27 fails before its own gap.
    assert r.warnings == [_SEQ_GAPS.format(5)]
    assert r.seq_gaps == 5
    assert r.warning_details == _PER_RECORD[:5]


def _cli(capsys, d: Path, *extra: str) -> tuple[int, str]:
    return _run_cli(capsys, ["audit", "verify", str(d), *extra])


def _bang_lines(out: str) -> list[str]:
    return [line[len("  ! "):] for line in out.splitlines() if line.startswith("  ! ")]


def test_cli_prints_one_line_per_kind(tmp_path, signer, capsys):
    d = _tenant_bundle(tmp_path, signer)
    code, out = _cli(capsys, d)
    assert code == 0
    assert _bang_lines(out) == _SUMMARY, out
    for line in _PER_RECORD:
        assert line not in out
    assert "(--verbose lists the 15 per-record warnings)" in out
    assert "VERIFIED, SELF-ATTESTED" in out


def test_cli_verbose_prints_the_per_record_lines(tmp_path, signer, capsys):
    d = _tenant_bundle(tmp_path, signer)
    code, plain = _cli(capsys, d)
    verbose_code, out = _cli(capsys, d, "--verbose")
    assert verbose_code == code == 0
    assert _bang_lines(out) == _SUMMARY
    lines = out.splitlines()
    start = lines.index("  per-record warnings:")
    assert lines[start + 1:start + 1 + len(_PER_RECORD)] == [f"    - {w}" for w in _PER_RECORD]
    assert "--verbose lists" not in out
    # Everything after the warnings, the verdict included, is the same.
    assert plain.split("\n\n", 1)[1] == out.split("\n\n", 1)[1]


def test_cli_json_carries_the_counts_and_the_details(tmp_path, signer, capsys):
    d = _tenant_bundle(tmp_path, signer)
    code, raw = _cli(capsys, d, "--json")
    assert code == 0
    payload = json.loads(raw)
    assert payload["ok"] is True
    assert payload["warnings"] == _SUMMARY
    assert payload["warning_details"] == _PER_RECORD
    assert (payload["seq_gaps"], payload["seal_chain_gaps"],
            payload["partial_seals"], payload["partial_seals_proved"]) == (7, 2, 3, 3)
    # --verbose changes the text report only.
    verbose_code, verbose_raw = _cli(capsys, d, "--json", "--verbose")
    assert verbose_code == 0 and json.loads(verbose_raw) == payload


def test_cli_failure_exit_status_is_unchanged(tmp_path, signer, capsys):
    d = _tenant_bundle(tmp_path, signer)
    leaves = _read_leaves(d)
    next(leaf for leaf in leaves if leaf["seq"] == 27)["target"] = "crm:edited"
    _write_leaves(d, leaves)
    code, out = _cli(capsys, d)
    assert code == 1
    assert _bang_lines(out) == [_SEQ_GAPS.format(5)]
    assert out.rstrip().endswith(
        "FAILED (first bad seq: 27): leaf_hash mismatch at seq 27 (record tampered)")

