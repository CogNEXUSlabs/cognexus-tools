"""Seeded sampling over an evidence bundle's ``decisions.csv`` (auditor
journey plan, WP 5.3).

``artzain audit sample <bundle> --size N [--seed S]`` picks N rows of the
population an export holds, the same N for the same seed whoever runs it and
whatever order the rows are in. It writes the selected rows (``sample.csv``,
the bundle's own columns and cells) and a record of how they were chosen
(``sample.json``: the seed, the method, the population and its file's
SHA-256, the selection). The method is plain enough to redo by hand: each
row's key is the SHA-256 of the seed, a newline and its ``leaf_id``; the N
smallest keys are the sample.
"""

from __future__ import annotations

import contextlib
import csv
import hashlib
import io
import json
import zipfile
from pathlib import Path

import pytest

from artzain import cli
from artzain.audit_sample import METHOD, SampleError, sample_bundle, write_sample

_HEADER = ["seq", "created_at", "decision_id", "leaf_id", "outcome", "target", "reasons"]


def _rows(n=20):
    rows = []
    for i in range(1, n + 1):
        rows.append({
            "seq": str(i),
            "created_at": f"2026-10-01T00:00:{i:02d}+00:00",
            "decision_id": f"D{i:04d}",
            "leaf_id": f"L{i:025d}",
            "outcome": ("deny" if i % 4 == 0 else "review" if i % 5 == 0 else "allow"),
            "target": f"crm:{i}",
            # Cells a naive splitter breaks: a comma, a quote and a newline.
            "reasons": 'policy "A", line one\nline two' if i % 3 == 0 else "",
        })
    return rows


def _csv_text(rows, header=_HEADER) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(header)
    for row in rows:
        writer.writerow([row.get(c, "") for c in header])
    return buf.getvalue()


def _bundle_dir(tmp: Path, rows=None, *, manifest=True, text=None) -> Path:
    d = tmp / "bundle"
    d.mkdir()
    data = (text if text is not None else _csv_text(rows or _rows())).encode("utf-8")
    (d / "decisions.csv").write_bytes(data)
    if manifest:
        (d / "manifest.json").write_text(json.dumps({
            "leaf_count": 20,
            "companions": {"decisions.csv": hashlib.sha256(data).hexdigest()},
        }), encoding="utf-8")
    return d


def _zipped(d: Path) -> Path:
    z = d.parent / "bundle.zip"
    with zipfile.ZipFile(z, "w") as zf:
        for p in sorted(d.iterdir()):
            zf.write(p, p.name)
    return z


def _by_hand(rows, seed, n):
    """The method as the record states it, redone without the module."""
    keyed = sorted(rows, key=lambda r: hashlib.sha256(f"{seed}\n{r['leaf_id']}".encode("utf-8")).hexdigest())
    return sorted((r["leaf_id"] for r in keyed[:n]), key=lambda lid: int(next(r["seq"] for r in rows if r["leaf_id"] == lid)))


def _leaf_ids(sample):
    return [row["leaf_id"] for row in sample.rows]


def test_the_selection_is_the_method_the_record_states(tmp_path):
    sample = sample_bundle(_bundle_dir(tmp_path), size=5, seed="audit-2026-q3")

    assert _leaf_ids(sample) == _by_hand(_rows(), "audit-2026-q3", 5)
    assert sample.record["method"] == METHOD
    assert sample.record["seed"] == "audit-2026-q3"


def test_the_same_seed_picks_the_same_rows_whatever_their_order(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    a = sample_bundle(_bundle_dir(tmp_path / "a", _rows()), size=6, seed="s1")
    b = sample_bundle(_bundle_dir(tmp_path / "b", list(reversed(_rows()))), size=6, seed="s1")

    assert _leaf_ids(a) == _leaf_ids(b)


def test_another_seed_picks_other_rows(tmp_path):
    d = _bundle_dir(tmp_path)

    assert _leaf_ids(sample_bundle(d, size=6, seed="one")) != _leaf_ids(sample_bundle(d, size=6, seed="two"))


def test_the_rows_are_listed_in_seq_order(tmp_path):
    sample = sample_bundle(_bundle_dir(tmp_path), size=8, seed="order")

    seqs = [int(row["seq"]) for row in sample.rows]
    assert seqs == sorted(seqs)


def test_a_size_at_or_past_the_population_takes_every_row(tmp_path):
    sample = sample_bundle(_bundle_dir(tmp_path), size=50, seed="all")

    assert len(sample.rows) == 20
    assert sample.record["size_requested"] == 50
    assert sample.record["size_selected"] == 20


def test_an_outcome_filter_samples_only_those_rows_and_counts_that_population(tmp_path):
    sample = sample_bundle(_bundle_dir(tmp_path), size=3, seed="denies", outcomes=["deny"])

    denies = [r for r in _rows() if r["outcome"] == "deny"]
    assert {row["outcome"] for row in sample.rows} == {"deny"}
    assert sample.record["population"] == {"rows": 20, "sampled_from": len(denies), "outcomes": ["deny"]}
    assert _leaf_ids(sample) == _by_hand(denies, "denies", 3)


def test_without_a_seed_one_is_drawn_recorded_and_reproduces_the_sample(tmp_path):
    d = _bundle_dir(tmp_path)
    first = sample_bundle(d, size=4)

    seed = first.record["seed"]
    assert isinstance(seed, str) and len(seed) == 32 and int(seed, 16) >= 0
    assert first.record["seed_drawn"] is True
    assert _leaf_ids(sample_bundle(d, size=4, seed=seed)) == _leaf_ids(first)


def test_a_zip_a_folder_and_the_csv_itself_give_the_same_sample(tmp_path):
    d = _bundle_dir(tmp_path)
    z = _zipped(d)

    ids = {tuple(_leaf_ids(sample_bundle(p, size=5, seed="x"))) for p in (d, z, d / "decisions.csv")}
    assert len(ids) == 1


def test_the_record_names_the_population_file_by_its_sha256(tmp_path):
    d = _bundle_dir(tmp_path)
    sample = sample_bundle(d, size=5, seed="x")

    assert sample.record["source"]["decisions_csv_sha256"] == hashlib.sha256((d / "decisions.csv").read_bytes()).hexdigest()
    assert sample.record["source"]["checked_against_manifest"] is True
    assert sample.record["selected"] == [
        {"seq": int(r["seq"]), "decision_id": r["decision_id"], "leaf_id": r["leaf_id"]} for r in sample.rows
    ]


def test_a_csv_that_differs_from_the_manifest_is_refused(tmp_path):
    d = _bundle_dir(tmp_path)
    (d / "decisions.csv").write_bytes((d / "decisions.csv").read_bytes() + b"21,x,D9,L9,allow,t,\r\n")

    with pytest.raises(SampleError, match="decisions.csv does not match the bundle's manifest"):
        sample_bundle(d, size=5, seed="x")


def test_a_bundle_without_a_manifest_digest_is_sampled_and_says_so(tmp_path):
    sample = sample_bundle(_bundle_dir(tmp_path, manifest=False), size=5, seed="x")

    assert sample.record["source"]["checked_against_manifest"] is False


@pytest.mark.parametrize("text, message", [
    ("seq,created_at,decision_id,outcome\r\n1,t,D1,allow\r\n", "has no leaf_id column"),
    (_csv_text([{"seq": "1", "leaf_id": ""}]), "row 2 has no leaf_id"),
    (_csv_text([{"seq": "1", "leaf_id": "L1"}, {"seq": "2", "leaf_id": "L1"}]), "leaf_id L1 appears twice"),
    (_csv_text([{"seq": "x", "leaf_id": "L1"}]), "row 2 has no integer seq"),
])
def test_a_population_that_is_not_one_row_per_leaf_is_refused(tmp_path, text, message):
    with pytest.raises(SampleError, match=message):
        sample_bundle(_bundle_dir(tmp_path, manifest=False, text=text), size=1, seed="x")


@pytest.mark.parametrize("size", [0, -1])
def test_a_size_below_one_is_refused(tmp_path, size):
    with pytest.raises(SampleError, match="size must be at least 1"):
        sample_bundle(_bundle_dir(tmp_path), size=size, seed="x")


def test_a_bundle_with_no_decisions_csv_is_refused(tmp_path):
    d = tmp_path / "empty"
    d.mkdir()

    with pytest.raises(SampleError, match="no decisions.csv"):
        sample_bundle(d, size=1, seed="x")


def test_sample_csv_keeps_the_bundle_s_header_and_cells(tmp_path):
    d = _bundle_dir(tmp_path)
    sample = sample_bundle(d, size=20, seed="x")
    csv_path, json_path = write_sample(sample, tmp_path / "out" / "sample")

    assert csv_path.name == "sample.csv" and json_path.name == "sample.json"
    # Every row, so the written file is the input in seq order: byte for byte.
    assert csv_path.read_bytes() == (d / "decisions.csv").read_bytes()
    assert json.loads(json_path.read_text(encoding="utf-8")) == sample.record


def test_write_sample_does_not_overwrite(tmp_path):
    sample = sample_bundle(_bundle_dir(tmp_path), size=2, seed="x")
    write_sample(sample, tmp_path / "s")

    with pytest.raises(SampleError, match="already exists"):
        write_sample(sample, tmp_path / "s")


def _cli(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), pytest.raises(SystemExit) as exit_:
        cli.main(["audit", "sample", *argv])
    return exit_.value.code, out.getvalue()


def test_the_cli_writes_both_files_and_prints_the_seed_and_the_count(tmp_path):
    d = _bundle_dir(tmp_path)
    code, out = _cli(str(d), "--size", "5", "--seed", "q3", "--out", str(tmp_path / "picked"))

    assert code == 0
    assert (tmp_path / "picked.csv").is_file() and (tmp_path / "picked.json").is_file()
    assert "5 of 20 rows" in out
    assert "seed: q3" in out


def test_the_cli_json_prints_the_record(tmp_path):
    d = _bundle_dir(tmp_path)
    code, out = _cli(str(d), "--size", "3", "--seed", "q3", "--outcome", "deny", "--out", str(tmp_path / "p"), "--json")

    assert code == 0
    body = json.loads(out)
    assert body["seed"] == "q3" and body["size_selected"] == 3 and body["population"]["outcomes"] == ["deny"]


def test_the_cli_exits_1_with_the_reason_on_a_refused_input(tmp_path):
    d = _bundle_dir(tmp_path)
    (d / "decisions.csv").write_bytes(b"edited")

    code, out = _cli(str(d), "--size", "5", "--seed", "x", "--out", str(tmp_path / "p"))

    assert code == 1
    assert "decisions.csv does not match the bundle's manifest" in out
    assert not (tmp_path / "p.csv").exists()
