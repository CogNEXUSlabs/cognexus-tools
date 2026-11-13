"""Seeded sampling over an evidence bundle's ``decisions.csv``
(``artzain audit sample``).

An auditor testing a control picks rows of the population and must be able
to say how: the same seed gives the same rows to anyone who runs it, and the
method is plain enough to redo by hand. Each row's key is the SHA-256 of the
seed, a newline and the row's ``leaf_id`` (UTF-8); the rows with the N
smallest keys, compared as lowercase hex, are the sample, listed in ``seq``
order. Keying on ``leaf_id`` rather than a row's position means the order the
rows arrive in does not change the sample.

Nothing here verifies the bundle: run ``artzain audit verify`` first. When
the bundle's manifest commits ``decisions.csv`` (its ``companions`` map),
the file is checked against that digest and a mismatch is refused.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import secrets
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

from . import __version__

#: The method's name, recorded in ``sample.json``. A change to how keys are
#: computed or rows chosen gets a new name.
METHOD = "sha256-leaf-id-rank-v1"

METHOD_TEXT = (
    "Each row's key is the SHA-256 of the seed, a newline and the row's leaf_id, "
    "all UTF-8. The rows with the smallest keys, compared as lowercase hex, are "
    "the sample, listed in seq order."
)

_CSV = "decisions.csv"
_MAX_SEED = 256


class SampleError(Exception):
    """The input cannot be sampled; the message says why."""


@dataclass
class Sample:
    header: list[str]
    rows: list[dict[str, str]]
    record: dict[str, Any]


def _read_source(source: Path) -> tuple[bytes, Optional[dict[str, Any]], str]:
    """``decisions.csv``'s bytes, the bundle's manifest (``None`` for a bare
    CSV, or when the bundle has none) and the name to record."""
    if not source.exists():
        raise SampleError(f"{source} not found")
    if source.is_file() and source.suffix.lower() == ".csv":
        return source.read_bytes(), None, source.name
    if source.is_dir():
        path = source / _CSV
        if not path.is_file():
            raise SampleError(f"{source} holds no {_CSV}")
        manifest_path = source / "manifest.json"
        manifest_raw = manifest_path.read_bytes() if manifest_path.is_file() else b""
        data = path.read_bytes()
    else:
        try:
            with zipfile.ZipFile(source) as zf:
                names = set(zf.namelist())
                if _CSV not in names:
                    raise SampleError(f"{source} holds no {_CSV}")
                data = zf.read(_CSV)
                manifest_raw = zf.read("manifest.json") if "manifest.json" in names else b""
        except zipfile.BadZipFile as exc:
            raise SampleError(f"{source} is not a bundle folder, a .zip or a .csv") from exc
    try:
        manifest = json.loads(manifest_raw) if manifest_raw.strip() else None
    except ValueError as exc:
        raise SampleError("the bundle's manifest.json is not JSON") from exc
    return data, manifest if isinstance(manifest, dict) else None, source.name


def _parse(data: bytes) -> tuple[list[str], list[dict[str, str]]]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SampleError(f"{_CSV} is not UTF-8") from exc
    reader = csv.reader(io.StringIO(text, newline=""))
    try:
        header = next(reader)
    except StopIteration as exc:
        raise SampleError(f"{_CSV} is empty") from exc
    if "leaf_id" not in header:
        raise SampleError(f"{_CSV} has no leaf_id column")
    if "seq" not in header:
        raise SampleError(f"{_CSV} has no seq column")
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for number, cells in enumerate(reader, start=2):
        if len(cells) != len(header):
            raise SampleError(f"row {number} has {len(cells)} cells, the header {len(header)}")
        row = dict(zip(header, cells, strict=True))
        leaf_id = row["leaf_id"]
        if not leaf_id:
            raise SampleError(f"row {number} has no leaf_id")
        if leaf_id in seen:
            raise SampleError(f"leaf_id {leaf_id} appears twice: the population is one row per leaf")
        try:
            int(row["seq"])
        except ValueError as exc:
            raise SampleError(f"row {number} has no integer seq") from exc
        seen.add(leaf_id)
        rows.append(row)
    return header, rows


def rank_key(seed: str, leaf_id: str) -> str:
    """A row's key under :data:`METHOD`."""
    return hashlib.sha256(f"{seed}\n{leaf_id}".encode("utf-8")).hexdigest()


def sample_bundle(source: str | Path, size: int, seed: Optional[str] = None,
                  outcomes: Optional[Iterable[str]] = None) -> Sample:
    """Pick *size* rows of the ``decisions.csv`` in *source* (a bundle
    folder, a bundle ``.zip`` or the CSV itself).

    *seed*: any text up to 256 characters with no newline; when ``None`` one
    is drawn (32 hex characters) and the record says so. *outcomes*: sample
    only the rows with one of these outcomes. Raises :class:`SampleError`.
    """
    if size < 1:
        raise SampleError("size must be at least 1")
    seed_drawn = seed is None
    if seed is None:
        seed = secrets.token_hex(16)
    if not seed or len(seed) > _MAX_SEED or "\n" in seed or "\r" in seed:
        raise SampleError(f"the seed must be 1 to {_MAX_SEED} characters on one line")
    path = Path(source)
    data, manifest, name = _read_source(path)
    digest = hashlib.sha256(data).hexdigest()
    committed = None
    if manifest is not None and isinstance(manifest.get("companions"), dict):
        committed = manifest["companions"].get(_CSV)
    if committed is not None and committed != digest:
        raise SampleError(
            f"{_CSV} does not match the bundle's manifest (digest mismatch): "
            "run artzain audit verify on the bundle")
    header, rows = _parse(data)
    wanted = sorted(set(outcomes)) if outcomes else None
    if wanted is not None and "outcome" not in header:
        raise SampleError(f"{_CSV} has no outcome column to filter on")
    population = [r for r in rows if wanted is None or r["outcome"] in wanted]
    chosen = sorted(population, key=lambda r: rank_key(seed, r["leaf_id"]))[:size]
    chosen.sort(key=lambda r: int(r["seq"]))
    record: dict[str, Any] = {
        "method": METHOD,
        "method_text": METHOD_TEXT,
        "seed": seed,
        "seed_drawn": seed_drawn,
        "size_requested": size,
        "size_selected": len(chosen),
        "population": {"rows": len(rows), "sampled_from": len(population), "outcomes": wanted},
        "source": {
            "name": name,
            "decisions_csv_sha256": digest,
            "checked_against_manifest": committed is not None,
        },
        "artzain_version": __version__,
        "selected": [
            {"seq": int(r["seq"]), "decision_id": r.get("decision_id", ""), "leaf_id": r["leaf_id"]}
            for r in chosen
        ],
    }
    return Sample(header=header, rows=chosen, record=record)


def write_sample(sample: Sample, prefix: str | Path) -> tuple[Path, Path]:
    """Write ``<prefix>.csv`` (the selected rows, the source's header and
    cells) and ``<prefix>.json`` (the record). Refuses to overwrite either."""
    prefix = Path(prefix)
    csv_path = prefix.with_name(prefix.name + ".csv")
    json_path = prefix.with_name(prefix.name + ".json")
    for p in (csv_path, json_path):
        if p.exists():
            raise SampleError(f"{p} already exists")
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(sample.header)
        for row in sample.rows:
            writer.writerow([row[c] for c in sample.header])
    json_path.write_text(json.dumps(sample.record, indent=2) + "\n", encoding="utf-8")
    return csv_path, json_path
