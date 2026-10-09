"""The published license is an SPDX identifier, not the license text.

``license = { file = "LICENSE" }`` makes the build backend copy the Apache
license, and the third-party notice under it, into the ``License``
core-metadata field. Scanners that only recognise SPDX expressions, deps.dev
among them, then report the license as non-standard. ``license`` is the
expression ``Apache-2.0``; ``license-files`` ships the text beside it.
"""

from __future__ import annotations

import re
import zipfile
from pathlib import Path

import pytest

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def _project_table() -> dict:
    text = PYPROJECT.read_text(encoding="utf-8")
    try:
        import tomllib
    except ModuleNotFoundError:
        return _project_table_py310(text)
    return tomllib.loads(text)["project"]


def _project_table_py310(text: str) -> dict:
    """The two license keys, for 3.10 (no ``tomllib``)."""
    section = text.split("[project]", 1)[1].split("\n[", 1)[0]
    license_id = re.search(r'(?m)^license = "([^"]+)"\s*$', section)
    files = re.search(r'(?m)^license-files = \[(.*)\]\s*$', section)
    assert license_id is not None, "license is not an SPDX expression string"
    assert files is not None, "license-files is missing"
    return {
        "license": license_id.group(1),
        "license-files": re.findall(r'"([^"]+)"', files.group(1)),
    }


def test_license_is_the_apache_spdx_expression():
    """Scanners read an SPDX expression; the license text stays a file."""
    project = _project_table()
    assert project["license"] == "Apache-2.0"
    assert project["license-files"] == ["LICENSE"]


def test_wheel_metadata_names_the_expression(tmp_path, monkeypatch):
    """The built wheel's core metadata carries ``License-Expression``, not the
    license body. ``license = { file = "LICENSE" }`` puts that body in the
    ``License`` field, which is what deps.dev reports as non-standard."""
    pytest.importorskip("hatchling")
    from hatchling.build import build_wheel

    monkeypatch.chdir(PYPROJECT.parent)
    name = build_wheel(str(tmp_path))
    with zipfile.ZipFile(tmp_path / name) as wheel:
        metadata_name = next(n for n in wheel.namelist() if n.endswith(".dist-info/METADATA"))
        metadata = wheel.read(metadata_name).decode("utf-8")
        license_name = next(n for n in wheel.namelist() if n.endswith("/licenses/LICENSE"))
        license_text = wheel.read(license_name).decode("utf-8")
    header = metadata.split("\n\n", 1)[0]
    fields = dict(line.split(": ", 1) for line in header.splitlines() if line.startswith("License"))
    assert fields["License-Expression"] == "Apache-2.0"
    assert fields["License-File"] == "LICENSE"
    assert "License" not in fields
    assert "TERMS AND CONDITIONS" not in header
    assert "Apache License" in license_text
