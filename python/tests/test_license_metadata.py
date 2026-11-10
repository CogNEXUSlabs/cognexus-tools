"""The published license is an SPDX identifier, and the notice is a file.

``license = { file = "LICENSE" }`` makes the build backend copy the Apache
license, and any third-party notice under it, into the ``License``
core-metadata field. Scanners that only recognise SPDX expressions, deps.dev
among them, then report the license as non-standard. ``license`` is the
expression ``Apache-2.0``; ``license-files`` ships the texts beside it:
``LICENSE``, the Apache-2.0 text alone, and ``NOTICE``, the attribution for
the portions derived from microsoft/agent-governance-toolkit (MIT), which
sat at the end of ``LICENSE`` until 0.6.65 (survey 25 Sep 2026, row 167).
"""

from __future__ import annotations

import re
import zipfile
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parents[1]
PYPROJECT = PACKAGE / "pyproject.toml"
LICENSE = PACKAGE / "LICENSE"
NOTICE = PACKAGE / "NOTICE"
LICENSE_FILES = ["LICENSE", "NOTICE"]


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
    """Scanners read an SPDX expression; the texts stay files."""
    project = _project_table()
    assert project["license"] == "Apache-2.0"
    assert project["license-files"] == LICENSE_FILES


def test_the_license_is_the_apache_text_alone():
    text = LICENSE.read_text(encoding="utf-8")
    assert text.lstrip().startswith("Apache License")
    assert "THIRD-PARTY NOTICES" not in text
    assert "MIT License" not in text
    assert text.rstrip().endswith("limitations under the License.")


def test_the_third_party_notice_lives_in_notice():
    text = NOTICE.read_text(encoding="utf-8")
    assert text.startswith("artzain")
    assert "Copyright 2026 CogNEXUS Labs" in text
    assert text.count("THIRD-PARTY NOTICES") == 1
    assert "microsoft/agent-governance-toolkit" in text
    assert "Copyright (c) Microsoft Corporation" in text
    assert "MIT License" in text


def test_the_sdist_ships_the_notice():
    text = PYPROJECT.read_text(encoding="utf-8")
    sdist = text.split("[tool.hatch.build.targets.sdist]", 1)[1].split("\n[", 1)[0]
    included = re.findall(r'"([^"]+)"', sdist.split("include = [", 1)[1].split("]", 1)[0])
    assert "LICENSE" in included
    assert "NOTICE" in included


def test_wheel_metadata_names_the_expression(tmp_path, monkeypatch):
    """The built wheel's core metadata carries ``License-Expression``, not the
    license body (``license = { file = "LICENSE" }`` puts that body in the
    ``License`` field, which is what deps.dev reports as non-standard), one
    ``License-File`` per text, and both texts under ``licenses/``."""
    pytest.importorskip("hatchling")
    from hatchling.build import build_wheel

    monkeypatch.chdir(PYPROJECT.parent)
    name = build_wheel(str(tmp_path))
    with zipfile.ZipFile(tmp_path / name) as wheel:
        metadata_name = next(n for n in wheel.namelist() if n.endswith(".dist-info/METADATA"))
        metadata = wheel.read(metadata_name).decode("utf-8")
        texts = {Path(n).name: wheel.read(n).decode("utf-8")
                 for n in wheel.namelist() if "/licenses/" in n}
    lines = metadata.split("\n\n", 1)[0].splitlines()
    assert [line.split(": ", 1)[1] for line in lines if line.startswith("License-Expression: ")] == ["Apache-2.0"]
    assert sorted(line.split(": ", 1)[1] for line in lines if line.startswith("License-File: ")) == LICENSE_FILES
    assert not any(line.startswith("License: ") for line in lines)
    assert not any("TERMS AND CONDITIONS" in line for line in lines)
    assert sorted(texts) == LICENSE_FILES
    assert "Apache License" in texts["LICENSE"]
    assert "THIRD-PARTY NOTICES" not in texts["LICENSE"]
    assert "THIRD-PARTY NOTICES" in texts["NOTICE"]
