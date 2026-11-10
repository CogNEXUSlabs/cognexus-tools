"""The classifiers name every Python version the package supports.

``requires-python`` is the floor; the ``Programming Language :: Python :: 3.x``
classifiers list each minor version from that floor to the newest release
the test matrices run, with no gap. 0.6.64 shipped claiming 3.10 to 3.12
while CI already ran 3.13 and 3.14 (survey 25 Sep 2026, rows 165 and 166).
"""

from __future__ import annotations

import re
from pathlib import Path

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"
SUPPORTED = ["3.10", "3.11", "3.12", "3.13", "3.14"]


def _text() -> str:
    return PYPROJECT.read_text(encoding="utf-8")


def _classifier_versions() -> list[str]:
    return re.findall(r'(?m)^\s*"Programming Language :: Python :: (3\.\d+)",?\s*$', _text())


def test_the_classifiers_run_from_the_floor_to_the_newest_tested_release() -> None:
    assert _classifier_versions() == SUPPORTED


def test_the_floor_is_the_first_classifier() -> None:
    floor = re.search(r'(?m)^requires-python = ">=(3\.\d+)"\s*$', _text())
    assert floor is not None, "requires-python is not a >=3.x floor"
    assert _classifier_versions()[0] == floor.group(1)


def test_the_classifiers_have_no_gap() -> None:
    minors = [int(v.split(".")[1]) for v in _classifier_versions()]
    assert minors == list(range(minors[0], minors[-1] + 1))
