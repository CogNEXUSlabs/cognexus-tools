"""An empty or malformed kill-switch env var does not break ``import artzain``.

Survey row 61. The SDK read ``COGNEXUS_KILL_SWITCH_PANIC_THRESHOLD`` and
``COGNEXUS_KILL_SWITCH_PANIC_WINDOW_SECONDS`` with a bare ``int()`` at import:
an empty value or a typo raised ``ValueError`` and took ``decide()`` down with
the package. Now an empty value is the default, a value that is not a whole
number is the default with a WARNING naming the variable, and anything below
1 is 1.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest

from artzain import kill_switch

_SRC = Path(__file__).resolve().parents[1] / "src"
_THRESHOLD = "COGNEXUS_KILL_SWITCH_PANIC_THRESHOLD"
_WINDOW = "COGNEXUS_KILL_SWITCH_PANIC_WINDOW_SECONDS"


@pytest.mark.parametrize(("raw", "expected"), [
    (None, 5), ("", 5), ("8", 8), ("0", 1), ("-4", 1),
])
def test_a_threshold_is_read_as_a_whole_number_of_at_least_one(monkeypatch, raw, expected):
    if raw is None:
        monkeypatch.delenv(_THRESHOLD, raising=False)
    else:
        monkeypatch.setenv(_THRESHOLD, raw)

    assert kill_switch._env_int(_THRESHOLD, 5) == expected


def test_a_value_that_is_not_a_whole_number_is_the_default_and_says_so(monkeypatch, caplog):
    monkeypatch.setenv(_WINDOW, "sixty")

    with caplog.at_level(logging.WARNING, logger="artzain.kill_switch"):
        assert kill_switch._env_int(_WINDOW, 60) == 60

    assert any(_WINDOW in r.getMessage() for r in caplog.records), caplog.text


@pytest.mark.parametrize("raw", ["", "nope"])
@pytest.mark.parametrize("name", [_THRESHOLD, _WINDOW])
def test_import_artzain_survives_a_bad_value(name, raw):
    env = {k: v for k, v in os.environ.items() if k not in (_THRESHOLD, _WINDOW)}
    env = {**env, name: raw, "PYTHONPATH": str(_SRC)}
    proc = subprocess.run(
        [sys.executable, "-c", "import artzain; from artzain import kill_switch as k; "
                               "print(k._PANIC_THRESHOLD, k._PANIC_WINDOW_SECONDS)"],
        env=env, capture_output=True, text=True, timeout=120)

    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.split()[-2:] == ["5", "60"]
