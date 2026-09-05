"""Exception-hygiene lint gate for the SDK sources (open-items 9.87).

Two ruff rules that ``pyproject.toml`` now selects for this package:

* ``B904`` - a ``raise`` inside ``except`` must say ``from exc`` (or
  ``from None``) so the original cause is not lost from the traceback.
* ``S110`` - ``try: ... except Exception: pass`` swallows the error with no
  trace at all; the SDK logs at DEBUG (or narrows the ``except``) instead.

The gate in CI is ``ruff check pypi-package``; this test pins the same two
rules independently of the configured ``select`` list, so the rules cannot
be dropped from the config again without a test going red.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_PKG_DIR = Path(__file__).resolve().parents[1]
_SRC_DIR = _PKG_DIR / "src"


def _ruff_executable() -> str | None:
    found = shutil.which("ruff")
    if found:
        return found
    # `pip install --user ruff` puts the console script here when ~/.local/bin
    # is not on PATH (the case on a bare CI runner or a fresh dev box).
    candidate = Path.home() / ".local" / "bin" / "ruff"
    if candidate.is_file():
        return str(candidate)
    return None


@pytest.mark.skipif(_ruff_executable() is None, reason="ruff is not installed")
def test_sdk_sources_have_no_b904_or_s110_findings() -> None:
    ruff = _ruff_executable()
    assert ruff is not None
    proc = subprocess.run(
        [
            ruff,
            "check",
            str(_SRC_DIR),
            "--select",
            "B904,S110",
            "--no-fix",
            "--no-cache",
            "--output-format",
            "concise",
        ],
        cwd=str(_PKG_DIR),
        capture_output=True,
        text=True,
        check=False,
    )
    findings = [
        line
        for line in proc.stdout.splitlines()
        if " B904 " in line or " S110 " in line
    ]
    assert proc.returncode == 0 and not findings, (
        f"ruff reported {len(findings)} B904/S110 finding(s) in src/ "
        f"(python {sys.version.split()[0]}):\n" + "\n".join(findings) + "\n"
        + proc.stderr
    )
