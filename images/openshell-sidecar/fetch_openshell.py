#!/usr/bin/env python3
"""Fetch the openshell CLI builds openshell.lock names into openshell/, beside
the Dockerfile, and check each against its SHA-256.

Usage::

    python images/openshell-sidecar/fetch_openshell.py

Run it before every build of the image. The Dockerfile copies openshell/ in,
checks both builds against the lock again, and installs the one for the
platform it builds; it fetches nothing itself. Standard library only.
"""

from __future__ import annotations

import hashlib
import re
import sys
import urllib.request
from pathlib import Path
from typing import List, Tuple

HERE = Path(__file__).resolve().parent
LOCK = HERE / "openshell.lock"
OUT = HERE / "openshell"
#: The only place a build may come from: a release of NVIDIA's OpenShell.
_FROM = re.compile(r"https://github\.com/NVIDIA/OpenShell/releases/download/v(\d+\.\d+\.\d+)/")
_LINE = re.compile(r"([0-9a-f]{64})  (openshell-(?:x86_64|aarch64)-unknown-linux-musl\.tar\.gz)")


def read(text: str) -> Tuple[str, str, List[Tuple[str, str]]]:
    """``(release, base URL, [(sha256, name), ...])`` from the lock. Raises
    ValueError for a lock that is not one."""
    release = re.search(r"^# release: (\d+\.\d+\.\d+)$", text, re.M)
    base = re.search(r"^# from: (\S+)$", text, re.M)
    if not release or not base:
        raise ValueError("openshell.lock names no release, or no place to fetch it from")
    found = _FROM.fullmatch(base[1])
    if not found or found[1] != release[1]:
        raise ValueError(f"openshell.lock fetches from {base[1]}, which is not NVIDIA's "
                         f"OpenShell {release[1]} release")
    builds = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        match = _LINE.fullmatch(line)
        if not match:
            raise ValueError(f"openshell.lock: not `<sha256>  <build>`: {line!r}")
        builds.append((match[1], match[2]))
    names = sorted(name for _sha, name in builds)
    if names != ["openshell-aarch64-unknown-linux-musl.tar.gz",
                 "openshell-x86_64-unknown-linux-musl.tar.gz"]:
        raise ValueError(f"openshell.lock must name one build for each platform, not {names}")
    return release[1], base[1], builds


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=120) as resp:  # noqa: S310 - https, from the lock
        return resp.read()


def main() -> int:
    release, base, builds = read(LOCK.read_text(encoding="utf-8"))
    OUT.mkdir(exist_ok=True)
    for sha, name in builds:
        data = fetch(base + name)
        got = hashlib.sha256(data).hexdigest()
        if got != sha:
            print(f"{name} is not the build openshell.lock names (SHA-256 {got}): not keeping it",
                  file=sys.stderr)
            return 1
        (OUT / name).write_bytes(data)
        print(f"{name}: OpenShell {release}, SHA-256 {sha}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
