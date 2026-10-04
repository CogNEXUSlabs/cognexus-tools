"""The connect script: one command that installs ``artzain`` and connects
this host's OpenShell gateway.

``connect-<version>.sh`` is published with each ``python-v<version>``
release of ``artzain``. The operator downloads it, checks it against the
SHA-256 the dashboard shows, and runs it as the user the gateway runs as::

    ARTZAIN_ENROLL_TOKEN=... sh connect-<version>.sh --config-digest <digest>

What the script does, in order:

1. Refuses anything but Linux on x86_64 or aarch64, and root: it binds the
   gateway OpenShell's deb or rpm package runs as a systemd user service.
2. Downloads uv :data:`UV_VERSION` (the static musl build) from its GitHub
   release, over HTTPS only, and runs it only if its SHA-256 is the one
   written into the script.
3. Installs ``artzain[openshell]==<version>`` as a uv tool, on a Python uv
   manages: a lasting environment, which the sidecar's service keeps running
   from (``uvx``'s cache is not one, and ``up`` refuses it).
4. Runs ``artzain connect openshell up`` with the script's own arguments.
   The enroll token stays in ``ARTZAIN_ENROLL_TOKEN``, where ``up`` reads it.

``ARTZAIN_PACKAGE``, when set, is what step 3 installs instead: a wheel of a
build under test. The published command never sets it.

:func:`render` writes the script; ``python bootstrap.py <version>`` prints
it. This file uses the standard library only, so the release job runs it by
its path, with no ``artzain`` installed.
"""

from __future__ import annotations

import hashlib
import re
import sys

#: The uv the script installs with, and the SHA-256 of each static build,
#: from its GitHub release (each asset's ``.sha256`` file and GitHub's own
#: digest agree). The engine repository's ``packaging/local-setup`` pins the
#: same version; a test there holds the two together.
UV_VERSION = "0.8.15"
UV_SHA256 = {
    "x86_64": "d0fec58f3124e05e0a1af0f6541abfce4333253cdaf23c7b6bb2e6128bf138ea",
    "aarch64": "23ea21a05c62c4c307ce691f29bff2f15c94c4f07f2b83d9b356f0664bc8b3a2",
}

_VERSION = re.compile(r"\d+\.\d+\.\d+")
#: The first ``artzain`` with ``connect openshell``.
FIRST_VERSION = (0, 6, 36)

_SCRIPT = r"""#!/bin/sh
# Connect this host's OpenShell gateway to ArtzAIn (artzain @ARTZAIN_VERSION@).
#
# Run it as the user the gateway runs as, with the enroll token you were
# given in ARTZAIN_ENROLL_TOKEN:
#
#   ARTZAIN_ENROLL_TOKEN=... sh connect-@ARTZAIN_VERSION@.sh --config-digest <digest>
#
# It installs uv @UV_VERSION@ (checked against its SHA-256), installs
# artzain[openshell]==@ARTZAIN_VERSION@ as a uv tool, and runs
# `artzain connect openshell up` with the arguments given here. The operator
# manual, chapter 17, says what `up` does.
set -eu

ARTZAIN_VERSION="@ARTZAIN_VERSION@"
UV_VERSION="@UV_VERSION@"

say() { printf 'artzain connect: %s\n' "$*" >&2; }
fail() { say "$*"; exit 1; }

[ "$(uname -s)" = Linux ] || fail "this connects the gateway OpenShell's deb or rpm package installs, on Linux"
case "$(uname -m)" in
  x86_64|amd64) arch=x86_64; uv_sha256="@UV_SHA256_X86_64@" ;;
  aarch64|arm64) arch=aarch64; uv_sha256="@UV_SHA256_AARCH64@" ;;
  *) fail "there is no pinned uv for $(uname -m)" ;;
esac
[ "$(id -u)" != 0 ] || fail "run this as the user the gateway runs as, not as root"
for tool in curl tar mktemp; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is needed"
done
if command -v sha256sum >/dev/null 2>&1; then
  sha256_of() { sha256sum "$1" | cut -d ' ' -f 1; }
elif command -v shasum >/dev/null 2>&1; then
  sha256_of() { shasum -a 256 "$1" | cut -d ' ' -f 1; }
else
  fail "sha256sum or shasum is needed"
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
trap 'exit 130' INT TERM

asset="uv-$arch-unknown-linux-musl.tar.gz"
say "downloading uv $UV_VERSION"
curl --proto '=https' --tlsv1.2 -fsSL -o "$work/$asset" \
  "https://github.com/astral-sh/uv/releases/download/$UV_VERSION/$asset"
[ "$(sha256_of "$work/$asset")" = "$uv_sha256" ] \
  || fail "uv $UV_VERSION is not the build its SHA-256 names: not running it"
tar -xzf "$work/$asset" -C "$work"
uv="$work/uv-$arch-unknown-linux-musl/uv"

package="${ARTZAIN_PACKAGE:-artzain[openshell]==$ARTZAIN_VERSION}"
say "installing $package"
"$uv" tool install --force --managed-python --python '>=3.11' "$package"
artzain="$("$uv" tool dir --bin)/artzain"
[ -x "$artzain" ] || fail "uv did not install artzain where it says its tools go"

say "connecting this host's gateway"
status=0
"$artzain" connect openshell up "$@" || status=$?
say "artzain is $artzain: \`$artzain connect openshell status\`, \`doctor\` and \`remove\` run from there"
exit "$status"
"""


def render(version: str) -> str:
    """The connect script for ``artzain`` *version* (``major.minor.patch``)."""
    if not _VERSION.fullmatch(version or ""):
        raise ValueError("version must be major.minor.patch, e.g. 0.6.37")
    if tuple(int(part) for part in version.split(".")) < FIRST_VERSION:
        raise ValueError("artzain has `connect openshell` from 0.6.36 on")
    return (_SCRIPT.replace("@ARTZAIN_VERSION@", version)
            .replace("@UV_VERSION@", UV_VERSION)
            .replace("@UV_SHA256_X86_64@", UV_SHA256["x86_64"])
            .replace("@UV_SHA256_AARCH64@", UV_SHA256["aarch64"]))


def sha256(version: str) -> str:
    """The SHA-256 of :func:`render`'s script for *version*, as the
    dashboard shows it and ``sha256sum -c`` checks it."""
    return hashlib.sha256(render(version).encode("utf-8")).hexdigest()


def main(argv: list) -> int:
    if len(argv) != 1:
        print("usage: python bootstrap.py <version>", file=sys.stderr)
        return 2
    try:
        script = render(argv[0])
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    sys.stdout.buffer.write(script.encode("utf-8"))  # LF, whatever the platform
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
