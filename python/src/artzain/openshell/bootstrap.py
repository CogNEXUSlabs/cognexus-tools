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
3. Makes an environment of its own, ``venv-<version>`` under
   ``$XDG_DATA_HOME/artzain/openshell`` (``~/.local/share`` by default), on
   Python :data:`PYTHON` as uv manages it: a lasting one, which the
   sidecar's service runs from. Into it go the wheels :data:`REQUIREMENTS`
   names, then ``artzain`` itself, each checked against the SHA-256 the
   script carries (``uv pip install --require-hashes``, wheels only). uv's
   tool install, which earlier scripts used, checks no hash. An environment
   that already holds this version is used as it is.
4. Runs ``artzain connect openshell up`` with the script's own arguments.
   The enroll token stays in ``ARTZAIN_ENROLL_TOKEN``, where ``up`` reads it.
   ``up`` moves the service to this environment.
5. After a good ``up``: points ``$XDG_BIN_HOME/artzain`` (``~/.local/bin``)
   here, and takes away what an earlier script installed: another
   version's environment, and an ``artzain`` uv tool.

``ARTZAIN_PACKAGE``, when set, is the artzain step 3 installs instead,
without a hash: a wheel of a build under test, on the locked dependencies.
The published command never sets it.

:func:`render` writes the script from a version and its wheel's SHA-256;
``python bootstrap.py <version> <wheel sha256>`` prints it. This file uses
the standard library only, so the release job runs it by its path, with no
``artzain`` installed.
"""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

#: The uv the script installs with, and the SHA-256 of each static build,
#: from its GitHub release (each asset's ``.sha256`` file and GitHub's own
#: digest agree). The engine repository's ``packaging/local-setup`` pins the
#: same version; a test there holds the two together.
UV_VERSION = "0.8.15"
UV_SHA256 = {
    "x86_64": "d0fec58f3124e05e0a1af0f6541abfce4333253cdaf23c7b6bb2e6128bf138ea",
    "aarch64": "23ea21a05c62c4c307ce691f29bff2f15c94c4f07f2b83d9b356f0664bc8b3a2",
}
#: The Python the environment runs on: the one :data:`REQUIREMENTS` is
#: locked for.
PYTHON = "3.12"
#: What ``artzain[openshell]`` needs from other projects, every wheel by its
#: SHA-256: the sidecar image's own lock, held equal to it by a test.
REQUIREMENTS = Path(__file__).with_name("sidecar-requirements.lock")

_VERSION = re.compile(r"\d+\.\d+\.\d+")
_SHA256 = re.compile(r"[0-9a-f]{64}")
#: The first ``artzain`` whose script installs from hash-locked wheels.
FIRST_VERSION = (0, 6, 41)

_SCRIPT = r"""#!/bin/sh
# Connect this host's OpenShell gateway to ArtzAIn (artzain @ARTZAIN_VERSION@).
#
# Run it as the user the gateway runs as, with the enroll token you were
# given in ARTZAIN_ENROLL_TOKEN:
#
#   ARTZAIN_ENROLL_TOKEN=... sh connect-@ARTZAIN_VERSION@.sh --config-digest <digest>
#
# It installs uv @UV_VERSION@ (checked against its SHA-256), installs
# artzain @ARTZAIN_VERSION@ and what it needs into an environment of its own,
# every wheel checked against the SHA-256 written below, and runs
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

data="${XDG_DATA_HOME:-$HOME/.local/share}/artzain/openshell"
venv="$data/venv-$ARTZAIN_VERSION"
bin="${XDG_BIN_HOME:-$HOME/.local/bin}"

# What artzain needs from other projects, then artzain itself: every wheel
# named by its SHA-256. uv installs nothing they do not name.
cat > "$work/requirements.lock" <<'ARTZAIN_LOCK'
@REQUIREMENTS@
ARTZAIN_LOCK
cat > "$work/artzain.lock" <<'ARTZAIN_LOCK'
artzain==@ARTZAIN_VERSION@ \
    --hash=sha256:@WHEEL_SHA256@
ARTZAIN_LOCK

installed() {
  [ -x "$venv/bin/artzain" ] && "$venv/bin/python" -c \
    'import sys, artzain; sys.exit(artzain.__version__ != sys.argv[1])' "$ARTZAIN_VERSION" \
    >/dev/null 2>&1
}
if [ -z "${ARTZAIN_PACKAGE:-}" ] && installed; then
  # The service may be running from it: it is not taken away underneath.
  say "artzain $ARTZAIN_VERSION is installed in $venv already"
else
  rm -rf "$venv"
  say "making $venv, on Python @PYTHON@ as uv manages it"
  "$uv" venv --quiet --managed-python --python @PYTHON@ "$venv"
  say "installing what artzain needs, every wheel checked against its SHA-256"
  "$uv" pip install --quiet --python "$venv/bin/python" --require-hashes --only-binary :all: \
    -r "$work/requirements.lock"
  if [ -n "${ARTZAIN_PACKAGE:-}" ]; then
    say "installing $ARTZAIN_PACKAGE"
    "$uv" pip install --quiet --python "$venv/bin/python" --no-deps "$ARTZAIN_PACKAGE"
  else
    say "installing artzain $ARTZAIN_VERSION, checked against its SHA-256"
    "$uv" pip install --quiet --python "$venv/bin/python" --no-deps --require-hashes \
      --only-binary :all: -r "$work/artzain.lock"
  fi
fi
artzain="$venv/bin/artzain"
[ -x "$artzain" ] || fail "uv did not install artzain in $venv"

say "connecting this host's gateway"
status=0
"$artzain" connect openshell up "$@" || status=$?
if [ "$status" != 0 ]; then
  say "artzain is $artzain: \`status\`, \`doctor\` and \`remove\` run from there"
  exit "$status"
fi

# The service runs from $venv now. What an earlier script installed goes:
# artzain as a uv tool (0.6.40 and before), and other versions' environments.
if "$uv" tool list 2>/dev/null | grep -q '^artzain '; then
  "$uv" tool uninstall artzain >/dev/null 2>&1 \
    || say "the artzain an earlier script installed stays: \`uv tool uninstall artzain\`"
fi
for old in "$data"/venv-*; do
  if [ -d "$old" ] && [ "$old" != "$venv" ]; then rm -rf "$old"; fi
done
mkdir -p "$bin"
ln -sfn "$artzain" "$bin/artzain"
say "artzain is $bin/artzain: \`artzain connect openshell status\`, \`doctor\` and \`remove\` run from there"
exit 0
"""


def render(version: str, wheel_sha256: str) -> str:
    """The connect script for ``artzain`` *version* (``major.minor.patch``),
    whose wheel on PyPI has the SHA-256 *wheel_sha256*."""
    if not _VERSION.fullmatch(version or ""):
        raise ValueError("version must be major.minor.patch, e.g. 0.6.41")
    if tuple(int(part) for part in version.split(".")) < FIRST_VERSION:
        raise ValueError("the script installs from hash-locked wheels from artzain 0.6.41 on")
    if not _SHA256.fullmatch(wheel_sha256 or ""):
        raise ValueError("the wheel's SHA-256 must be 64 lowercase hex characters")
    requirements = REQUIREMENTS.read_text(encoding="utf-8").rstrip("\n")
    return (_SCRIPT.replace("@ARTZAIN_VERSION@", version)
            .replace("@UV_VERSION@", UV_VERSION)
            .replace("@UV_SHA256_X86_64@", UV_SHA256["x86_64"])
            .replace("@UV_SHA256_AARCH64@", UV_SHA256["aarch64"])
            .replace("@PYTHON@", PYTHON)
            .replace("@WHEEL_SHA256@", wheel_sha256)
            .replace("@REQUIREMENTS@", requirements))


def sha256(version: str, wheel_sha256: str) -> str:
    """The SHA-256 of :func:`render`'s script, as the dashboard shows it
    and ``sha256sum -c`` checks it."""
    return hashlib.sha256(render(version, wheel_sha256).encode("utf-8")).hexdigest()


def main(argv: list) -> int:
    if len(argv) != 2:
        print("usage: python bootstrap.py <version> <wheel sha256>", file=sys.stderr)
        return 2
    try:
        script = render(argv[0], argv[1])
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    sys.stdout.buffer.write(script.encode("utf-8"))  # LF, whatever the platform
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
