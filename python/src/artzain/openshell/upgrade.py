"""What ``artzain connect openshell upgrade`` reads, checks and runs.

The mirror (CogNEXUSlabs/cognexus-tools) publishes the OpenShell
compatibility manifest at each ``compat-v<serial>`` release: which artzain
release passed conformance with which OpenShell release, and the SHA-256 of
each artzain release's connect script. Its ``openshell-compat.yml`` signs it
keyless (cosign sign-blob) as that workflow at that tag. ``upgrade``
verifies the signature with cosign, downloaded by a SHA-256 pinned here (as
the connect script pins uv), and moves a gateway only to a pair the manifest
lists, by running that release's connect script, checked against the
SHA-256 the manifest names.

Nothing here decides; :func:`artzain.openshell.connect.upgrade` does. The
host is duck-typed (``run``, ``which``): the same ``Host`` connect uses.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Mapping, Tuple

MIRROR = "CogNEXUSlabs/cognexus-tools"
#: The compat-v tags, newest serial last or anywhere: they are sorted here.
TAGS_URL = f"https://api.github.com/repos/{MIRROR}/git/matching-refs/tags/compat-v"
RELEASES = f"https://github.com/{MIRROR}/releases/download/"
MANIFEST = "openshell-compat.json"
BUNDLE = "openshell-compat.json.sigstore.json"

#: Who signed it: the mirror's openshell-compat.yml at a compat-v tag.
ISSUER = "https://token.actions.githubusercontent.com"
IDENTITY = (r"^https://github\.com/CogNEXUSlabs/cognexus-tools/\.github/workflows/"
            r"openshell-compat\.yml@refs/tags/compat-v[0-9]+$")

#: cosign, the 2.x release the mirror's workflows sign with, by
#: ``uname -m``, with the SHA-256 its cosign_checksums.txt lists (and the
#: release API's asset digest).
COSIGN_VERSION = "v2.6.5"
COSIGN_RELEASE = f"https://github.com/sigstore/cosign/releases/download/{COSIGN_VERSION}/"
COSIGN: Mapping[str, Tuple[str, str]] = {
    "x86_64": ("cosign-linux-amd64",
               "c3b4f5410e608af03a5eb0aaac84a4313d8da131248e08ff1759ac70c79d1644"),
    "aarch64": ("cosign-linux-arm64",
                "426193b4c5da4d4d643e822f48fe0cc8a476ca1782a272704831f5a0cef716d7"),
}
#: The name it is kept under, in the sidecar's state folder.
COSIGN_NAME = f"cosign-{COSIGN_VERSION}"

KIND = "artzain.openshell.compat"
VERSION = 2
_SEMVER = re.compile(r"\d+\.\d+\.\d+")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_TAG = re.compile(r"refs/tags/compat-v([1-9][0-9]{0,8})")
_PAIR_KEYS = {"artzain", "openshell", "verified", "conformance_run", "connect_script_sha256"}


class UpgradeError(Exception):
    """The upgrade cannot go on; the message says why."""


def key(version: str) -> Tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def _said(done: Any) -> str:
    return " ".join(((done.stderr or "") + " " + (done.stdout or "")).split())[-300:]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def fetch(host: Any, url: str, path: Path, *, what: str) -> None:
    """Download *url* to *path* with curl, as the connect script does."""
    done = host.run("curl", "--proto", "=https", "--tlsv1.2", "-fsSL", "--retry", "3",
                    "-o", str(path), url, timeout=600)
    if done.returncode != 0 or not path.is_file():
        raise UpgradeError(f"downloading {what} failed: {_said(done)}")


def newest_serial(host: Any, work: Path) -> int:
    """The highest ``compat-v<serial>`` tag on the mirror."""
    listing = work / "compat-tags.json"
    fetch(host, TAGS_URL, listing, what="the list of compat-v tags")
    try:
        refs = json.loads(listing.read_text(encoding="utf-8"))
    except ValueError:
        raise UpgradeError("the list of compat-v tags is not JSON") from None
    serials = [int(found.group(1)) for found in (
        _TAG.fullmatch(str(ref.get("ref") or "")) for ref in refs if isinstance(ref, dict))
        if found] if isinstance(refs, list) else []
    if not serials:
        raise UpgradeError(f"{MIRROR} has no signed compatibility manifest yet "
                           "(no compat-v tag)")
    return max(serials)


def cosign(host: Any, state_dir: Path, say: Any) -> Path:
    """cosign, as pinned, kept in *state_dir*/bin for the next run and
    checked against its SHA-256 every time before it runs."""
    done = host.run("uname", "-m", timeout=10)
    arch = (done.stdout or "").strip()
    if arch not in COSIGN:
        raise UpgradeError(f"there is no pinned cosign for {arch or 'this machine'}")
    name, sha = COSIGN[arch]
    kept = state_dir / "bin" / COSIGN_NAME
    if kept.is_file() and _sha256(kept) == sha:
        return kept
    kept.parent.mkdir(parents=True, exist_ok=True)
    partial = kept.with_name(COSIGN_NAME + ".download")
    say(f"downloading cosign {COSIGN_VERSION} ({name}), once, to check signatures with")
    fetch(host, COSIGN_RELEASE + name, partial, what=name)
    if _sha256(partial) != sha:
        partial.unlink()
        raise UpgradeError(f"{name} is not the build its SHA-256 names: not running it")
    os.chmod(partial, 0o755)
    os.replace(partial, kept)
    return kept


def verify(host: Any, cosign_path: Path, manifest: Path, bundle: Path) -> None:
    done = host.run(str(cosign_path), "verify-blob", "--bundle", str(bundle),
                    "--certificate-oidc-issuer", ISSUER,
                    "--certificate-identity-regexp", IDENTITY, str(manifest), timeout=120)
    if done.returncode != 0:
        raise UpgradeError("the compatibility manifest's signature does not verify as "
                           f"{MIRROR}'s openshell-compat.yml: {_said(done)}")


def read(manifest: Path, serial: int) -> Dict[str, Any]:
    """The manifest, when it is one, and its serial is its tag's."""
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except ValueError:
        data = None
    pairs = data.get("pairs") if isinstance(data, dict) else None
    well_formed = (
        isinstance(data, dict) and data.get("kind") == KIND and data.get("version") == VERSION
        and isinstance(data.get("serial"), int) and not isinstance(data.get("serial"), bool)
        and isinstance(pairs, list) and all(
            isinstance(p, dict) and set(p) == _PAIR_KEYS
            and all(isinstance(p[k], str) and _SEMVER.fullmatch(p[k]) for k in ("artzain", "openshell"))
            and isinstance(p["connect_script_sha256"], str)
            and _SHA256.fullmatch(p["connect_script_sha256"]) for p in pairs))
    if not well_formed:
        raise UpgradeError(f"what compat-v{serial} carries is not a compatibility manifest")
    if data["serial"] != serial:
        raise UpgradeError(f"the manifest says serial {data['serial']}, and it was published "
                           f"as compat-v{serial}: not using it")
    return data


def listed(manifest: Mapping[str, Any], openshell: str) -> List[Dict[str, Any]]:
    """The pairs for *openshell*, newest artzain first."""
    return sorted((dict(p) for p in manifest["pairs"] if p["openshell"] == openshell),
                  key=lambda p: key(p["artzain"]), reverse=True)


def script(host: Any, work: Path, pair: Mapping[str, Any]) -> Path:
    """The connect script of *pair*'s artzain release, checked against the
    SHA-256 the signed manifest names."""
    version = pair["artzain"]
    name = f"connect-{version}.sh"
    path = work / name
    fetch(host, f"{RELEASES}python-v{version}/{name}", path, what=name)
    if _sha256(path) != pair["connect_script_sha256"]:
        raise UpgradeError(f"{name} is not the script the signed manifest names: not running it")
    return path
