"""Install OpenShell on a host that has none, for ``artzain connect openshell up``.

``up`` binds the gateway OpenShell's deb or rpm package installs. On a host
without it, this installs NVIDIA's packages of the release this artzain is
pinned to (:data:`artzain.openshell.interceptor.PINNED_OPENSHELL`), each
checked against the SHA-256 written below before anything runs as root, then
starts the gateway's user service and registers it with the ``openshell``
CLI. Those are the steps NVIDIA's ``install.sh`` takes for a deb or rpm host;
here every package is pinned by this artzain release, not by a checksums
file fetched beside it.

Nothing here decides whether to install: ``up`` does, and only when it was
told to (``--install-openshell``) or the person at the terminal said yes.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, List, Mapping, Tuple

#: The OpenShell release installed: the one the interceptor is pinned to.
RELEASE = "0.1.9"
BASE_URL = f"https://github.com/NVIDIA/OpenShell/releases/download/v{RELEASE}/"

#: NVIDIA's packages of :data:`RELEASE`, by architecture as the package
#: manager names it, with the SHA-256 the release's
#: ``openshell-checksums-sha256.txt`` lists (read 24 November 2026). The rpm
#: release is three packages, installed together.
DEB: Mapping[str, Tuple[Tuple[str, str], ...]] = {
    "amd64": (("openshell_0.1.9-1_amd64.deb",
               "5d3c758fe1860625cd28b0791865b25e25912acacdc99c8ce1c6071a95ef360b"),),
    "arm64": (("openshell_0.1.9-1_arm64.deb",
               "3661dfd83aadd8dd7b94ccb35b52c120bea614c9a63b6b5182b9626187e19232"),),
}
RPM: Mapping[str, Tuple[Tuple[str, str], ...]] = {
    "x86_64": (
        ("openshell-0.1.9-1.fc44.x86_64.rpm",
         "e13436babd3687f1cb494898dff490ac2ff266e303af7dfca1fec376ab74c957"),
        ("openshell-gateway-0.1.9-1.fc44.x86_64.rpm",
         "2293b23e51bf87ff977dfe6f8456e421d66ce716790a74656fffbbde95580bcb"),
        ("openshell-prover-0.1.9-1.fc44.x86_64.rpm",
         "2612495c189e0ac3d1bb57a4f44f71d0491e747dfe4723637bb182d116762b03"),
    ),
    "aarch64": (
        ("openshell-0.1.9-1.fc44.aarch64.rpm",
         "9c645c428a1b576007df589ac0384e4dba486b7d6747e5cf01469463325f0a14"),
        ("openshell-gateway-0.1.9-1.fc44.aarch64.rpm",
         "a31171a0cc7b6f269f704f4b93d0766d18c4f593bc693532a23d5a9c463793c5"),
        ("openshell-prover-0.1.9-1.fc44.aarch64.rpm",
         "4d31d136c273bd73f9daf8c48da92b48b8cfbfd638ae7ccbedd5b1ba37ec8467"),
    ),
}

#: Where the package's gateway listens, and the name the CLI knows it by.
GATEWAY_ENDPOINT = "https://127.0.0.1:17670"
GATEWAY_UNIT = "openshell-gateway"
#: How long the gateway gets to answer the CLI once it is started.
GATEWAY_WAIT_SECONDS = 60.0

_ARCH = re.compile(r"[A-Za-z0-9_]+")


class InstallError(Exception):
    """OpenShell could not be installed here; the message says why."""


@dataclass(frozen=True)
class Plan:
    """What installing OpenShell on this host means."""

    kind: str                                  # "deb" or "rpm"
    arch: str
    packages: Tuple[Tuple[str, str], ...]      # (file name, SHA-256)
    installer: Tuple[str, ...]                 # the command, before the package files
    sudo: bool                                 # not root: the installer runs under sudo

    def by_hand(self) -> List[str]:
        """The same steps as shell lines, for a person to run."""
        lines: List[str] = []
        for name, sha in self.packages:
            lines.append(f"curl -fsSLO {BASE_URL}{name}")
            lines.append(f"echo '{sha}  {name}' | sha256sum -c -")
        command = [c for c in self.installer if not c.startswith("DEBIAN_FRONTEND=") and c != "env"]
        lines.append(" ".join([*(["sudo"] if self.sudo else []), *command,
                               *("./" + name for name, _sha in self.packages)]))
        return lines

    @property
    def tool(self) -> str:
        """The package manager that installs."""
        return self.installer[2] if self.installer[0] == "env" else self.installer[0]


def _arch(host: Any, argv: List[str]) -> str:
    done = host.run(*argv, timeout=30)
    value = (done.stdout or "").strip()
    if done.returncode != 0 or not _ARCH.fullmatch(value):
        raise InstallError(f"`{' '.join(argv)}` did not say this host's architecture")
    return value


def plan(host: Any) -> Plan:
    """The packages for this host's format and architecture, and how they go in.
    Raises :class:`InstallError` when NVIDIA publishes none for it."""
    if host.which("dpkg"):
        kind, arch = "deb", _arch(host, ["dpkg", "--print-architecture"])
        table = DEB
        if host.which("apt-get"):
            installer: Tuple[str, ...] = ("env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install",
                                          "-y", "--no-install-recommends")
        else:
            installer = ("dpkg", "-i")
    elif host.which("rpm"):
        kind, arch = "rpm", _arch(host, ["rpm", "--eval", "%{_arch}"])
        table = RPM
        if host.which("dnf"):
            installer = ("dnf", "install", "-y")
        elif host.which("yum"):
            installer = ("yum", "install", "-y")
        elif host.which("zypper"):
            installer = ("zypper", "--non-interactive", "install", "--allow-unsigned-rpm")
        else:
            installer = ("rpm", "-Uvh", "--replacepkgs")
    else:
        raise InstallError("this host has neither dpkg nor rpm: OpenShell's packages are deb and rpm")
    if arch not in table:
        raise InstallError(f"NVIDIA publishes no OpenShell {RELEASE} package for {arch} ({kind})")
    return Plan(kind, arch, tuple(table[arch]), installer, sudo=host.uid != 0)


def _said(done: Any) -> str:
    return " ".join(((done.stderr or "") + " " + (done.stdout or "")).split())[-300:]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def install(host: Any, plan: Plan, *, say: Callable[[str], None]) -> None:
    """Download, check, install, start and register. Raises
    :class:`InstallError` at the first step that fails; nothing runs as root
    until every package matched its SHA-256."""
    steps = "\n".join("  " + line for line in plan.by_hand())
    if plan.sudo and not host.which("sudo"):
        raise InstallError("sudo is not on PATH: run these as root, then run this again:\n" + steps)
    if not host.which("curl"):
        raise InstallError("curl is not on PATH: install it, or run these yourself:\n" + steps)
    # apt reads the files as its own user: the folder and the files are
    # readable by all and writable by this user alone.
    work = Path(tempfile.mkdtemp(prefix="artzain-openshell-"))
    try:
        os.chmod(work, 0o755)
        files = []
        for name, sha in plan.packages:
            path = work / name
            say(f"downloading {name} from NVIDIA's OpenShell {RELEASE} release")
            done = host.run("curl", "--proto", "=https", "--tlsv1.2", "-fsSL", "--retry", "3",
                            "-o", str(path), BASE_URL + name, timeout=600)
            if done.returncode != 0 or not path.is_file():
                raise InstallError(f"downloading {name} failed: {_said(done)}")
            if _sha256(path) != sha:
                raise InstallError(f"{name} is not the build its SHA-256 names ({sha[:12]}…): "
                                   "not installing it")
            os.chmod(path, 0o644)
            files.append(str(path))
        prefix = ["sudo"] if plan.sudo else []
        say(f"installing OpenShell {RELEASE} with {plan.tool}"
            + (" under sudo (it may ask for your password)" if plan.sudo else ""))
        done = host.run(*prefix, *plan.installer, *files, timeout=900)
        if done.returncode != 0:
            raise InstallError(f"`{' '.join(plan.installer)}` failed: {_said(done)}")
    finally:
        shutil.rmtree(work, ignore_errors=True)

    say(f"starting the {GATEWAY_UNIT} user service and registering it with the openshell CLI")
    for verb in (["daemon-reload"], ["enable", "--now", GATEWAY_UNIT]):
        done = host.run("systemctl", "--user", *verb, timeout=120)
        if done.returncode != 0:
            raise InstallError(f"`systemctl --user {' '.join(verb)}` failed: {_said(done)}")
    done = host.run("openshell", "gateway", "add", GATEWAY_ENDPOINT, "--local", "--name", "openshell",
                    timeout=60)
    if done.returncode != 0 and "already exists" not in _said(done):
        raise InstallError(f"`openshell gateway add {GATEWAY_ENDPOINT} --local --name openshell` "
                           f"failed: {_said(done)}")
    deadline = host.clock() + GATEWAY_WAIT_SECONDS
    while True:
        done = host.run("openshell", "settings", "get", "--global", timeout=30)
        if done.returncode == 0:
            return
        if host.clock() >= deadline:
            raise InstallError(f"the gateway did not answer within {int(GATEWAY_WAIT_SECONDS)} s: see "
                               f"`journalctl --user -u {GATEWAY_UNIT}`: {_said(done)}")
        host.sleep(2.0)
