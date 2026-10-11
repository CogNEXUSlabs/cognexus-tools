"""NVIDIA's OpenShell snap, as ``artzain connect openshell`` binds it.

The snap runs its gateway in one of two modes, and ``up`` binds either:

* **system**: a root service of the snap. It is ``openshell.gateway`` in
  0.1.3, and ``openshell.system-gateway`` from 0.1.4, where ``snap get
  openshell gateway-mode`` is ``system`` (a 0.1.3 install becomes it when it
  is refreshed). Its ``gateway.toml`` and keys are in
  ``/var/snap/openshell/common``. The snap's AppArmor profile lets the
  gateway connect to a socket there and nowhere else, so the sidecar runs as
  a system service, as the operator, with its socket in a folder of the
  operator's under that folder. The files ``up`` writes for it are root's,
  and go in with ``sudo``.
* **user**: from 0.1.4, a fresh install's default: ``openshell.user-gateway``,
  a snap user service. Its ``gateway.toml`` and keys are under
  ``~/snap/openshell/common``, and the sidecar's socket is in
  ``/run/user/<uid>/snap.openshell``, where the snap's profile lets it
  connect. Nothing ``up`` writes is root's.

Snaps refresh themselves. ``up`` holds the snap's refreshes, so that
OpenShell stays the release the configuration was approved for until the
operator moves it; ``remove`` lifts a hold ``up`` put.

The snap's ``openshell`` CLI is started by snap-confine, which is setuid:
the sidecar's unit does not set ``NoNewPrivileges``, or its listing fails.

This module reads the snap and renders what ``up`` writes; ``connect``
decides when.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

SNAP = "openshell"
COMMON = "/var/snap/openshell/common"
#: The system gateway's app: 0.1.3's, then the name from 0.1.4.
SYSTEM_APPS = ("gateway", "system-gateway")
USER_APP = "user-gateway"
MODE_SYSTEM = "system"
MODE_USER = "user"
#: The id the snap's gateway signs its calls with (its generated JWT bundle).
JWT_GATEWAY_ID = "openshell"
#: The sidecar's folder: under ``COMMON`` (system), or under the snap's
#: runtime folder ``/run/user/<uid>/snap.openshell`` (user).
FOLDER = "artzain"
SOCKET = "openshell.sock"
#: The gateway's public key, as the system sidecar's unit copies it out of
#: the snap's root-only TLS folder.
JWT_COPY = "gateway-jwt.pem"
DROPIN = "50-artzain.conf"
SIDECAR_UNIT = "artzain-openshell-sidecar.service"
#: Where the snap keeps a user's files, under the home folder.
USER_COMMON = ("snap", "openshell", "common")

_VERSION = re.compile(r"(\d+)\.(\d+)\.(\d+)")
_REVISION = re.compile(r"^x?\d+$")
_UNSAFE = re.compile(r"[\x00-\x1f\x7f\"'\\$%`;&|<>(){}*?\[\]~!#]")


def _refused(message: str) -> Exception:
    from artzain.openshell.connect import ConnectError

    return ConnectError(message)


def _said(done: Any) -> str:
    text = re.sub(r"\x1b\[[0-9;]*m", "", (done.stderr or "") + " " + (done.stdout or ""))
    return " ".join(text.split())[-300:]


@dataclass(frozen=True)
class Gateway:
    """The snap's gateway: its mode, the app that runs it, and what ``snap
    list`` says of the snap."""

    mode: str
    app: str
    version: str
    revision: str
    held: bool

    @property
    def unit(self) -> str:
        """The gateway's systemd unit (the system manager's, or the user's)."""
        return f"snap.{SNAP}.{self.app}.service"

    @property
    def system(self) -> bool:
        return self.mode == MODE_SYSTEM

    def facts(self) -> Dict[str, Any]:
        """What the connect record keeps of it."""
        return {"mode": self.mode, "app": self.app, "revision": self.revision,
                "version": self.version}


def _rows(text: str) -> List[List[str]]:
    lines = [line for line in (text or "").splitlines() if line.strip()]
    return [line.split() for line in lines[1:]]


def find(host: Any) -> Optional[Gateway]:
    """The OpenShell snap's gateway on this host, or None when the snap is
    not installed. Raises when the snap runs no gateway."""
    if not host.which("snap"):
        return None
    listed = host.run("snap", "list", SNAP, "--unicode=never", "--color=never", timeout=30)
    if listed.returncode != 0:
        return None
    row = next((r for r in _rows(listed.stdout) if r and r[0] == SNAP), None)
    if row is None or len(row) < 3:
        raise _refused(f"`snap list {SNAP}` did not say the snap's version")
    found = _VERSION.search(row[1])
    if not found or not _REVISION.fullmatch(row[2]):
        raise _refused(f"`snap list {SNAP}` did not say the snap's version and revision")
    notes = row[5] if len(row) > 5 else (row[-1] if len(row) > 3 else "")
    held = "held" in notes.split(",")
    # `snap services` takes neither --unicode nor --color, and prints plain text.
    services = host.run("snap", "services", SNAP, timeout=30)
    if services.returncode != 0:
        raise _refused(f"`snap services {SNAP}` failed: {_said(services)}")
    startup = {r[0]: r[1] for r in _rows(services.stdout) if len(r) >= 2}
    common = dict(version=found.group(0), revision=row[2], held=held)
    if f"{SNAP}.gateway" in startup:
        return Gateway(MODE_SYSTEM, "gateway", **common)
    if startup.get(f"{SNAP}.system-gateway") == "enabled":
        return Gateway(MODE_SYSTEM, "system-gateway", **common)
    if startup.get(f"{SNAP}.{USER_APP}") == "enabled":
        return Gateway(MODE_USER, USER_APP, **common)
    raise _refused(f"the {SNAP} snap runs no gateway: choose one with `sudo snap set {SNAP} "
                   "gateway-mode=user` (or `=system`), then run this again")


def recorded(facts: Mapping[str, Any], current: Optional[Gateway]) -> Gateway:
    """The gateway a connect record names. When the snap now runs a gateway
    in the same mode (a 0.1.3 system gateway refreshed to 0.1.4 runs as
    ``system-gateway``), that one."""
    mode, app = facts.get("mode"), facts.get("app")
    if mode not in (MODE_SYSTEM, MODE_USER) or not isinstance(app, str) or app not in (
            *SYSTEM_APPS, USER_APP):
        raise _refused("the connect record names no snap gateway this artzain knows")
    if current is not None and current.mode == mode:
        return current
    return Gateway(str(mode), app, str(facts.get("version") or ""),
                   str(facts.get("revision") or ""), False)


# ---------------------------------------------------------------------------
# Where things are
# ---------------------------------------------------------------------------


def user_common(host: Any) -> Path:
    return host.home.joinpath(*USER_COMMON)


def gateway_toml(host: Any, gateway: Gateway) -> Path:
    if gateway.system:
        return host.system(f"{COMMON}/gateway.toml")
    return user_common(host) / ".config" / "openshell" / "gateway.toml"


def folder(host: Any, gateway: Gateway) -> Path:
    """The sidecar's folder, where its socket is."""
    if gateway.system:
        return host.system(f"{COMMON}/{FOLDER}")
    return host.runtime_dir / f"snap.{SNAP}" / FOLDER


def socket(host: Any, gateway: Gateway) -> Path:
    return folder(host, gateway) / SOCKET


def candidate(host: Any, gateway: Gateway) -> Path:
    """Where ``up`` puts ``gateway.toml`` as it would be, for the gateway's
    own preflight to read from inside the snap."""
    if gateway.system:
        return folder(host, gateway) / "gateway.toml.candidate"
    return user_common(host) / FOLDER / "gateway.toml.candidate"


def jwt_key(host: Any, gateway: Gateway) -> Path:
    """The public half of the JWT bundle the snap's gateway generates."""
    if gateway.system:
        return host.system(f"{COMMON}/tls/jwt/public.pem")
    return user_common(host) / ".local" / "state" / "openshell" / "tls" / "jwt" / "public.pem"


def sidecar_jwt(host: Any, gateway: Gateway, key: Path) -> Path:
    """Where the sidecar reads the gateway's public *key*: the system
    sidecar's unit copies it next to the socket, out of a folder of root's."""
    return folder(host, gateway) / JWT_COPY if gateway.system else key


def units(host: Any, gateway: Gateway) -> Path:
    """The folder of the units ``up`` writes: the system manager's, or the
    operator's own."""
    if gateway.system:
        return host.system("/etc/systemd/system")
    return host.config_home / "systemd" / "user"


def dropins(host: Any, gateway: Gateway) -> Tuple[Path, ...]:
    """The drop-ins that make the gateway wait for the sidecar. The system
    gateway gets one for each name its app has had, so that a refresh from
    0.1.3 to 0.1.4 keeps it bound."""
    apps = SYSTEM_APPS if gateway.system else (USER_APP,)
    return tuple(units(host, gateway) / f"snap.{SNAP}.{app}.service.d" / DROPIN for app in apps)


def sidecar_unit_path(host: Any, gateway: Gateway) -> Path:
    return units(host, gateway) / SIDECAR_UNIT


# ---------------------------------------------------------------------------
# What up writes
# ---------------------------------------------------------------------------


def sidecar_unit(host: Any, gateway: Gateway, *, python: str, settings: Path,
                 key: Optional[Path]) -> str:
    """The sidecar's unit. The system one runs as the operator, and makes
    its folder (and copies the gateway's *key*) as root first."""
    for value in (python, settings.as_posix(), *(() if key is None else (key.as_posix(),))):
        if _UNSAFE.search(value) or " " in value or not value.startswith("/"):
            raise _refused(f"{value} is a path a systemd unit cannot name here")
    before = " ".join(f"snap.{SNAP}.{app}.service" for app in (
        SYSTEM_APPS if gateway.system else (USER_APP,)))
    lines = [
        "# Written by `artzain connect openshell up`; `artzain connect openshell remove`",
        "# deletes it.",
        "[Unit]",
        "Description=ArtzAIn sidecar for the OpenShell gateway (snap)",
        f"Before={before}",
        "",
        "[Service]",
        # Started once it serves (sd_notify READY=1): the gateway's unit is
        # ordered after this one, and must not start before the socket is there.
        "Type=notify",
        "NotifyAccess=main",
    ]
    if gateway.system:
        where = folder(host, gateway).as_posix()
        uid, gid = host.uid, host.gid
        lines += [
            f"User={uid}",
            f"Group={gid}",
            "# The gateway's AppArmor profile lets it connect only under the snap's",
            "# own folder: the socket's folder is made there, the operator's alone.",
            f"ExecStartPre=+/usr/bin/install -d -o {uid} -g {gid} -m 0700 {where}",
        ]
        if key is not None:
            lines += [
                "# The gateway's public key is in a folder of root's: a copy goes next",
                "# to the socket, for the sidecar to check the gateway's calls with.",
                f"ExecStartPre=+/usr/bin/install -o {uid} -g {gid} -m 0644 {key.as_posix()} "
                f"{where}/{JWT_COPY}",
            ]
    lines += [
        f"EnvironmentFile={settings.as_posix()}",
        f'ExecStart="{python}" -m artzain.cli openshell sidecar',
        "Restart=on-failure",
        "RestartSec=2s",
        "UMask=0077",
        "# No NoNewPrivileges: the sidecar lists sandboxes with the snap's openshell",
        "# CLI, which snap-confine (setuid) starts.",
        "",
        "[Install]",
        "WantedBy=multi-user.target" if gateway.system else "WantedBy=default.target",
    ]
    return "\n".join(lines) + "\n"


def dropin(telemetry: bool) -> str:
    """The gateway's drop-in: it starts after the sidecar and stops with it,
    and carries the telemetry choice, as the snap's gateway reads no
    ``gateway.env``."""
    return (
        "# Written by `artzain connect openshell up`; `artzain connect openshell remove`\n"
        "# deletes it. The gateway refuses to start while its interceptor does not\n"
        "# answer, so it starts after the sidecar, and stops with it. The snap's\n"
        "# gateway reads no gateway.env: its telemetry choice is set here.\n"
        "[Unit]\n"
        f"Requires={SIDECAR_UNIT}\n"
        f"After={SIDECAR_UNIT}\n"
        "\n"
        "[Service]\n"
        f"Environment=OPENSHELL_TELEMETRY_ENABLED={'true' if telemetry else 'false'}\n"
    )


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def systemctl(host: Any, gateway: Gateway, *args: str,
              timeout: float = 60.0) -> subprocess.CompletedProcess:
    """``systemctl`` on the manager the gateway runs under: the system's
    (through ``sudo``, but for what only reads), or the operator's own."""
    if not gateway.system:
        return host.run("systemctl", "--user", *args, timeout=timeout)
    if args and args[0] in ("is-active", "show", "cat"):
        return host.run("systemctl", *args, timeout=timeout)
    return host.run("sudo", "systemctl", *args, timeout=timeout)


def read(host: Any, path: Path) -> Optional[bytes]:
    """*path*'s bytes, or None when it does not exist. A file of root's that
    only root reads is read through ``sudo``."""
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return None
    except PermissionError:
        done = host.run("sudo", "cat", "--", path.as_posix(), timeout=30)
        if done.returncode != 0:
            raise _refused(f"{path} cannot be read, even with sudo: {_said(done)}") from None
        return done.stdout.encode("utf-8") if isinstance(done.stdout, str) else done.stdout


def put(host: Any, path: Path, data: bytes, *, mode: int = 0o644) -> None:
    """Write *path* whole as root (``sudo install``), from a file of the
    operator's alone, so that nobody sees it half written."""
    work = Path(tempfile.mkdtemp(prefix="artzain-snap-"))
    try:
        source = work / path.name
        source.write_bytes(data)
        if hasattr(os, "chmod"):
            os.chmod(source, 0o600)
        done = host.run("sudo", "install", "-D", "-m", f"{mode:04o}", "-o", "root", "-g", "root",
                        "--", source.as_posix(), path.as_posix(), timeout=60)
        if done.returncode != 0:
            raise _refused(f"writing {path} with sudo failed: {_said(done)}")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def delete(host: Any, path: Path) -> bool:
    """Remove *path*, a file of root's, and its drop-in folder when that is
    then empty. True when it was there."""
    if not path.exists():
        return False
    done = host.run("sudo", "rm", "-f", "--", path.as_posix(), timeout=30)
    if done.returncode != 0:
        raise _refused(f"removing {path} with sudo failed: {_said(done)}")
    if path.parent.name.endswith(".service.d"):
        host.run("sudo", "rmdir", "--ignore-fail-on-non-empty", "--", path.parent.as_posix(),
                 timeout=30)
    return True


def preflight(host: Any, gateway: Gateway, trial: Path) -> subprocess.CompletedProcess:
    """The gateway's own ``config preflight`` of *trial*, run inside the
    snap as its gateway app (the gateway binary is the snap's own)."""
    path = trial.as_posix()
    if _UNSAFE.search(path) or " " in path:
        raise _refused(f"{path} is a path the preflight cannot be given")
    argv = ["snap", "run", "--shell", f"{SNAP}.{gateway.app}", "-c",
            f'"$SNAP/bin/openshell-gateway" config preflight --path {path}']
    return host.run(*(["sudo", *argv] if gateway.system else argv), timeout=120)


def restart(host: Any, gateway: Gateway) -> subprocess.CompletedProcess:
    """Restart the gateway. A gateway that failed to start five times in a
    row is left failed by systemd until that is reset."""
    systemctl(host, gateway, "reset-failed", gateway.unit, timeout=30)
    return systemctl(host, gateway, "restart", gateway.unit, timeout=120)


def active(host: Any, gateway: Gateway) -> str:
    return systemctl(host, gateway, "is-active", gateway.unit, timeout=10).stdout.strip()


def hold(host: Any) -> subprocess.CompletedProcess:
    """Hold the snap's refreshes: OpenShell stays this release until the
    operator refreshes it themselves."""
    return host.run("sudo", "snap", "refresh", "--hold", SNAP, timeout=60)


def unhold(host: Any) -> subprocess.CompletedProcess:
    return host.run("sudo", "snap", "refresh", "--unhold", SNAP, timeout=60)


__all__ = ["COMMON", "Gateway", "MODE_SYSTEM", "MODE_USER", "SNAP", "SYSTEM_APPS", "USER_APP",
           "active", "candidate", "delete", "dropin", "dropins", "find", "folder",
           "gateway_toml", "hold", "jwt_key", "preflight", "put", "read", "recorded", "restart",
           "sidecar_jwt", "sidecar_unit", "sidecar_unit_path", "socket", "systemctl", "unhold"]
