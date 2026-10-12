"""NVIDIA's OpenShell Homebrew formula, as ``artzain connect openshell`` binds it.

On a Mac with Apple silicon, NVIDIA's formula installs ``openshell`` and
``openshell-gateway``, and ``brew services`` runs the gateway as a launchd
agent of the user who installed it, through the formula's wrapper. The
wrapper reads ``~/.config/openshell/gateway.toml`` when there is one, and
else the formula's ``$(brew --prefix)/var/openshell/gateway.toml``. It
sources ``~/.config/openshell/gateway.env`` when there is one, and else the
formula's ``var/openshell/gateway.env``, and copies the gateway's TLS and JWT
bundle to ``~/.local/state/openshell/homebrew/tls`` at each start.

The sidecar runs beside it as a launchd agent of the same user
(``~/Library/LaunchAgents``), from this ``artzain``, with its settings in the
same ``sidecar.env`` as on Linux and its socket in a folder of the user's
alone. launchd has no start order between two agents: a gateway started
before the sidecar exits and is started again (the formula keeps it alive),
until the sidecar answers. ``up`` waits for that.

:func:`ctl` gives ``connect`` the ``systemctl`` verbs it uses, carried out
with ``launchctl`` (the sidecar's agent) and ``brew services`` (the
gateway's), so the deb's steps run unchanged.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional
from xml.sax.saxutils import escape

FORMULA = "openshell"
#: The sidecar's launchd agent.
LABEL = "ai.cognexuslabs.artzain-openshell-sidecar"
#: The gateway's own JWT bundle, as the formula's wrapper copies it, and the
#: id it signs its calls with.
JWT = (".local", "state", "openshell", "homebrew", "tls", "jwt", "public.pem")
JWT_GATEWAY_ID = "openshell"
#: Where the formula's gateway listens, as NVIDIA's installer registers it.
ENDPOINT = "https://localhost:17670"
#: The longest path a socket can have on macOS (``sun_path`` holds 104
#: bytes, the last one NUL).
SOCKET_MAX = 103
#: A launchd agent's file, and the sidecar's log.
AGENTS = ("Library", "LaunchAgents")
LOG = ("Library", "Logs", "artzain-openshell-sidecar.log")
#: The gateway's log, as the formula's service writes it.
GATEWAY_LOG = "$(brew --prefix)/var/log/openshell/openshell-gateway.err.log"
#: A ``gateway.env`` line that makes the gateway read another file.
_NAMES_ITS_CONFIG = re.compile(r"^\s*(?:export\s+)?OPENSHELL_GATEWAY_CONFIG\s*=", re.M)

_VERSION = re.compile(r"(\d+)\.(\d+)\.(\d+)")
_UNSAFE = re.compile(r"[\x00-\x1f\x7f\"'\\$%`]")


def _refused(message: str) -> Exception:
    from artzain.openshell.connect import ConnectError

    return ConnectError(message)


def _said(done: Any) -> str:
    text = re.sub(r"\x1b\[[0-9;]*m", "", (done.stderr or "") + " " + (done.stdout or ""))
    return " ".join(text.split())[-300:]


def _done(code: int = 0, out: str = "", err: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess([], code, out, err)


@dataclass(frozen=True)
class Gateway:
    """The formula's gateway: Homebrew's prefix, the gateway's release, and
    the two files of the gateway's that ``up`` adds a block to."""

    prefix: Path
    version: str
    gateway_toml: Path
    gateway_env: Path

    def facts(self) -> Dict[str, Any]:
        """What the connect record keeps of it: ``remove`` puts back the files
        ``up`` changed, even when another one would be read by then."""
        return {"prefix": self.prefix.as_posix(), "version": self.version,
                "gateway_toml": self.gateway_toml.as_posix(),
                "gateway_env": self.gateway_env.as_posix()}


def _chosen(host: Any, prefix: Path) -> Dict[str, Path]:
    """The ``gateway.toml`` and ``gateway.env`` the formula's wrapper reads:
    the user's own when there is one, else the formula's when there is one,
    and else the user's own, which ``up`` creates (in a folder of the user's:
    never in Homebrew's). A ``gateway.env`` that names another file for the
    gateway is refused."""
    xdg = host.config_home / "openshell"
    var = prefix / "var" / "openshell"
    toml, env = (next((path for path in (xdg / name, var / name) if path.exists()), xdg / name)
                 for name in ("gateway.toml", "gateway.env"))
    try:
        sourced = env.read_text(encoding="utf-8") if env.is_file() else ""
    except (OSError, UnicodeDecodeError):
        raise _refused(f"{env} cannot be read") from None
    if _NAMES_ITS_CONFIG.search(sourced):
        raise _refused(f"{env} sets OPENSHELL_GATEWAY_CONFIG, so the gateway reads a file of its "
                       "own choosing: take that line out (put the settings in "
                       f"{toml}), then run this again")
    return {"gateway_toml": toml, "gateway_env": env}


def find(host: Any) -> Optional[Gateway]:
    """The formula's gateway on this Mac, or None when Homebrew or the
    formula is not installed."""
    if not host.platform.startswith("darwin") or not host.which("brew"):
        return None
    listed = host.run("brew", "list", "--formula", "--versions", FORMULA, timeout=60)
    if listed.returncode != 0 or not (listed.stdout or "").strip():
        return None
    done = host.run("brew", "--prefix", timeout=60)
    prefix = (done.stdout or "").strip()
    if done.returncode != 0 or not prefix.startswith("/"):
        raise _refused(f"`brew --prefix` did not say where Homebrew is: {_said(done)}")
    done = host.run("openshell-gateway", "--version", timeout=30)
    found = _VERSION.search((done.stdout or "") + " " + (done.stderr or ""))
    if done.returncode != 0 or not found:
        raise _refused("openshell-gateway --version did not say its version")
    return Gateway(Path(prefix), found.group(0), **_chosen(host, Path(prefix)))


def recorded(facts: Mapping[str, Any]) -> Gateway:
    """The gateway a connect record names."""
    try:
        return Gateway(Path(str(facts["prefix"])), str(facts.get("version") or ""),
                       Path(str(facts["gateway_toml"])), Path(str(facts["gateway_env"])))
    except (KeyError, TypeError):
        raise _refused("the connect record names no Homebrew gateway this artzain knows") from None


# ---------------------------------------------------------------------------
# Where things are
# ---------------------------------------------------------------------------


def agent(host: Any) -> Path:
    """The sidecar's launchd agent file."""
    return host.home.joinpath(*AGENTS) / f"{LABEL}.plist"


def socket(host: Any) -> Path:
    """The sidecar's socket, in a folder of the user's alone: a Mac has no
    ``XDG_RUNTIME_DIR``. :func:`check_socket` says whether the gateway can
    connect to it."""
    return host.state_home / "artzain" / "openshell" / "run" / "openshell.sock"


def check_socket(path: Path) -> None:
    """Refuse a socket the gateway could not connect to: longer than
    :data:`SOCKET_MAX`, or with a character the registration cannot carry."""
    named = path.as_posix()
    if len(named.encode("utf-8")) > SOCKET_MAX or any(ch in named for ch in ' "\\'):
        raise _refused(f"{named} is not a path the gateway can connect to (a socket's path "
                       f"holds at most {SOCKET_MAX} bytes, and no space or quote): set "
                       "XDG_STATE_HOME to a shorter folder without one")


def jwt_key(host: Any) -> Path:
    return host.home.joinpath(*JWT)


def log(host: Any) -> Path:
    return host.home.joinpath(*LOG)


# ---------------------------------------------------------------------------
# What up writes
# ---------------------------------------------------------------------------


def sidecar_agent(host: Any, *, python: str, settings: Path) -> str:
    """The sidecar's launchd agent. launchd reads no environment file: the
    agent runs ``sh``, which reads ``sidecar.env`` (its values are quoted,
    and hold no ``$``, quote or backquote) and starts the sidecar."""
    for value in (python, settings.as_posix(), log(host).as_posix()):
        if _UNSAFE.search(value) or not value.startswith("/"):
            raise _refused(f"{value} is a path a launchd agent cannot name here")
    command = (f'set -a; . "{settings.as_posix()}"; set +a; '
               f'exec "{python}" -m artzain.cli openshell sidecar')
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        "<!-- Written by `artzain connect openshell up`; `artzain connect openshell remove`\n"
        "     deletes it. -->\n"
        '<plist version="1.0">\n'
        "<dict>\n"
        f"  <key>Label</key><string>{LABEL}</string>\n"
        "  <key>ProgramArguments</key>\n"
        "  <array>\n"
        "    <string>/bin/sh</string>\n"
        "    <string>-c</string>\n"
        f"    <string>{escape(command)}</string>\n"
        "  </array>\n"
        "  <key>RunAtLoad</key><true/>\n"
        "  <key>KeepAlive</key><true/>\n"
        "  <key>ProcessType</key><string>Background</string>\n"
        "  <!-- 0077: what the sidecar makes is its user's alone. -->\n"
        "  <key>Umask</key><integer>63</integer>\n"
        f"  <key>StandardErrorPath</key><string>{escape(log(host).as_posix())}</string>\n"
        "</dict>\n"
        "</plist>\n"
    )


# ---------------------------------------------------------------------------
# The two services
# ---------------------------------------------------------------------------


def _domain(host: Any) -> str:
    return f"gui/{host.uid}"


#: ``launchctl bootstrap``'s exit while the agent is still loaded, or still
#: being taken out (``bootout`` can return before launchd is done).
_STILL_LOADED = 5
#: How many times, half a second apart, to look again for either.
_TRIES = 20


def _loaded(host: Any) -> bool:
    return host.run("launchctl", "print", f"{_domain(host)}/{LABEL}",
                    timeout=30).returncode == 0


def _bootout(host: Any) -> subprocess.CompletedProcess:
    """Take the sidecar's agent out of launchd, and wait until launchd has:
    ``bootout`` returns while launchd still takes it out. Fails when launchd
    still has it after a few seconds."""
    service = f"{_domain(host)}/{LABEL}"
    done = host.run("launchctl", "bootout", service, timeout=60)
    for _ in range(_TRIES):
        if not _loaded(host):
            return _done()
        host.sleep(0.5)
    return _done(1, "", f"launchd still has {service} ({_said(done)})")


def _bootstrap(host: Any) -> subprocess.CompletedProcess:
    """Load the sidecar's agent from its file, trying again for a few
    seconds while launchd still takes the old one out."""
    for _ in range(_TRIES - 1):
        done = host.run("launchctl", "bootstrap", _domain(host), agent(host).as_posix(),
                        timeout=60)
        if done.returncode != _STILL_LOADED:
            return done
        host.sleep(0.5)
    return host.run("launchctl", "bootstrap", _domain(host), agent(host).as_posix(), timeout=60)


def gateway_state(host: Any) -> str:
    """``active`` when ``brew services`` says the gateway runs, ``failed`` when
    it is loaded and not running, and else ``inactive``."""
    done = host.run("brew", "services", "info", FORMULA, "--json", timeout=60)
    try:
        info = json.loads(done.stdout or "")
    except ValueError:
        return "unknown"
    item = info[0] if isinstance(info, list) and info else info
    if not isinstance(item, dict):
        return "unknown"
    if item.get("running"):
        return "active"
    return "failed" if item.get("loaded") else "inactive"


def sidecar_state(host: Any) -> str:
    done = host.run("launchctl", "print", f"{_domain(host)}/{LABEL}", timeout=30)
    if done.returncode != 0:
        return "inactive"
    return "active" if re.search(r"^\s*state = running\s*$", done.stdout or "", re.M) else "failed"


def ctl(host: Any, gateway: str, *args: str) -> subprocess.CompletedProcess:
    """``systemctl`` *args* (the unit last), carried out under launchd: the
    sidecar's agent with ``launchctl``, the gateway (*gateway* is its name)
    with ``brew services``."""
    verb = list(args)
    if verb[:1] in (["daemon-reload"], ["reset-failed"]):
        return _done()
    target = verb[-1] if verb else ""
    if verb[:1] == ["is-active"]:
        state = gateway_state(host) if target == gateway else sidecar_state(host)
        return _done(0 if state == "active" else 3, state + "\n")
    if target == gateway:
        if verb[:1] == ["restart"]:
            return host.run("brew", "services", "restart", FORMULA, timeout=120)
        raise ValueError(f"no launchd form of systemctl {' '.join(verb)}")
    if verb[:2] == ["enable", "--now"] or verb[:1] == ["restart"]:
        # launchd keeps the agent as it was loaded: a restart (`kickstart -k`)
        # would not read a file `up` has just rewritten. The agent is taken
        # out, then loaded again from its file.
        gone = _bootout(host)
        return gone if gone.returncode != 0 else _bootstrap(host)
    if verb[:2] == ["disable", "--now"]:
        return _bootout(host)
    raise ValueError(f"no launchd form of systemctl {' '.join(verb)}")


__all__ = ["ENDPOINT", "FORMULA", "GATEWAY_LOG", "Gateway", "JWT_GATEWAY_ID", "LABEL", "agent",
           "ctl", "find", "gateway_state", "jwt_key", "log", "recorded", "sidecar_agent",
           "sidecar_state", "socket"]
