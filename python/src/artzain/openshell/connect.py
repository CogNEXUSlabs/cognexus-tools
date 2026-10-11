"""``artzain connect openshell``: bind an OpenShell gateway on this host to ArtzAIn.

This release handles three gateway shapes:

* the deb or rpm package, which runs the gateway as a systemd *user* service
  (``openshell-gateway.service``, ``~/.config/openshell/gateway.toml``);
* NVIDIA's OpenShell snap, whose gateway runs as a root service of the snap
  (0.1.3, and 0.1.4's ``system`` mode) or as a snap user service (0.1.4's
  ``user`` mode). The sidecar runs as a systemd service beside it, and ``up``
  holds the snap's refreshes (:mod:`artzain.openshell.snap`);
* NVIDIA's Docker Compose project, which runs it as a Compose service with
  ``gateway.toml`` bind-mounted from the project folder. The sidecar then
  runs as a second service of that project, from the signed sidecar image
  (:mod:`artzain.openshell.compose`).

Homebrew comes later, and is refused with a message that says so. The steps
below are the deb's; :mod:`artzain.openshell.snap` and
:mod:`artzain.openshell.compose` say how the other shapes do each.

``up`` takes an enroll token (``ARTZAIN_ENROLL_TOKEN``) and the digest of the
configuration the operator approved, and then:

1. swaps the token for the gateway's credential and that configuration
   (``POST /api/v1/openshell/connect/redeem``), and checks the configuration
   against the digest. The credential goes straight into the sidecar's
   settings file (``0600``), so a run that stops later needs no new token;
2. sets the gateway's ``proposal_approval_mode`` to ``manual`` while nothing
   governs it yet (the CLI must already reach the gateway, as the install
   script leaves it; this is checked before the token is spent);
3. writes the gateway's telemetry choice into ``gateway.env``;
4. installs the sidecar as a systemd user service, starts it and waits until
   it answers;
5. adds the two interceptor registrations to ``gateway.toml`` as one marked
   block, after ``openshell-gateway config preflight`` has passed on the
   result, and makes the gateway's unit require the sidecar. A package
   install runs on its defaults and has no ``gateway.toml`` until someone
   writes one: ``up`` then writes it, and ``remove`` deletes it;
6. restarts the gateway, and waits until it stays up;
7. runs the self-test: it asks the gateway to set ``proposal_approval_mode``
   to ``auto``, which ArtzAIn's built-in rule denies. The write must be
   refused, with an ArtzAIn decision id in the reason, and the setting must
   still be ``manual``.

Every step is recorded in ``~/.config/artzain/openshell/connect.json``. A run
that stopped part way is finished by running ``up`` again, and undone by
``remove``.

``remove`` undoes ``up``. ``gateway.toml`` and ``gateway.env`` get back the
bytes they had before, checked by SHA-256; if someone edited them since,
only the managed block is taken out and their edits stay. The gateway is
restarted unbound, the sidecar's service, files and state are deleted, and
the credential is revoked in the engine. ``status`` says what is installed
and whether it is up.

Nothing here logs the credential or the token.
"""

from __future__ import annotations

import contextlib
import getpass
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

from artzain._private_files import private_dir, replace_file, write_private
from artzain.openshell import compose, install, registration, snap, transport
from artzain.openshell import upgrade as signed

#: What the configuration a token carries says it is, and the one version
#: this release reads.
CONFIG_KIND = "artzain.openshell.connect"
CONFIG_VERSION = 1
_CONFIG_KEYS = frozenset({"kind", "version", "decision_url", "openshell_version",
                          "interceptor_timeout_ms", "decide_timeout_ms", "telemetry"})
#: The shapes this release can bind.
SHAPE_SYSTEMD_USER = "systemd-user"
SHAPE_COMPOSE = "compose"
SHAPE_SNAP = "snap"

GATEWAY_UNIT = "openshell-gateway.service"
SIDECAR_UNIT = "artzain-openshell-sidecar.service"
DROPIN = "50-artzain.conf"
TOKEN_PREFIX = "cnxt_"
CREDENTIAL_PREFIX = "cnxg_"
REDEEM_PATH = "/api/v1/openshell/connect/redeem"
SELF_TEST_KEY = "proposal_approval_mode"
DEFAULT_ENGINE = "https://app.cognexuslabs.ai"
DEFAULT_PORT = 8088
RECORD_VERSION = 1

#: The lines a managed block starts and ends with. A file holds one. The
#: sidecar finds the registration between them (``registration.found``).
BLOCK_BEGIN = registration.BLOCK_BEGIN
BLOCK_END = registration.BLOCK_END

_GATEWAY_ID = re.compile(r"^gw_[0-9A-HJKMNP-TV-Z]{26}$")
_DECISION_ID = re.compile(r"decision (?:deny|review) \(([0-9A-HJKMNP-TV-Z]{26})\)")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_VERSION = re.compile(r"(\d+)\.(\d+)\.(\d+)")
#: A decision id as a receipt link carries it (the engine's
#: GET /api/v1/audit/decisions?decision= takes the same).
_RECEIPT_ID = re.compile(r"[0-9A-Za-z]{26}")
#: Characters a value written into a systemd unit or environment file must
#: not hold.
_UNSAFE = re.compile(r"[\x00-\x1f\x7f\"'\\$%`]")


class ConnectError(Exception):
    """A step that could not be done. The message says what to do about it,
    and never holds the token or the credential."""


# ---------------------------------------------------------------------------
# The host
# ---------------------------------------------------------------------------


class Host:
    """What ``connect`` reads and changes on this machine: files under the
    user's home, a few system paths, and commands. Tests give it a
    temporary home, a root for system paths, and scripted commands."""

    def __init__(self, *, environ: Optional[Mapping[str, str]] = None,
                 root: str = "/",
                 runner: Optional[Callable[..., subprocess.CompletedProcess]] = None,
                 executor: Optional[Callable[..., int]] = None,
                 healthy: Optional[Callable[[int], bool]] = None,
                 reports: Optional[Callable[[int, str], Optional[Dict[str, Any]]]] = None,
                 break_glass: Optional[Callable[[int, str], Optional[Dict[str, Any]]]] = None,
                 post_json: Optional[Callable[..., Tuple[int, Any]]] = None,
                 get_engine: Optional[Callable[..., Tuple[int, Mapping[str, str]]]] = None,
                 which: Optional[Callable[[str], Optional[str]]] = None,
                 stat: Optional[Callable[[Path], os.stat_result]] = None,
                 sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic,
                 wall: Callable[[], float] = time.time,
                 platform: Optional[str] = None,
                 executable: Optional[str] = None,
                 uid: Optional[int] = None,
                 gid: Optional[int] = None) -> None:
        self.environ = dict(os.environ if environ is None else environ)
        # The openshell CLI colours its output unless told not to.
        self.environ.setdefault("NO_COLOR", "1")
        self.root = Path(root)
        self._runner = runner or _run
        self._executor = executor or _execute
        self._healthy = healthy or _healthy
        self._reports = reports or _reports
        self._break_glass = break_glass or _break_glass_state
        self._post_json = post_json or _post_json
        self._get_engine = get_engine or _get_engine
        self._which = which
        self._stat = stat or os.stat
        self.sleep = sleep
        self.clock = clock
        self.wall = wall
        self.platform = platform or sys.platform
        self.executable = executable or sys.executable
        self.uid = uid if uid is not None else (os.getuid() if hasattr(os, "getuid") else 0)
        self.gid = gid if gid is not None else (os.getgid() if hasattr(os, "getgid") else 0)

    # paths
    @property
    def home(self) -> Path:
        return Path(self.environ.get("HOME") or str(Path.home()))

    def _xdg(self, name: str, default: Path) -> Path:
        value = self.environ.get(name) or ""
        return Path(value) if value.startswith("/") or Path(value).is_absolute() else default

    @property
    def config_home(self) -> Path:
        return self._xdg("XDG_CONFIG_HOME", self.home / ".config")

    @property
    def state_home(self) -> Path:
        return self._xdg("XDG_STATE_HOME", self.home / ".local" / "state")

    @property
    def runtime_dir(self) -> Path:
        return self._xdg("XDG_RUNTIME_DIR", Path(f"/run/user/{self.uid}"))

    def system(self, path: str) -> Path:
        """*path* (absolute) under this host's root."""
        return self.root / path.lstrip("/")

    # commands
    def which(self, name: str) -> Optional[str]:
        if self._which is not None:
            return self._which(name)
        return shutil.which(name, path=self.environ.get("PATH"))

    def run(self, *argv: str, timeout: float = 60.0) -> subprocess.CompletedProcess:
        return self._runner(list(argv), env=self.environ, timeout=timeout)

    def execute(self, *argv: str, timeout: float = 3600.0) -> int:
        """Run *argv* on this terminal, its output shown as it comes, and
        return its exit status."""
        return self._executor(list(argv), env=self.environ, timeout=timeout)

    def healthy(self, port: int) -> bool:
        return self._healthy(port)

    def reports(self, port: int, token: str = "") -> Optional[Dict[str, Any]]:
        """What the sidecar says the engine took (``GET /artzain/reports``,
        with the sidecar's *token*), or None when it does not say."""
        return self._reports(port, token)

    def break_glass(self, port: int, token: str = "") -> Optional[Dict[str, Any]]:
        """The sidecar's break-glass window and what waits (``GET
        /artzain/break-glass``, with its *token*), or None when it does not
        say."""
        return self._break_glass(port, token)

    def post_json(self, url: str, *, headers: Mapping[str, str], body: Mapping[str, Any],
                  proxy: str = "", ca_bundle: str = "") -> Tuple[int, Any]:
        return self._post_json(url, headers=headers, body=body, proxy=proxy, ca_bundle=ca_bundle)

    def get_engine(self, url: str, *, proxy: str = "",
                   ca_bundle: str = "") -> Tuple[int, Mapping[str, str]]:
        """``(status, {"Date": ...})`` of a ``GET`` to the engine, the way the
        sidecar reaches it. Raises when it cannot be reached."""
        return self._get_engine(url, proxy=proxy, ca_bundle=ca_bundle)

    def stat(self, path: Path) -> os.stat_result:
        return self._stat(path)


def _run(argv: List[str], *, env: Mapping[str, str], timeout: float) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, env=dict(env), capture_output=True, text=True,
                              timeout=timeout, check=False)
    except FileNotFoundError:
        return subprocess.CompletedProcess(argv, 127, "", f"{argv[0]}: not found")
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(argv, 124, "", f"{argv[0]}: timed out")


def _execute(argv: List[str], *, env: Mapping[str, str], timeout: float) -> int:
    try:
        return subprocess.run(argv, env=dict(env), timeout=timeout, check=False).returncode
    except FileNotFoundError:
        return 127
    except subprocess.TimeoutExpired:
        return 124


def _sidecar_get(port: int, path: str, token: str = "") -> Any:
    """``GET`` a route of the sidecar on loopback, with its *token* when one
    is given. Never through a proxy: a host behind one sets ``HTTP_PROXY``,
    which would be asked for 127.0.0.1. Raises."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    request = urllib.request.Request(f"http://127.0.0.1:{int(port)}{path}", headers=headers)
    with opener.open(request, timeout=2) as resp:
        return json.loads(resp.read(65536) or b"null")


def _healthy(port: int) -> bool:
    try:
        answer = _sidecar_get(port, "/healthz")
    except Exception:  # noqa: BLE001 - not up yet
        return False
    return isinstance(answer, dict) and answer.get("ok") is True


def _reports(port: int, token: str = "") -> Optional[Dict[str, Any]]:
    try:
        answer = _sidecar_get(port, "/artzain/reports", token)
    except Exception:  # noqa: BLE001 - it does not say
        return None
    return answer if isinstance(answer, dict) else None


def _sidecar_post(port: int, path: str, body: Mapping[str, Any], token: str) -> Any:
    """``POST`` JSON to a route of the sidecar on loopback, with its *token*.
    Never through a proxy. The sidecar's refusal comes back as its answer;
    no answer at all raises :class:`ConnectError`."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(
        f"http://127.0.0.1:{int(port)}{path}", data=json.dumps(dict(body)).encode("utf-8"),
        method="POST", headers={"Content-Type": "application/json",
                                "Authorization": f"Bearer {token}"})
    try:
        with opener.open(request, timeout=5) as resp:
            return json.loads(resp.read(65536) or b"null")
    except urllib.error.HTTPError as exc:
        try:
            answer = json.loads(exc.read(65536) or b"null")
        except ValueError:
            answer = None
        reason = answer.get("reason") if isinstance(answer, dict) else ""
        raise ConnectError(f"the sidecar refused: {reason or 'HTTP %d' % exc.code}") from None
    except OSError as exc:
        raise ConnectError(f"the sidecar does not answer on 127.0.0.1:{int(port)} "
                           f"({type(exc).__name__}): is it running?") from None


def _get_engine(url: str, *, proxy: str = "", ca_bundle: str = "") -> Tuple[int, Mapping[str, str]]:
    """``(status, {"Date": ...})`` of a ``GET`` to the engine through the
    sidecar's own client: one origin, the proxy and the bundle given here."""
    environ = {"ARTZAIN_DECISION_URL": url, "OPENSHELL_SIDECAR_PROXY": proxy,
               "OPENSHELL_SIDECAR_CA_BUNDLE": ca_bundle}
    settings = transport.settings_from_environment(environ)
    if settings is None:
        raise ConnectError("the engine URL must be http:// or https:// with a host")
    client = transport.EngineClient(settings)
    try:
        status, headers, _data = client.request("GET", url, headers={"Accept": "application/json"},
                                                deadline=time.monotonic() + 10.0)
    finally:
        client.close()
    return status, {"Date": (headers.get("Date") if headers is not None else None) or ""}


def _post_json(url: str, *, headers: Mapping[str, str], body: Mapping[str, Any],
               proxy: str = "", ca_bundle: str = "") -> Tuple[int, Any]:
    """``(status, answer)`` of a JSON ``POST`` to the engine, through the
    sidecar's own client: one origin, the proxy and the bundle given here,
    nothing followed."""
    environ = {"ARTZAIN_DECISION_URL": url, "OPENSHELL_SIDECAR_PROXY": proxy,
               "OPENSHELL_SIDECAR_CA_BUNDLE": ca_bundle}
    settings = transport.settings_from_environment(environ)
    if settings is None:
        raise ConnectError("the engine URL must be http:// or https:// with a host")
    client = transport.EngineClient(settings)
    try:
        status, _headers, data = client.request(
            "POST", url, headers={**headers, "Content-Type": "application/json",
                                  "Accept": "application/json"},
            body=json.dumps(dict(body)).encode("utf-8"), deadline=time.monotonic() + 30.0)
    finally:
        client.close()
    try:
        answer = json.loads(data or b"null")
    except ValueError:
        answer = None
    return status, answer


# ---------------------------------------------------------------------------
# The configuration a token carries
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConnectConfig:
    """What the operator approved for this gateway."""

    decision_url: str
    openshell_version: str
    interceptor_timeout_ms: int = registration.TIMEOUT_MS_DEFAULT
    decide_timeout_ms: int = 1200
    telemetry: bool = False


def config_digest(config: Any) -> str:
    """The SHA-256 the engine keeps for a configuration: JSON with sorted
    keys, no spaces between tokens, UTF-8 left unescaped."""
    return hashlib.sha256(json.dumps(config, ensure_ascii=False, sort_keys=True,
                                     separators=(",", ":")).encode("utf-8")).hexdigest()


def _whole(value: Any, name: str, low: int, high: int) -> int:
    # A bool is an int, and 0 or 1 is below every lower bound here.
    if not isinstance(value, int) or not low <= value <= high:
        raise ConnectError(f"the configuration's {name} must be a whole number {low}..{high}")
    return value


def parse_config(config: Any) -> ConnectConfig:
    """The configuration, checked. Raises :class:`ConnectError`."""
    if not isinstance(config, dict):
        raise ConnectError("the configuration is not an object")
    if config.get("kind") != CONFIG_KIND or config.get("version") != CONFIG_VERSION:
        raise ConnectError(f"the configuration is not a {CONFIG_KIND} version {CONFIG_VERSION}: "
                           "this artzain may be too old for it")
    unknown = sorted(set(config) - _CONFIG_KEYS)
    if unknown:
        raise ConnectError("the configuration has settings this artzain does not know "
                           f"({', '.join(unknown)}): upgrade artzain and run it again")
    url = config.get("decision_url")
    if not isinstance(url, str) or transport.settings_from_environment(
            {"ARTZAIN_DECISION_URL": url}) is None or _UNSAFE.search(url) or " " in url:
        raise ConnectError("the configuration's decision_url is not an http(s) URL")
    if _plain_http_elsewhere(url):
        raise ConnectError("the configuration's decision_url is plain http: the sidecar sends "
                           "the gateway's credential there, so it must be https (or an engine "
                           "on this host)")
    version = config.get("openshell_version")
    if not isinstance(version, str) or not _VERSION.fullmatch(version):
        raise ConnectError("the configuration's openshell_version is not a version")
    interceptor = _whole(config.get("interceptor_timeout_ms", registration.TIMEOUT_MS_DEFAULT),
                         "interceptor_timeout_ms", registration.TIMEOUT_MS_MIN,
                         registration.TIMEOUT_MS_MAX)
    decide = _whole(config.get("decide_timeout_ms", 1200), "decide_timeout_ms", 50, 30_000)
    if decide >= interceptor:
        raise ConnectError("the configuration's decide_timeout_ms must be below its "
                           "interceptor_timeout_ms, so a slow engine is a sidecar deny")
    telemetry = config.get("telemetry", False)
    if not isinstance(telemetry, bool):
        raise ConnectError("the configuration's telemetry must be true or false")
    return ConnectConfig(url, version, interceptor, decide, telemetry)


@dataclass(frozen=True)
class Redeemed:
    gateway_id: str
    credential: str = field(repr=False)
    config: ConnectConfig
    raw_config: Dict[str, Any] = field(repr=False)


_REDEEM_REFUSALS = {
    401: "the enroll token is not one the engine knows: check it was copied whole",
    409: ("the enroll token was already used, names another configuration, or its gateway "
          "was revoked: ask for a new one"),
    410: "the enroll token expired, or a newer one replaced it: ask for a new one",
    422: "the configuration digest is not 64 lowercase hex characters",
    429: "too many redeems from this address: wait an hour, then run it again",
}


def redeem(host: Host, *, engine: str, token: str, digest: str, proxy: str = "",
           ca_bundle: str = "") -> Redeemed:
    """Swap *token* for the gateway's credential and its configuration, and
    check the configuration is the one *digest* names."""
    if not token.startswith(TOKEN_PREFIX) or len(token) < 40 or _UNSAFE.search(token):
        raise ConnectError("ARTZAIN_ENROLL_TOKEN is not an enroll token (cnxt_...)")
    if not _DIGEST.fullmatch(digest or ""):
        raise ConnectError("--config-digest must be the 64 lowercase hex characters you were shown")
    if _plain_http_elsewhere(engine):
        raise ConnectError("--engine is plain http: the enroll token would cross the network "
                           "unencrypted, so it must be https (or an engine on this host)")
    url = engine.rstrip("/") + REDEEM_PATH
    try:
        status, answer = host.post_json(url, headers={"Authorization": f"Bearer {token}"},
                                        body={"config_digest": digest}, proxy=proxy,
                                        ca_bundle=ca_bundle)
    except ConnectError:
        raise
    except transport.SettingsError as exc:
        raise ConnectError(f"engine connection settings: {exc}") from None
    except Exception as exc:  # noqa: BLE001 - the message names the failure, not the token
        raise ConnectError(f"the engine could not be reached ({type(exc).__name__}): check "
                           "--engine, --proxy and --ca-bundle") from None
    if status != 200:
        raise ConnectError(_REDEEM_REFUSALS.get(status, f"the engine refused the redeem (HTTP {status})"))
    if not isinstance(answer, dict):
        raise ConnectError("the engine's answer is not an object")
    gateway_id = answer.get("gateway_id")
    credential = answer.get("credential")
    config = answer.get("config")
    if not isinstance(gateway_id, str) or not _GATEWAY_ID.fullmatch(gateway_id):
        raise ConnectError("the engine's answer names no gateway")
    if (not isinstance(credential, str) or not credential.startswith(CREDENTIAL_PREFIX)
            or _UNSAFE.search(credential) or len(credential) > 256):
        raise ConnectError("the engine's answer holds no gateway credential")
    if answer.get("config_digest") != digest or config_digest(config) != digest:
        raise ConnectError("the configuration the engine sent is not the one the digest names")
    return Redeemed(gateway_id, credential, parse_config(config), config)


# ---------------------------------------------------------------------------
# Where things are
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Layout:
    gateway_toml: Path
    gateway_env: Path
    gateway_unit: Path
    dropin: Path
    sidecar_unit: Path
    artzain_dir: Path
    sidecar_env: Path
    record: Path
    state_dir: Path
    socket: Path
    #: The gateway's systemd unit.
    gateway_service: str = GATEWAY_UNIT
    #: The units run under the system manager, and the gateway's files and
    #: units are root's: ``up`` writes them with ``sudo`` (the snap's system
    #: gateway).
    system: bool = False
    #: Drop-ins beyond ``dropin``: one for each name the gateway's unit has had.
    more_dropins: Tuple[Path, ...] = ()
    #: Where ``gateway.toml`` as it would be goes, for the gateway's preflight.
    trial: Optional[Path] = None

    @property
    def dropins(self) -> Tuple[Path, ...]:
        return (self.dropin, *self.more_dropins)

    @property
    def candidate(self) -> Path:
        return self.trial or self.artzain_dir / "gateway.toml.candidate"

    @property
    def root_files(self) -> Tuple[Path, ...]:
        """The files ``up`` writes as root."""
        return (self.gateway_toml, self.sidecar_unit, *self.dropins) if self.system else ()

    @property
    def toml_backup(self) -> Path:
        return self.artzain_dir / "gateway.toml.before"

    @property
    def env_backup(self) -> Path:
        return self.artzain_dir / "gateway.env.before"

    @property
    def compose_file(self) -> Path:
        """``up``'s compose file, for a gateway under Compose."""
        return self.artzain_dir / compose.FILE

    @property
    def compose_env_backup(self) -> Path:
        return self.artzain_dir / compose.ENV_BACKUP


def layout(host: Host) -> Layout:
    config = host.config_home
    units = config / "systemd" / "user"
    candidates = [units / GATEWAY_UNIT, host.system("/etc/systemd/user") / GATEWAY_UNIT,
                  host.system("/usr/lib/systemd/user") / GATEWAY_UNIT]
    unit = next((path for path in candidates if path.is_file()), candidates[-1])
    artzain = config / "artzain" / "openshell"
    return Layout(
        gateway_toml=config / "openshell" / "gateway.toml",
        gateway_env=config / "openshell" / "gateway.env",
        gateway_unit=unit,
        dropin=units / (GATEWAY_UNIT + ".d") / DROPIN,
        sidecar_unit=units / SIDECAR_UNIT,
        artzain_dir=artzain,
        sidecar_env=artzain / "sidecar.env",
        record=artzain / "connect.json",
        state_dir=host.state_home / "artzain" / "openshell",
        socket=host.runtime_dir / "artzain" / "openshell.sock",
    )


def compose_layout(paths: Layout, project: compose.Project) -> Layout:
    """Where things are for a gateway under Compose: its ``gateway.toml``
    where the project mounts it from, the project's ``.env`` as the file
    ``up`` adds a block to, and the socket where both containers see it."""
    return replace(paths, gateway_toml=project.gateway_toml,
                   gateway_env=project.directory / ".env", socket=Path(compose.SOCKET))


def snap_layout(host: Host, paths: Layout, gateway: snap.Gateway) -> Layout:
    """Where things are for the snap's gateway: its ``gateway.toml`` and
    units where the snap's mode keeps them, and the socket where the snap's
    AppArmor profile lets the gateway connect."""
    dropins = snap.dropins(host, gateway)
    return replace(paths, gateway_toml=snap.gateway_toml(host, gateway),
                   gateway_unit=snap.units(host, gateway) / gateway.unit,
                   dropin=dropins[0], more_dropins=dropins[1:],
                   sidecar_unit=snap.sidecar_unit_path(host, gateway),
                   socket=snap.socket(host, gateway), gateway_service=gateway.unit,
                   system=gateway.system, trial=snap.candidate(host, gateway))


@dataclass(frozen=True)
class Shape:
    kind: str
    openshell_version: str
    paths: Layout
    #: The gateway's Compose project, for the Compose shape.
    project: Optional[compose.Project] = None
    #: The snap's gateway, for the snap shape.
    snap: Optional[snap.Gateway] = None


def receipt_url(engine: Any, decision_id: Any) -> str:
    """The dashboard's page of *decision_id*'s receipt on *engine* (its
    origin), or "" when either is not one: ``/dashboard.html?receipt=<id>``
    opens the sealed leaf, after a sign-in if need be."""
    if not isinstance(decision_id, str) or not _RECEIPT_ID.fullmatch(decision_id):
        return ""
    parts = urllib.parse.urlsplit(engine if isinstance(engine, str) else "")
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return ""
    return f"{parts.scheme}://{parts.netloc}/dashboard.html?receipt={decision_id}"


def _install_question(plan: install.Plan) -> str:
    packages = ", ".join(f"{name} (SHA-256 {sha[:12]}\u2026)" for name, sha in plan.packages)
    return (f"OpenShell {install.RELEASE} is not installed. Install it now? This downloads "
            f"{packages} from NVIDIA's release on GitHub, checks each against the SHA-256 this "
            f"artzain release pins, installs {'it' if len(plan.packages) == 1 else 'them'} with "
            f"`{'sudo ' if plan.sudo else ''}{plan.tool}`, and starts the openshell-gateway user "
            "service. [y/N] ")


def _openshell_installed(host: Host, *, install_openshell: bool,
                         ask: Optional[Callable[[str], str]], out: Callable[[str], None]) -> None:
    """Install OpenShell when the host has systemd and no OpenShell, and the
    operator said to: ``--install-openshell``, or yes at the terminal.
    Otherwise say how, before any token is spent."""
    missing = [tool for tool in ("openshell-gateway", "openshell") if not host.which(tool)]
    if (not missing or not host.platform.startswith("linux") or sys.version_info < (3, 11)
            or not host.which("systemctl")):
        return  # detect says what is wrong, if anything is
    if host.which("docker") and compose.find(host, layout(host).compose_file) is not None:
        return  # a gateway under Compose: nothing to install on this host
    if _snap_installed(host):
        return  # the OpenShell snap: nothing to install beside it
    try:
        plan = install.plan(host)
    except install.InstallError as exc:
        raise ConnectError(f"{missing[0]} is not on PATH, and OpenShell cannot be installed "
                           f"here: {exc}") from None
    if not install_openshell:
        answer = ask(_install_question(plan)) if ask is not None else ""
        if answer.strip().lower() not in ("y", "yes"):
            steps = "\n".join("  " + line for line in plan.by_hand())
            raise ConnectError(
                f"{missing[0]} is not on PATH: OpenShell {install.RELEASE} is not installed. "
                "Run `artzain connect openshell up --install-openshell` to install it, "
                f"or run these yourself:\n{steps}\nthen run this again (no token was spent)")
    try:
        install.install(host, plan, say=lambda message: _say(out, message))
    except install.InstallError as exc:
        raise ConnectError(f"installing OpenShell {install.RELEASE}: {exc}") from None


def _snap_installed(host: Host) -> bool:
    return bool(host.which("snap")) and host.run(
        "snap", "list", snap.SNAP, timeout=30).returncode == 0


def _recorded_snap(host: Host, data: Mapping[str, Any]) -> Optional[snap.Gateway]:
    """The snap gateway a record names (the one the snap runs now, when it
    runs one in the same mode), or None."""
    if data.get("shape") != SHAPE_SNAP:
        return None
    try:
        current = snap.find(host)
    except ConnectError:
        current = None
    try:
        return snap.recorded(data.get("snap") or {}, current)
    except ConnectError:
        return None


def _snap_of(host: Host, data: Mapping[str, Any]) -> Optional[snap.Gateway]:
    """The snap gateway a record names, for a record of the snap shape; None
    for another shape. Raises when the record's snap facts cannot be read."""
    if data.get("shape") != SHAPE_SNAP:
        return None
    try:
        current = snap.find(host)
    except ConnectError:
        current = None
    return snap.recorded(data.get("snap") or {}, current)


def _recorded_project(data: Mapping[str, Any]) -> Optional[compose.Project]:
    """The Compose project a record names, or None."""
    if data.get("shape") != SHAPE_COMPOSE:
        return None
    try:
        return compose.recorded(data.get("compose") or {})
    except ConnectError:
        return None


def _recorded_shape(paths: Layout) -> str:
    try:
        data = json.loads(paths.record.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    return str(data.get("shape") or "") if isinstance(data, dict) else ""


def _compose_shape(host: Host, paths: Layout, project: compose.Project) -> Shape:
    if not host.which("openshell"):
        raise ConnectError("openshell is not on PATH: install NVIDIA's openshell CLI and "
                           "register it with the gateway (openshell gateway add "
                           "http://127.0.0.1:8080 --name openshell-docker)")
    compose.check(project, paths.compose_file)
    return Shape(SHAPE_COMPOSE, compose.version(host, project), compose_layout(paths, project),
                 project)


def _snap_shape(host: Host, paths: Layout, gateway: snap.Gateway) -> Shape:
    if host.uid == 0:
        raise ConnectError("run this as the user who operates the gateway, not as root: "
                           "`up` uses sudo for what is root's")
    for tool in ("systemctl", "openshell", *(("sudo",) if gateway.system else ())):
        if not host.which(tool):
            raise ConnectError(f"{tool} is not on PATH" + (
                ": the snap's CLI is /snap/bin/openshell" if tool == "openshell" else ""))
    return Shape(SHAPE_SNAP, gateway.version, snap_layout(host, paths, gateway), snap=gateway)


def detect(host: Host) -> Shape:
    """The gateway on this host, when it is one this release can bind: the
    deb or rpm package's, else the OpenShell snap's, else one under Docker
    Compose. A host already bound keeps the shape its record names."""
    if not host.platform.startswith("linux"):
        raise ConnectError("this release binds the deb, rpm, snap or Compose gateway on Linux "
                           "only; Homebrew comes later")
    if sys.version_info < (3, 11):
        raise ConnectError("artzain connect needs Python 3.11 or later (it reads TOML)")
    paths = layout(host)
    packaged = (bool(host.which("systemctl")) and bool(host.which("openshell-gateway"))
                and paths.gateway_unit.is_file())
    recorded = _recorded_shape(paths)
    if recorded == SHAPE_SNAP or (not packaged and recorded != SHAPE_COMPOSE):
        gateway = snap.find(host)
        if gateway is not None:
            return _snap_shape(host, paths, gateway)
    if recorded == SHAPE_SNAP:
        raise ConnectError("this host's gateway was bound as the OpenShell snap's, and the "
                           "snap is not installed now: install it again, or run `artzain "
                           "connect openshell remove`")
    if (not packaged or recorded == SHAPE_COMPOSE) and host.which("docker"):
        project = compose.find(host, paths.compose_file)
        if project is not None:
            return _compose_shape(host, paths, project)
    if recorded == SHAPE_COMPOSE:
        raise ConnectError("this host's gateway was bound under Docker Compose, and no "
                           "OpenShell gateway runs under Compose here now: start it (docker "
                           "compose up -d in its folder), or run `artzain connect openshell "
                           "remove`")
    for tool in ("systemctl", "openshell-gateway", "openshell"):
        if not host.which(tool):
            raise ConnectError(f"{tool} is not on PATH: install OpenShell's deb or rpm package")
    paths = layout(host)
    if not paths.gateway_unit.is_file():
        raise ConnectError(f"no {GATEWAY_UNIT} user unit, no OpenShell snap, and no "
                           "OpenShell gateway under Docker Compose: this is not a deb, rpm, "
                           "snap or Compose gateway (Homebrew comes later)")
    if paths.gateway_toml.exists() and not paths.gateway_toml.is_file():
        raise ConnectError(f"{paths.gateway_toml} is not a file")
    done = host.run("openshell-gateway", "--version", timeout=30)
    found = _VERSION.search((done.stdout or "") + " " + (done.stderr or ""))
    if done.returncode != 0 or not found:
        raise ConnectError("openshell-gateway --version did not say its version")
    return Shape(SHAPE_SYSTEMD_USER, found.group(0), paths)


# ---------------------------------------------------------------------------
# Files: private writes, managed blocks
# ---------------------------------------------------------------------------


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _replace(path: Path, data: bytes, *, private: bool = False) -> None:
    """Write *path* whole, by a rename, keeping the mode an existing file had.

    Windows refuses the rename while another program has *path* open, a
    virus scanner reading the file just written, say, so it is tried again
    for a while (:func:`~artzain._private_files.replace_file`). Whatever
    fails, *path* is as it was and the new file is gone.
    """
    mode = path.stat().st_mode & 0o777 if path.exists() else (0o600 if private else 0o644)
    temporary = path.with_name(path.name + ".artzain-new")
    if private:
        private_dir(path.parent)
        write_private(temporary, data)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary.write_bytes(data)
    try:
        if hasattr(os, "chmod"):
            os.chmod(temporary, mode)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise
    replace_file(temporary, path)


def block(text: str) -> str:
    """*text* between the managed block's two marker lines."""
    return f"{BLOCK_BEGIN}\n{text.rstrip(chr(10))}\n{BLOCK_END}\n"


def add_block(original: bytes, text: str) -> bytes:
    """*original* with the managed block appended, after one empty line."""
    body = original.decode("utf-8")
    separator = "" if not body else ("\n" if body.endswith("\n") else "\n\n")
    return (body + separator + block(text)).encode("utf-8")


def strip_block(current: bytes) -> Optional[bytes]:
    """*current* without its managed block and the empty line before it,
    or None when it holds no block, or not exactly one.

    This is what is left when someone edited the file after ``up``. A file
    nobody touched is put back from its saved copy instead
    (:func:`_restore`), because a file that did not end in a newline and
    one that did can leave the same text here.
    """
    body = current.decode("utf-8")
    if body.count(BLOCK_BEGIN) != 1 or body.count(BLOCK_END) != 1:
        return None
    start, end = body.find(BLOCK_BEGIN + "\n"), body.find(BLOCK_END + "\n")
    if start < 0 or end < start or (start and body[start - 1] != "\n"):
        return None
    head, tail = body[:start], body[end + len(BLOCK_END) + 1:]
    if head.endswith("\n\n"):
        head = head[:-1]
    return (head + tail).encode("utf-8")


def _restore(path: Path, backup: Path, before_sha: str, created: bool, *,
             host: Optional[Host] = None, paths: Optional[Layout] = None) -> str:
    """Put *path* back as it was before ``up``. Returns what happened:

    * ``restored``: nothing but the block changed since, so the saved copy
      goes back, byte for byte (its SHA-256 is the one ``up`` recorded);
    * ``removed``: ``up`` created the file, and nothing else was added;
    * ``kept-edits``: someone changed it outside the block, so only the
      block is taken out and their changes stay;
    * ``no-block`` or ``missing``: there was nothing to take out.
    """
    if not path.exists():
        return "missing"
    root = host is not None and paths is not None and path in paths.root_files

    def write(data: bytes) -> None:
        if root:
            _put(host, paths, path, data)
        else:
            _replace(path, data)

    current = _read(host, paths, path) if root else path.read_bytes()
    stripped = strip_block(current or b"")
    if stripped is None:
        return "no-block"
    saved = backup.read_bytes() if backup.is_file() else None
    if saved is not None and _sha(saved) == before_sha and stripped == strip_block(
            add_block(saved, "")):
        if created and not saved:
            if root:
                _drop(host, paths, path)
            else:
                path.unlink()
            return "removed"
        write(saved)
        return "restored"
    write(stripped)
    return "kept-edits"


# ---------------------------------------------------------------------------
# The record of a connect
# ---------------------------------------------------------------------------


class Record:
    """What ``up`` has done, so a second ``up`` finishes it and ``remove``
    undoes it. JSON, ``0600``, next to the sidecar's settings."""

    def __init__(self, path: Path, data: Optional[Dict[str, Any]] = None) -> None:
        self.path = path
        self.data: Dict[str, Any] = data or {"version": RECORD_VERSION, "steps": []}

    @classmethod
    def load(cls, path: Path) -> "Record":
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return cls(path)
        except (OSError, ValueError) as exc:
            raise ConnectError(f"{path} cannot be read ({type(exc).__name__}); "
                               "move it aside to start again") from None
        if not isinstance(data, dict) or data.get("version") != RECORD_VERSION:
            raise ConnectError(f"{path} is not a connect record this artzain reads")
        data.setdefault("steps", [])
        return cls(path, data)

    def done(self, step: str) -> bool:
        return step in self.data["steps"]

    def mark(self, step: str, **facts: Any) -> None:
        if step not in self.data["steps"]:
            self.data["steps"].append(step)
        self.data.update(facts)
        self.save()

    def save(self) -> None:
        _replace(self.path, (json.dumps(self.data, indent=2, sort_keys=True) + "\n")
                 .encode("utf-8"), private=True)

    def delete(self) -> None:
        if self.path.exists():
            self.path.unlink()


# ---------------------------------------------------------------------------
# What up writes
# ---------------------------------------------------------------------------


#: Where a package-managed gateway keeps the JWT bundle it signs its calls
#: with when ``gateway.toml`` names none: next to its generated TLS files
#: (the deb unit's ``OPENSHELL_LOCAL_TLS_DIR``), under this gateway id.
LOCAL_JWT_DIR = (".local", "state", "openshell", "tls", "jwt")
LOCAL_JWT_GATEWAY_ID = "openshell"


def _jwt_settings(toml_text: str, host: Optional[Host] = None) -> Dict[str, str]:
    """The gateway's own ``gateway_jwt`` public key and id, so the sidecar
    can check the gateway's signed calls: as ``gateway.toml`` names them,
    or else the bundle a package install generates for itself."""
    import tomllib

    try:
        jwt = tomllib.loads(toml_text).get("openshell", {}).get("gateway", {}).get("gateway_jwt")
    except tomllib.TOMLDecodeError:
        return {}
    if isinstance(jwt, dict):
        key, gateway = jwt.get("public_key_path"), jwt.get("gateway_id")
        if isinstance(key, str) and isinstance(gateway, str) and key and gateway and not (
                _UNSAFE.search(key) or _UNSAFE.search(gateway)):
            return {"OPENSHELL_JWT_PUBLIC_KEY": key, "OPENSHELL_JWT_GATEWAY_ID": gateway}
        return {}
    if host is None:
        return {}
    bundle = host.home.joinpath(*LOCAL_JWT_DIR)
    key = bundle / "public.pem"
    if (all((bundle / name).is_file() for name in ("signing.pem", "public.pem", "kid"))
            and not _UNSAFE.search(key.as_posix())):
        return {"OPENSHELL_JWT_PUBLIC_KEY": key.as_posix(),
                "OPENSHELL_JWT_GATEWAY_ID": LOCAL_JWT_GATEWAY_ID}
    return {}


def sidecar_environment(host: Host, paths: Layout, redeemed_gateway: str, credential: str,
                        config: ConnectConfig, *, registration_digest: str, port: int,
                        proxy: str, ca_bundle: str, jwt: Mapping[str, str], token: str,
                        container: bool = False, gateway_endpoint: str = "") -> str:
    """The sidecar service's ``EnvironmentFile``, or with *container* its
    Compose container's ``env_file``, which names the paths as the container
    sees them. It holds the credential, and *token*, which a caller of the
    sidecar's loopback routes must present."""
    state = Path(compose.STATE) if container else paths.state_dir
    values = {
        "COGNEXUS_API_KEY": credential,
        "ARTZAIN_DECISION_URL": config.decision_url,
        "OPENSHELL_GATEWAY_ID": redeemed_gateway,
        "OPENSHELL_SIDECAR_GRPC": f"unix://{paths.socket.as_posix()}",
        "OPENSHELL_SIDECAR_HOST": "127.0.0.1",
        "OPENSHELL_SIDECAR_PORT": str(port),
        # What a caller of its loopback routes must present (only the
        # health probe is open): `status`, `doctor` and `up` read it here.
        "OPENSHELL_SIDECAR_TOKEN": token,
        "OPENSHELL_SIDECAR_DECIDE_TIMEOUT_MS": str(config.decide_timeout_ms),
        "OPENSHELL_SIDECAR_STATE": (state / "state.json").as_posix(),
        "OPENSHELL_SIDECAR_JOURNAL": (state / "journal.json").as_posix(),
        "OPENSHELL_SIDECAR_BASE_POLICY": (state / "base-policy.json").as_posix(),
        "OPENSHELL_REGISTRATION_DIGEST": registration_digest,
        # Where the registration is: each heartbeat says whether it still is.
        "OPENSHELL_GATEWAY_TOML": (compose.toml_inside(paths.gateway_toml) if container
                                   else paths.gateway_toml.as_posix()),
        # Each inventory lists every workspace through the CLI the operator
        # registered with the gateway, so it is never partial; in a
        # container, the image's own CLI.
        "OPENSHELL_SIDECAR_LIST_CLI": compose.CLI if container else (host.which("openshell") or ""),
    }
    if container:
        # The image's CLI connects where the host's is registered: the
        # sidecar is on the host's network.
        values["OPENSHELL_GATEWAY_ENDPOINT"] = gateway_endpoint
    elif not values["OPENSHELL_SIDECAR_LIST_CLI"].startswith("/"):
        raise ConnectError("OPENSHELL_SIDECAR_LIST_CLI: the openshell CLI has no absolute path")
    if proxy:
        values["OPENSHELL_SIDECAR_PROXY"] = proxy
    if ca_bundle:
        values["OPENSHELL_SIDECAR_CA_BUNDLE"] = ca_bundle
    values.update(jwt)
    for name, value in values.items():
        if _UNSAFE.search(value):
            raise ConnectError(f"{name} holds a character a systemd environment file cannot "
                               "carry here")
    lines = ["# Written by `artzain connect openshell up`. It holds this gateway's",
             "# credential: keep it the owner's alone (0600)."]
    # Quoted, so that a path with a space in it is one value.
    lines += [f'{name}="{value}"' for name, value in values.items()]
    return "\n".join(lines) + "\n"


def sidecar_unit(host: Host, paths: Layout) -> str:
    python = host.executable
    if _UNSAFE.search(python) or not python.startswith("/"):
        raise ConnectError("the Python running artzain has a path a systemd unit cannot name")
    settings = paths.sidecar_env.as_posix()
    if _UNSAFE.search(settings) or " " in settings:
        raise ConnectError(f"{settings} has a path a systemd unit cannot name: set "
                           "XDG_CONFIG_HOME to a folder without spaces")
    return (
        "# Written by `artzain connect openshell up`; `artzain connect openshell remove`\n"
        "# deletes it.\n"
        "[Unit]\n"
        "Description=ArtzAIn sidecar for the OpenShell gateway\n"
        f"Before={GATEWAY_UNIT}\n"
        "\n"
        "[Service]\n"
        # Started once it serves (sd_notify READY=1): the gateway's unit is
        # ordered after this one, and must not start before the socket is there.
        "Type=notify\n"
        "NotifyAccess=main\n"
        f"EnvironmentFile={paths.sidecar_env.as_posix()}\n"
        f'ExecStart="{python}" -m artzain.cli openshell sidecar\n'
        "Restart=on-failure\n"
        "RestartSec=2s\n"
        "UMask=0077\n"
        "NoNewPrivileges=yes\n"
        "\n"
        "[Install]\n"
        "WantedBy=default.target\n"
    )


def _snap_jwt(host: Host, gateway: snap.Gateway,
              toml_text: str) -> Tuple[Dict[str, str], Optional[Path]]:
    """The settings that let the sidecar check the snap gateway's signed
    calls, and the key's own path (which the system sidecar's unit copies):
    the key ``gateway.toml`` names, or else the bundle the snap generates."""
    named = _jwt_settings(toml_text)
    if named:
        key, gateway_id = Path(named["OPENSHELL_JWT_PUBLIC_KEY"]), named["OPENSHELL_JWT_GATEWAY_ID"]
        if gateway.system:
            # The path is the snap's, as the gateway sees it: the same on the host.
            key = host.system(key.as_posix())
    else:
        key, gateway_id = snap.jwt_key(host, gateway), snap.JWT_GATEWAY_ID
        there = (host.run("sudo", "test", "-s", key.as_posix(), timeout=30).returncode == 0
                 if gateway.system else key.is_file())
        if not there:
            return {}, None
    sidecar_key = snap.sidecar_jwt(host, gateway, key)
    if _UNSAFE.search(sidecar_key.as_posix()) or _UNSAFE.search(gateway_id):
        return {}, None
    return ({"OPENSHELL_JWT_PUBLIC_KEY": sidecar_key.as_posix(),
             "OPENSHELL_JWT_GATEWAY_ID": gateway_id}, key)


def _unit(host: Host, paths: Layout, gateway: Optional[snap.Gateway],
          key: Optional[Path] = None) -> str:
    """The sidecar's unit for this shape."""
    if gateway is None:
        return sidecar_unit(host, paths)
    python = host.executable
    if not python.startswith("/"):
        raise ConnectError("the Python running artzain has a path a systemd unit cannot name")
    return snap.sidecar_unit(host, gateway, python=python, settings=paths.sidecar_env, key=key)


def gateway_dropin() -> str:
    return (
        "# Written by `artzain connect openshell up`; `artzain connect openshell remove`\n"
        "# deletes it. The gateway refuses to start while its interceptor does not\n"
        "# answer, so it starts after the sidecar, and stops with it.\n"
        "[Unit]\n"
        f"Requires={SIDECAR_UNIT}\n"
        f"After={SIDECAR_UNIT}\n"
    )


def check_gateway_toml(paths: Layout, toml_text: str) -> Dict[str, Any]:
    """The parsed file, when the registration can be added to it. Raises
    :class:`ConnectError` for one it cannot."""
    import tomllib

    try:
        current = tomllib.loads(toml_text)
    except tomllib.TOMLDecodeError as exc:
        raise ConnectError(f"{paths.gateway_toml} is not valid TOML ({exc})") from None
    openshell = current.get("openshell")
    if openshell is not None and not isinstance(openshell, dict):
        raise ConnectError(f"{paths.gateway_toml}: openshell is not a table")
    if openshell is not None and openshell.get("version") != 2:
        raise ConnectError(f"{paths.gateway_toml}: [openshell] must say version = 2 "
                           "(the v0.1.2 schema)")
    gateway = (openshell or {}).get("gateway", {})
    existing = gateway.get("interceptors", []) if isinstance(gateway, dict) else None
    if not isinstance(existing, list):
        raise ConnectError(f"{paths.gateway_toml}: openshell.gateway.interceptors is laid out "
                           "in a way the registration cannot be added to; add it by hand "
                           "from the manual")
    names = {entry.get("name") for entry in existing if isinstance(entry, dict)}
    taken = sorted(names & set(registration.NAMES))
    if taken:
        raise ConnectError(f"{paths.gateway_toml} already registers {', '.join(taken)}: take "
                           "that registration out, then run this again")
    return current


def sidecar_registration(paths: Layout, config: ConnectConfig) -> str:
    """The registrations the sidecar is installed for, without the
    ``[openshell]`` table a file may already have: its SHA-256 is
    ``OPENSHELL_REGISTRATION_DIGEST``."""
    return registration.render(f"unix://{paths.socket.as_posix()}",
                               timeout_ms=config.interceptor_timeout_ms)


def telemetry_line(config: ConnectConfig) -> str:
    """The gateway's telemetry choice, as ``gateway.env`` carries it."""
    return f"OPENSHELL_TELEMETRY_ENABLED={'true' if config.telemetry else 'false'}"


def registration_text(paths: Layout, config: ConnectConfig, toml_text: str) -> str:
    """The registrations for this file: with ``[openshell] version = 2``
    when the file has no ``[openshell]`` table. Raises :class:`ConnectError`
    for a file the block cannot be added to."""
    import tomllib

    current = check_gateway_toml(paths, toml_text)
    openshell = current.get("openshell")
    text = registration.render(f"unix://{paths.socket.as_posix()}",
                               timeout_ms=config.interceptor_timeout_ms,
                               version_table=openshell is None)
    candidate = add_block(toml_text.encode("utf-8"), text).decode("utf-8")
    try:
        merged = tomllib.loads(candidate)
    except tomllib.TOMLDecodeError as exc:
        raise ConnectError(f"{paths.gateway_toml} cannot take the registration as it is "
                           f"laid out ({exc})") from None
    added = [entry for entry in merged["openshell"]["gateway"]["interceptors"]
             if entry.get("name") in registration.NAMES]
    if [entry["name"] for entry in added] != list(registration.NAMES):
        raise ConnectError(f"{paths.gateway_toml}: the registration did not land where it "
                           "should; add it by hand from the manual")
    return text


# ---------------------------------------------------------------------------
# up
# ---------------------------------------------------------------------------


def _say(out: Callable[[str], None], message: str) -> None:
    out(message)


def _systemctl(host: Host, *args: str, timeout: float = 60.0) -> subprocess.CompletedProcess:
    return host.run("systemctl", "--user", *args, timeout=timeout)


def _ctl(host: Host, paths: Optional[Layout], *args: str,
         timeout: float = 60.0) -> subprocess.CompletedProcess:
    """``systemctl`` on the manager *paths*' units run under: the user's, or
    the system's (through ``sudo``, but for what only reads)."""
    if paths is None or not paths.system:
        return _systemctl(host, *args, timeout=timeout)
    if args and args[0] in ("is-active", "show"):
        return host.run("systemctl", *args, timeout=timeout)
    return host.run("sudo", "systemctl", *args, timeout=timeout)


def _reload(host: Host, paths: Optional[Layout]) -> None:
    system = paths is not None and paths.system
    _check(_ctl(host, paths, "daemon-reload"),
           "systemctl daemon-reload" if system else "systemctl --user daemon-reload")


def _journal(paths: Optional[Layout], unit: str) -> str:
    """The command that shows *unit*'s log."""
    return (f"`journalctl -u {unit}`" if paths is not None and paths.system
            else f"`journalctl --user -u {unit}`")


def _put(host: Host, paths: Layout, path: Path, data: bytes, *, private: bool = False) -> None:
    """Write *path* whole: as root, through ``sudo``, when it is one of the
    files of root's that *paths* names."""
    if path in paths.root_files:
        snap.put(host, path, data, mode=path.stat().st_mode & 0o777 if path.exists() else 0o644)
    else:
        _replace(path, data, private=private)


def _drop(host: Host, paths: Layout, path: Path) -> bool:
    """Remove *path*; True when it was there."""
    if path in paths.root_files:
        return snap.delete(host, path)
    if not path.exists():
        return False
    path.unlink()
    return True


def _read(host: Host, paths: Layout, path: Path) -> Optional[bytes]:
    """*path*'s bytes, or None when there is no such file."""
    if path in paths.root_files:
        return snap.read(host, path)
    return path.read_bytes() if path.is_file() else None


def _check(done: subprocess.CompletedProcess, what: str) -> None:
    if done.returncode != 0:
        detail = (done.stderr or done.stdout or "").strip().splitlines()[-1:] or [""]
        raise ConnectError(f"{what} failed (exit {done.returncode}): {detail[0][:300]}")


def _wait(host: Host, seconds: float, test: Callable[[], bool]) -> bool:
    until = host.clock() + seconds
    while True:
        if test():
            return True
        if host.clock() >= until:
            return False
        host.sleep(0.5)


def _gateway_stays_up(host: Host, paths: Optional[Layout] = None) -> bool:
    """Active, and still active a few seconds later: a gateway that cannot
    reach its interceptor exits at start and is restarted every 5 s."""
    unit = paths.gateway_service if paths is not None else GATEWAY_UNIT

    def active() -> bool:
        return _ctl(host, paths, "is-active", unit, timeout=10).stdout.strip() == "active"

    if not _wait(host, 30, active):
        return False
    host.sleep(6)
    return active()


def _same_line(found: str, wanted: str) -> bool:
    a, b = _VERSION.fullmatch(found), _VERSION.fullmatch(wanted)
    return bool(a and b and a.group(1, 2) == b.group(1, 2))


def _said(done: subprocess.CompletedProcess) -> str:
    """What a command printed, on one line, without colour codes or the
    box the openshell CLI draws around an error."""
    text = re.sub(r"\x1b\[[0-9;]*m", "", (done.stdout or "") + "\n" + (done.stderr or ""))
    return " ".join(re.sub("[\u2500-\u257f]", " ", text).split())


def _setting(host: Host, value: str) -> subprocess.CompletedProcess:
    """Set the gateway-wide ``proposal_approval_mode``. ``--yes`` because the
    CLI asks to confirm a global change, and nobody is there to answer."""
    return host.run("openshell", "settings", "set", "--global", "--key", SELF_TEST_KEY,
                    "--value", value, "--yes", timeout=60)


#: How the snap's gateway is started, and its CLI registered with it, by mode.
_SNAP_REGISTER = {
    snap.MODE_SYSTEM: ("sudo snap start openshell", "copy its client certificate to you as "
                       "NVIDIA's snap instructions say (from /var/snap/openshell/common/tls), "
                       "then openshell gateway add https://127.0.0.1:17670 --local --name "
                       "openshell"),
    snap.MODE_USER: ("systemctl --user start snap.openshell.user-gateway.service",
                     "openshell gateway add https://127.0.0.1:17670 --local --name openshell"),
}


def _cli_reaches_the_gateway(host: Host, *, under_compose: bool = False,
                             snap_mode: str = "") -> None:
    """Raise :class:`ConnectError` unless the ``openshell`` CLI can talk to
    the gateway: every step after the redeem needs it."""
    done = host.run("openshell", "settings", "get", "--global", timeout=60)
    if done.returncode != 0:
        start, register = (_SNAP_REGISTER[snap_mode] if snap_mode else
                           (f"systemctl --user start {GATEWAY_UNIT}",
                            "openshell gateway add https://127.0.0.1:17670 --local "
                            "--name openshell") if not under_compose else
                           ("docker compose up -d, in its folder",
                            "openshell gateway add http://127.0.0.1:8080 --name openshell-docker"))
        raise ConnectError(f"the openshell CLI cannot reach the gateway: start it ({start}) "
                           f"and register it ({register}), then run this again: "
                           + _said(done)[-300:])


def self_test(host: Host) -> str:
    """Ask the gateway for a write ArtzAIn denies. Returns the decision id.
    Raises :class:`ConnectError` when the write was not refused, or not by
    ArtzAIn, or the setting moved anyway."""
    tried = _setting(host, "auto")
    said = _said(tried)
    if tried.returncode == 0:
        # Governance is not in force. Put the setting back before saying so.
        _setting(host, "manual")
        raise ConnectError("the self-test write was ALLOWED: the gateway is not governed. "
                           "Run `artzain connect openshell status`, then `up` again")
    found = _DECISION_ID.search(said)
    if not found:
        raise ConnectError("the self-test write was refused, but not by an ArtzAIn decision: "
                           + said[-300:])
    now = host.run("openshell", "settings", "get", "--global", timeout=60)
    value = re.search(SELF_TEST_KEY + r"\s*=\s*(\w+)", _said(now))
    if now.returncode != 0 or not value or value.group(1) != "manual":
        raise ConnectError("after the self-test the gateway does not show "
                           f"{SELF_TEST_KEY} as manual: check it with `openshell settings get --global`")
    return found.group(1)


def _preflight(host: Host, project: Optional[compose.Project], trial: Path,
               gateway: Optional[snap.Gateway] = None) -> None:
    """The gateway's own ``config preflight`` on *trial*: the package's
    binary, the snap's own run inside the snap, or under Compose a
    throwaway container of the gateway's image."""
    if gateway is not None:
        _check(snap.preflight(host, gateway, trial),
               "openshell-gateway config preflight (inside the snap)")
    elif project is None:
        _check(host.run("openshell-gateway", "config", "preflight", "--path",
                        trial.as_posix(), timeout=60),
               "openshell-gateway config preflight")
    else:
        _check(compose.preflight(host, project, trial),
               "openshell-gateway config preflight (in the gateway's image)")


def _restart_bound(host: Host, paths: Layout, project: Optional[compose.Project]) -> None:
    """``up``'s step 6: the gateway restarted with its registration (under
    Compose, recreated from the project's files and up's), and up to stay."""
    if project is None:
        unit = paths.gateway_service
        if paths.system:
            # Five failed starts in a row leave the unit failed until reset.
            _ctl(host, paths, "reset-failed", unit, timeout=30)
        _check(_ctl(host, paths, "restart", unit, timeout=120), f"restarting {unit}")
        if not _gateway_stays_up(host, paths):
            raise ConnectError(f"{unit} did not stay up: see {_journal(paths, unit)}. "
                               "`artzain connect openshell remove` puts everything back")
        return
    _check(compose.up(host, project, paths.compose_file, project.service),
           f"docker compose up -d {project.service}")
    if not compose.stays_up(host, project.name, project.service):
        raise ConnectError(f"the gateway's container did not stay up: see `docker "
                           f"compose -p {project.name} logs {project.service}`. "
                           "`artzain connect openshell remove` puts everything back")
    _compose_gateway_answers(host, project)


#: How long a gateway container just started may take to answer the CLI.
GATEWAY_ANSWER_SECONDS = 90.0


def _compose_gateway_answers(host: Host, project: compose.Project) -> None:
    """Wait until the openshell CLI reaches a gateway container just
    (re)started. Docker publishes its port as soon as the container runs,
    before the gateway behind it listens, and a call meanwhile is reset."""
    def answers() -> bool:
        return host.run("openshell", "settings", "get", "--global", timeout=60).returncode == 0

    if not _wait(host, GATEWAY_ANSWER_SECONDS, answers):
        raise ConnectError(f"the gateway's container is up, but the openshell CLI cannot reach "
                           f"it: see `docker compose -p {project.name} logs {project.service}`")


def up(host: Host, *, token: str = "", digest: str = "", engine: str = DEFAULT_ENGINE,
       proxy: str = "", ca_bundle: str = "", port: int = DEFAULT_PORT,
       install_openshell: bool = False, sidecar_image: str = "",
       ask: Optional[Callable[[str], str]] = None,
       out: Callable[[str], None] = print) -> Dict[str, Any]:
    """Bind this host's gateway. Returns the record. Raises
    :class:`ConnectError` at the first step that cannot be done; what was
    done before it stays recorded. On a host without OpenShell, installs it
    first when *install_openshell* is set or *ask* is answered yes. Under
    Compose, the sidecar runs from this release's image as cosign verifies
    it, or from *sidecar_image* when that names one by its digest."""
    _openshell_installed(host, install_openshell=install_openshell, ask=ask, out=out)
    shape = detect(host)
    paths, project, gateway = shape.paths, shape.project, shape.snap
    if project is None and sidecar_image:
        raise ConnectError("--sidecar-image is for a gateway under Compose: this one is not, "
                           "and its sidecar runs from this artzain")
    if project is None and "/.cache/uv/" in host.executable.replace("\\", "/"):
        raise ConnectError("artzain is running from a temporary uv environment, which the "
                           "sidecar service cannot keep using: install it first, "
                           "`uv tool install 'artzain[openshell]'`, and run that artzain")
    if project is not None and proxy == "env":
        raise ConnectError("--proxy env: the sidecar's container does not run with this "
                           "shell's proxy settings; name the proxy (--proxy http://host:port)")
    if not (1 <= int(port) <= 65535):
        raise ConnectError("--port must be 1..65535")
    record = Record.load(paths.record)
    toml_text = (paths.gateway_toml.read_bytes().decode("utf-8")
                 if paths.gateway_toml.exists() else "")
    if strip_block(toml_text.encode("utf-8")) is None:
        # Before the token is spent: a file the block cannot go into stops here,
        # and so does a CLI that cannot reach the gateway.
        check_gateway_toml(paths, toml_text)
        _cli_reaches_the_gateway(host, under_compose=project is not None,
                                 snap_mode=gateway.mode if gateway else "")
    signer: Optional[Tuple[str, str]] = None
    image, release, endpoint = "", "", ""
    key: Optional[Path] = None
    if gateway is not None:
        jwt, key = _snap_jwt(host, gateway, toml_text)
    elif project is None:
        jwt = _jwt_settings(toml_text, host)
    else:
        # Also before the token: the project takes up's file, the gateway's
        # key is where the sidecar can read it, and the image verifies.
        _compose_can_bind(host, paths, project)
        signer = compose.jwt(project, toml_text)
        jwt = ({"OPENSHELL_JWT_PUBLIC_KEY": compose.JWT_KEY,
                "OPENSHELL_JWT_GATEWAY_ID": signer[1]} if signer else {})
        endpoint = compose.gateway_endpoint(host)
        image, release = _sidecar_image(host, record, sidecar_image, out)

    # 1. The credential, once. It is saved before anything else can fail.
    settings_changed = False
    if record.done("redeemed"):
        _say(out, f"gateway {record.data['gateway_id']}: already redeemed; using the saved credential")
        settings_changed = (_bring_the_settings_up_to_date(paths, out) if project is None
                            else _compose_settings_up_to_date(paths, endpoint, out))
        config = parse_config(record.data.get("config"))
        gateway_id = record.data["gateway_id"]
    else:
        if not token:
            raise ConnectError("set ARTZAIN_ENROLL_TOKEN to the enroll token you were given")
        # What this host puts into the sidecar's files, written once with
        # stand-ins for what the engine will send: a value systemd cannot
        # carry stops here, while the token is still unspent.
        if project is None:
            _unit(host, paths, gateway, key)
        sidecar_environment(host, paths, "gw_" + "0" * 26, CREDENTIAL_PREFIX + "0",
                            ConnectConfig("https://engine.invalid", "0.0.0"),
                            registration_digest="0" * 64, port=port, proxy=proxy,
                            ca_bundle=ca_bundle, jwt=jwt, token="0" * 43,
                            container=project is not None, gateway_endpoint=endpoint)
        got = redeem(host, engine=engine, token=token, digest=digest, proxy=proxy,
                     ca_bundle=ca_bundle)
        config, gateway_id = got.config, got.gateway_id
        _replace(paths.sidecar_env, sidecar_environment(
            host, paths, gateway_id, got.credential, config,
            registration_digest=registration.digest(sidecar_registration(paths, config)),
            port=port, proxy=proxy, ca_bundle=ca_bundle, jwt=jwt,
            token=secrets.token_urlsafe(32), container=project is not None,
            gateway_endpoint=endpoint).encode("utf-8"),
            private=True)
        shape_facts = ({"shape": SHAPE_COMPOSE, "compose": project.facts()} if project else
                       {"shape": SHAPE_SNAP, "snap": gateway.facts()} if gateway else {})
        record.mark("redeemed", gateway_id=gateway_id, config=got.raw_config,
                    engine=engine.rstrip("/"), port=int(port), **shape_facts)
        _say(out, f"gateway {gateway_id}: credential saved to {paths.sidecar_env}")
        if not jwt:
            _say(out, "note: neither gateway.toml nor the gateway's own files name a "
                      "gateway_jwt key, so the sidecar will not check that calls come "
                      "from the gateway (manual chapter 17)")
    if not _same_line(shape.openshell_version, config.openshell_version):
        raise ConnectError(f"this gateway is OpenShell {shape.openshell_version}, and the "
                           f"configuration was approved for {config.openshell_version}: "
                           "install that release, then run this again (no new token needed)")

    # 2. Nothing governs the gateway yet: no automatic approvals meanwhile.
    if not record.done("approval-manual"):
        _check(_setting(host, "manual"), f"setting {SELF_TEST_KEY} to manual")
        record.mark("approval-manual")
    if gateway is not None and not record.done("refresh-held"):
        # The snap stays this OpenShell release until the operator moves it.
        if not gateway.held:
            _check(snap.hold(host), f"holding the {snap.SNAP} snap's refreshes "
                                    f"(sudo snap refresh --hold {snap.SNAP})")
        record.mark("refresh-held", refresh_held_by_up=not gateway.held)

    # 3. The gateway's telemetry choice, in the file its unit reads. (Under
    # Compose it is in up's compose file, step 4; for the snap, in the
    # gateway's drop-in, step 5.)
    if project is None and gateway is None and not record.done("gateway-env"):
        before = paths.gateway_env.read_bytes() if paths.gateway_env.exists() else b""
        created = not paths.gateway_env.exists()
        if strip_block(before) is None:
            _replace(paths.env_backup, before, private=True)
            _replace(paths.gateway_env, add_block(before, telemetry_line(config)),
                     private=created)
        record.mark("gateway-env", env_sha256=_sha(before), env_created=created)

    # 4. The sidecar, as a service, up and answering. A sidecar already
    # running is brought up to date: its unit, when this artzain runs from
    # another environment (the 0.6.41 connect script installs into one of
    # its own), and the settings step 1 added. One restart for both; the
    # gateway, which requires it, restarts with it.
    if project is not None:
        _compose_sidecar(host, paths, project, record, image=image, release=release,
                         config=config, port=int(record.data.get("port", port)),
                         jwt_key=signer[0] if signer else "", settings_changed=settings_changed,
                         out=out)
    else:
        _sidecar_service(host, paths, record, _unit(host, paths, gateway, key),
                         settings_changed=settings_changed, out=out)
    if not _wait(host, 30, lambda: host.healthy(int(record.data.get("port", port)))):
        raise ConnectError("the sidecar did not answer within 30 s: see "
                           + (_journal(paths, SIDECAR_UNIT) if project is None else
                              f"`docker compose -p {project.name} logs {compose.SERVICE}`"))

    # 5. The registration, checked by the gateway's own preflight first.
    if not record.done("registration"):
        _register(host, paths, project, gateway, record, config)

    # 6. The gateway, restarted bound.
    if not record.done("gateway-restarted"):
        _restart_bound(host, paths, project)
        record.mark("gateway-restarted")

    # 7. The self-test.
    decision = self_test(host)
    record.mark("self-test", self_test_decision_id=decision, connected=True)
    _say(out, f"gateway {gateway_id} is governed: the self-test write was refused by "
              f"ArtzAIn decision {decision}.")
    receipt = receipt_url(record.data.get("engine") or engine, decision)
    if receipt:
        _say(out, f"its receipt: {receipt}")

    # 8. The first heartbeat and inventory. The sidecar sends them as it
    # starts, which can be while this restarts the gateway, so a listing
    # that failed is tried again before this is said. Say whether the engine
    # took them; reporting is not governance, so one it has not taken yet is
    # a note.
    reports = _first_reports(host, int(record.data.get("port", port)), _sidecar_token(paths))
    record.mark("reported", reports=reports)
    _say(out, _reports_said(reports))
    return dict(record.data)


#: How long ``up`` waits for the sidecar to have tried both reports.
REPORTS_WAIT_SECONDS = 30.0


def _sidecar_service(host: Host, paths: Layout, record: Record, unit: str, *,
                     settings_changed: bool, out: Callable[[str], None]) -> None:
    """``up``'s step 4 for a systemd gateway (the package's or the snap's):
    the sidecar's unit, enabled and started; or, when it already runs, its
    unit and settings brought up to date, with one restart for both (the
    gateway, which requires it, restarts with it)."""
    if not record.done("sidecar"):
        _put(host, paths, paths.sidecar_unit, unit.encode("utf-8"))
        private_dir(paths.state_dir)
        _reload(host, paths)
        _check(_ctl(host, paths, "enable", "--now", SIDECAR_UNIT), f"starting {SIDECAR_UNIT}")
        record.mark("sidecar")
        return
    now = _read(host, paths, paths.sidecar_unit)
    stale = now is None or now.decode("utf-8") != unit
    if stale:
        _put(host, paths, paths.sidecar_unit, unit.encode("utf-8"))
        _reload(host, paths)
    if stale or settings_changed:
        _say(out, f"restarting {SIDECAR_UNIT} to take "
                  + " and ".join(what for what, changed in (("its new unit", stale),
                                                            ("its new settings", settings_changed))
                                 if changed))
        _check(_ctl(host, paths, "restart", SIDECAR_UNIT, timeout=120),
               f"restarting {SIDECAR_UNIT}")
        if not _gateway_stays_up(host, paths):
            raise ConnectError(f"{paths.gateway_service} did not stay up: see "
                               f"{_journal(paths, paths.gateway_service)}")


def _register(host: Host, paths: Layout, project: Optional[compose.Project],
              gateway: Optional[snap.Gateway], record: Record, config: ConnectConfig) -> None:
    """``up``'s step 5: the registration added to ``gateway.toml`` once the
    gateway's own preflight passed on the result, and the gateway's unit made
    to require the sidecar (under Compose, ``.env`` made to name up's file)."""
    current = _read(host, paths, paths.gateway_toml)
    created = current is None
    current = current or b""
    if strip_block(current) is None:
        text = registration_text(paths, config, current.decode("utf-8"))
        candidate = add_block(current, text)
        trial = paths.candidate
        _replace(trial, candidate, private=True)
        try:
            _preflight(host, project, trial, gateway)
        finally:
            if trial.exists():
                trial.unlink()
        _replace(paths.toml_backup, current, private=True)
        record.mark("toml-saved", toml_sha256=_sha(current), toml_created=created)
        _put(host, paths, paths.gateway_toml, candidate, private=created and not paths.system)
    record.mark("registration")
    if project is not None:
        _compose_env(paths, project, record)
        return
    text = snap.dropin(config.telemetry) if gateway is not None else gateway_dropin()
    for dropin in paths.dropins:
        _put(host, paths, dropin, text.encode("utf-8"))
    _reload(host, paths)


# ---------------------------------------------------------------------------
# up, under Compose
# ---------------------------------------------------------------------------


def _compose_can_bind(host: Host, paths: Layout, project: compose.Project) -> None:
    """Before the token is spent, on a project ``up`` has not bound yet: its
    ``.env`` can take ``COMPOSE_FILE``, and ``docker compose`` from its files
    and ``.env`` brings the gateway up as it runs now (``up`` recreates it
    from them, plus its own file)."""
    env = paths.gateway_env.read_bytes() if paths.gateway_env.is_file() else b""
    if strip_block(env) is not None:
        return
    if compose.sets_compose_file(env.decode("utf-8", "replace")):
        raise ConnectError(f"{paths.gateway_env} sets COMPOSE_FILE: up adds its own compose "
                           "file there, in a block of its own. Name the project's files with "
                           "-f instead, then run this again")
    if host.environ.get("COMPOSE_FILE"):
        raise ConnectError("COMPOSE_FILE is set in this shell: docker compose would read it "
                           f"instead of {paths.gateway_env}, to which up adds its own compose "
                           "file. Unset it, then run this again")
    if not project.config_hash or compose.config_hash(host, project, None) != project.config_hash:
        raise ConnectError(f"docker compose, from {', '.join(project.files)} and "
                           f"{paths.gateway_env}, would not bring the gateway up as it runs now "
                           "(it was brought up with other settings: variables set in a shell, "
                           f"say). Put them in {paths.gateway_env}, run `docker compose up -d` "
                           f"in {project.directory}, then run this again")


def _sidecar_image(host: Host, record: Record, named: str,
                   out: Callable[[str], None]) -> Tuple[str, str]:
    """``(image, release)``: the sidecar image of this artzain release as
    cosign verifies it, by digest (kept in the record, so it is checked once
    per release), or the image the operator *named* by its digest, which is
    not checked (release empty)."""
    from artzain import __version__

    if named:
        if not compose.pinned(named):
            raise ConnectError("--sidecar-image must name the image by its digest: "
                               "name@sha256:<64 hex digits>, or a local image's id, "
                               "sha256:<64 hex digits>")
        _say(out, f"the sidecar runs from {named}, which you named: its signature is not "
                  "checked")
        return named, ""
    kept = str(record.data.get("sidecar_image") or "")
    if record.data.get("sidecar_image_release") == __version__ and compose.pinned(kept):
        return kept, __version__
    try:
        cosign = signed.cosign(host, layout(host).state_dir, lambda m: _say(out, m))
    except signed.UpgradeError as exc:
        raise ConnectError(str(exc)) from None
    _say(out, f"checking the signature of {compose.SIDECAR_IMAGE}:{__version__} with cosign")
    image = compose.verify_image(host, cosign, __version__)
    _say(out, f"the sidecar runs from {image}")
    return image, __version__


def _compose_sidecar(host: Host, paths: Layout, project: compose.Project, record: Record, *,
                     image: str, release: str, config: ConnectConfig, port: int, jwt_key: str,
                     settings_changed: bool, out: Callable[[str], None]) -> None:
    """Step 4 under Compose: up's compose file, and the sidecar's container
    up from it. A file that is not the one this artzain writes (an image of
    another release, say, after an upgrade), or settings that changed, and
    the sidecar is recreated, and the gateway, if bound, restarts with it."""
    text = compose.render(project, image=image, settings=paths.sidecar_env, port=port,
                          telemetry=config.telemetry, jwt_key=jwt_key or None,
                          ca_bundle=_settings(paths).get("OPENSHELL_SIDECAR_CA_BUNDLE", ""))
    current = (paths.compose_file.read_text(encoding="utf-8")
               if paths.compose_file.is_file() else None)
    if record.done("sidecar") and current == text and not settings_changed:
        return
    again = record.done("sidecar")
    if again:
        _say(out, f"bringing the sidecar's container up to date ({image})")
    _replace(paths.compose_file, text.encode("utf-8"))
    _check(compose.up(host, project, paths.compose_file, compose.SERVICE,
                      recreate=again and settings_changed),
           f"docker compose up -d {compose.SERVICE}")
    record.mark("sidecar", sidecar_image=image, sidecar_image_release=release)
    if again and record.done("gateway-restarted"):
        _check(compose.up(host, project, paths.compose_file, project.service, recreate=True),
               f"docker compose up -d {project.service}")
        if not compose.stays_up(host, project.name, project.service):
            raise ConnectError(f"the gateway's container did not stay up: see `docker compose "
                               f"-p {project.name} logs {project.service}`")
        _compose_gateway_answers(host, project)


def _compose_settings_up_to_date(paths: Layout, endpoint: str,
                                 out: Callable[[str], None]) -> bool:
    """A gateway under Compose connected by artzain 0.6.45: its sidecar's
    settings name neither the image's openshell CLI nor the gateway's
    endpoint, so its inventory is only what it has seen created, and its
    heartbeat carries no OpenShell release. Add them. True when something
    was added, and the sidecar must be recreated to read it."""
    saved = _saved(paths)
    missing: Dict[str, str] = {}
    if not saved.get("OPENSHELL_SIDECAR_LIST_CLI"):
        missing["OPENSHELL_SIDECAR_LIST_CLI"] = compose.CLI
    if not saved.get("OPENSHELL_GATEWAY_ENDPOINT"):
        missing["OPENSHELL_GATEWAY_ENDPOINT"] = endpoint
    if not missing:
        return False
    text = paths.sidecar_env.read_text(encoding="utf-8")
    _replace(paths.sidecar_env, _with_settings(text, missing).encode("utf-8"), private=True)
    _say(out, "the sidecar's settings now name its image's openshell CLI and the gateway's "
              "endpoint: it lists every sandbox, and reports the gateway's OpenShell release")
    return True


def _compose_env(paths: Layout, project: compose.Project, record: Record) -> None:
    """Step 5 under Compose: the project's ``.env`` adds up's file to
    ``COMPOSE_FILE``, so ``docker compose up -d`` in its folder keeps the
    gateway bound. Kept first, as ``gateway.toml`` is."""
    before = paths.gateway_env.read_bytes() if paths.gateway_env.exists() else b""
    if strip_block(before) is not None:
        return
    created = not paths.gateway_env.exists()
    _replace(paths.compose_env_backup, before, private=True)
    record.mark("compose-env-saved", compose_env_sha256=_sha(before), compose_env_created=created)
    _replace(paths.gateway_env, add_block(before, compose.compose_file_line(
        project, paths.compose_file)), private=created)


def _first_reports(host: Host, port: int, token: str) -> Optional[Dict[str, Any]]:
    """What the sidecar says the engine took, once it has tried both the
    heartbeat and the inventory, or what it last said after
    :data:`REPORTS_WAIT_SECONDS`.

    A listing that failed is tried again shortly (the gateway may have been
    restarting). This waits for a whole inventory, and keeps the last
    partial one when the wait ends with the listing still failing.
    """
    seen: Dict[str, Any] = {}

    def tried() -> bool:
        seen["reports"] = answer = host.reports(port, token)
        if not isinstance(answer, dict):
            return False
        if answer.get("reporting") is False:
            return True
        if not all(answer.get(what) in ("ok", "failed") for what in ("heartbeat", "inventory")):
            return False
        # The sidecar tries a failed listing again shortly. Wait for the
        # whole inventory; the wait's end still reports this partial one.
        return not (answer.get("inventory") == "ok" and answer.get("partial")
                    and answer.get("listing_error"))

    _wait(host, REPORTS_WAIT_SECONDS, tried)
    return seen.get("reports")


def _word(value: Any) -> str:
    """A name the sidecar sent, safe to print."""
    return re.sub(r"[^\w.]", "", str(value))[:60]


def _reports_said(reports: Optional[Dict[str, Any]]) -> str:
    status = "`artzain connect openshell status` shows when it has"
    if not isinstance(reports, dict):
        return ("note: the sidecar did not say what it reported to the engine: "
                f"{status}")
    if reports.get("reporting") is False:
        return ("note: the sidecar sends no heartbeat or inventory (it holds no gateway "
                f"credential): {status}")
    missing = [what for what in ("heartbeat", "inventory") if reports.get(what) != "ok"]
    if missing:
        errors = [_word(reports[f"{what}_error"]) for what in missing
                  if reports.get(f"{what}_error")]
        return (f"note: the engine has not taken this gateway's {' or its '.join(missing)} "
                f"yet{' (' + ', '.join(errors) + ')' if errors else ''}: {status}")
    count = int(reports.get("sandboxes") or 0)
    said = (f"the engine has this gateway's heartbeat, and its inventory: {count} "
            f"sandbox{'' if count == 1 else 'es'}")
    if reports.get("partial"):
        error = _word(reports.get("listing_error") or "")
        said += ", not every one" + (f" (the listing failed: {error})" if error else "")
    return said


def _settings(paths: Layout) -> Dict[str, str]:
    """The sidecar's settings as ``up`` wrote them; empty when there are none."""
    values: Dict[str, str] = {}
    try:
        text = paths.sidecar_env.read_text(encoding="utf-8")
    except OSError:
        text = ""
    for line in text.splitlines():
        if line and not line.startswith("#") and "=" in line:
            name, value = line.split("=", 1)
            if len(value) >= 2 and value[0] == value[-1] == '"':
                value = value[1:-1]
            values[name] = value
    return values


def _sidecar_token(paths: Layout) -> str:
    """What the sidecar's loopback routes take, or empty."""
    return _settings(paths).get("OPENSHELL_SIDECAR_TOKEN", "")


def _saved(paths: Layout) -> Dict[str, str]:
    """The sidecar's settings as ``up`` wrote them. Raises
    :class:`ConnectError` when there is no credential in them."""
    values = _settings(paths)
    if not values.get("COGNEXUS_API_KEY", "").startswith(CREDENTIAL_PREFIX):
        raise ConnectError(f"{paths.sidecar_env} holds no credential: run "
                           "`artzain connect openshell remove`, then `up` with a new token")
    return values


# ---------------------------------------------------------------------------
# remove
# ---------------------------------------------------------------------------


def revoke(host: Host, *, engine_url: str, gateway_id: str, credential: str, proxy: str = "",
           ca_bundle: str = "") -> bool:
    """Revoke this gateway's credential in the engine. True when the engine
    says it is revoked, or the credential is already unknown to it."""
    url = engine_url.rstrip("/") + f"/api/v1/openshell/gateways/{gateway_id}/revoke"
    try:
        status, _answer = host.post_json(url, headers={"X-Api-Key": credential}, body={},
                                         proxy=proxy, ca_bundle=ca_bundle)
    except Exception:  # noqa: BLE001 - reported by the caller, without the credential
        return False
    return status in (200, 401)


def remove(host: Host, *, keep_credential: bool = False,
           out: Callable[[str], None] = print) -> Dict[str, Any]:
    """Undo ``up``. Returns what was done. Raises :class:`ConnectError` only
    when the gateway does not come back up unbound."""
    paths = layout(host)
    record = Record.load(paths.record)
    data = record.data
    if data.get("shape") == SHAPE_COMPOSE:
        result = _unbind_compose(host, paths, data)
    else:
        gateway = _snap_of(host, data)
        result = _unbind_systemd(host, snap_layout(host, paths, gateway) if gateway else paths,
                                 data, gateway)

    revoked = None
    if data.get("gateway_id") and paths.sidecar_env.exists() and not keep_credential:
        saved = _saved(paths)
        revoked = revoke(host, engine_url=str(data.get("engine") or DEFAULT_ENGINE),
                         gateway_id=data["gateway_id"], credential=saved["COGNEXUS_API_KEY"],
                         proxy=saved.get("OPENSHELL_SIDECAR_PROXY", ""),
                         ca_bundle=saved.get("OPENSHELL_SIDECAR_CA_BUNDLE", ""))
        result["credential"] = "revoked" if revoked else "NOT revoked"
    if revoked is False:
        record.mark("revoke-pending")
        _say(out, f"the engine could not revoke gateway {data['gateway_id']}'s credential; it "
                  "is kept so that running `remove` again can revoke it")
        return result

    for path in (paths.sidecar_env, paths.toml_backup, paths.env_backup,
                 paths.compose_env_backup):
        if path.exists():
            path.unlink()
    if paths.state_dir.exists():
        shutil.rmtree(paths.state_dir)
    record.delete()
    _say(out, "removed: " + ", ".join(f"{k} {v}" for k, v in result.items()) if result
         else "nothing to remove")
    return result


def _unbind_systemd(host: Host, paths: Layout, data: Mapping[str, Any],
                    gateway: Optional[snap.Gateway] = None) -> Dict[str, Any]:
    """``remove``'s first half for the deb or rpm gateway, or the snap's: its
    files back, the gateway restarted unbound, the sidecar's service gone,
    and the snap's refreshes no longer held when ``up`` held them."""
    result: Dict[str, Any] = {}
    unit = paths.gateway_service
    if paths.gateway_toml.exists():
        result["gateway.toml"] = _restore(paths.gateway_toml, paths.toml_backup,
                                          data.get("toml_sha256", ""),
                                          bool(data.get("toml_created")), host=host, paths=paths)
    for dropin in paths.dropins:
        if _drop(host, paths, dropin):
            result["drop-in"] = "removed"
    _ctl(host, paths, "daemon-reload")
    if _ctl(host, paths, "is-active", unit, timeout=10).stdout.strip() in (
            "active", "activating", "failed") and result.get("gateway.toml") in (
            "restored", "kept-edits", "removed"):
        if paths.system:
            _ctl(host, paths, "reset-failed", unit, timeout=30)
        _check(_ctl(host, paths, "restart", unit, timeout=120), f"restarting {unit}")
        if not _gateway_stays_up(host, paths):
            raise ConnectError(f"{unit} did not come back up unbound: see "
                               f"{_journal(paths, unit)}")
        result["gateway"] = "restarted unbound"

    _ctl(host, paths, "disable", "--now", SIDECAR_UNIT)
    if _drop(host, paths, paths.sidecar_unit):
        result["sidecar"] = "removed"
    _ctl(host, paths, "daemon-reload")

    if gateway is None:
        if paths.gateway_env.exists():
            result["gateway.env"] = _restore(paths.gateway_env, paths.env_backup,
                                             data.get("env_sha256", ""),
                                             bool(data.get("env_created")))
        return result
    where = paths.socket.parent
    if where.exists():
        if paths.system:  # a folder of the operator's, in the snap's folder of root's
            host.run("sudo", "rm", "-rf", "--", where.as_posix(), timeout=30)
        else:
            shutil.rmtree(where, ignore_errors=True)
        result["socket folder"] = "removed"
    if data.get("refresh_held_by_up"):
        lifted = snap.unhold(host).returncode == 0
        result["refresh hold"] = ("lifted" if lifted else
                                  f"NOT lifted: run `sudo snap refresh --unhold {snap.SNAP}`")
    return result


def _unbind_compose(host: Host, paths: Layout, data: Mapping[str, Any]) -> Dict[str, Any]:
    """``remove``'s first half under Compose: ``gateway.toml`` and ``.env``
    back, the gateway recreated from the operator's files alone, then the
    sidecar's container, its volumes and up's compose file gone."""
    project = compose.recorded(data.get("compose") or {})
    paths = compose_layout(paths, project)
    result: Dict[str, Any] = {}
    if paths.gateway_toml.exists():
        result["gateway.toml"] = _restore(paths.gateway_toml, paths.toml_backup,
                                          data.get("toml_sha256", ""),
                                          bool(data.get("toml_created")))
    if paths.gateway_env.exists():
        result[".env"] = _restore(paths.gateway_env, paths.compose_env_backup,
                                  data.get("compose_env_sha256", ""),
                                  bool(data.get("compose_env_created")))
    changed = ("restored", "kept-edits", "removed")
    state = compose.status(host, project.name, project.service)
    if state.startswith(("running", "restarting")) and (
            result.get("gateway.toml") in changed or result.get(".env") in changed):
        _check(compose.up(host, project, None, project.service),
               f"docker compose up -d {project.service}")
        if not compose.stays_up(host, project.name, project.service):
            raise ConnectError(f"the gateway's container did not come back up unbound: see "
                               f"`docker compose -p {project.name} logs {project.service}`")
        result["gateway"] = "recreated unbound"
    elif state != "missing" and (result.get("gateway.toml") in changed
                                 or result.get(".env") in changed):
        # Stopped: recreated unbound and left stopped, so that it no longer
        # holds the socket's volume, and starts unbound.
        _check(compose.up(host, project, None, project.service, start=False),
               f"docker compose up --no-start {project.service}")
        result["gateway"] = f"recreated unbound, and left {state}"
    if compose.remove_sidecar(host, project.name):
        result["sidecar"] = "removed"
    if paths.compose_file.exists():
        paths.compose_file.unlink()
        result["compose file"] = "removed"
    return result


# ---------------------------------------------------------------------------
# rotate-key
# ---------------------------------------------------------------------------

#: How long ``rotate-key`` waits for the sidecar, restarted with the new
#: credential, to have its heartbeat taken.
ROTATE_WAIT_SECONDS = 45.0
_ROTATE_REFUSALS = {
    401: "the engine does not take this gateway's credential: the gateway was revoked; "
         "connect it again with a new token",
    403: "the engine refused the credential for this gateway",
    409: "the gateway already holds two live keys: run `artzain connect openshell "
         "rotate-key` again",
    429: "too many key rotations in an hour: wait, then run it again",
    503: "the engine could not write the keys: run it again",
}


def _with_key(text: str, credential: str) -> str:
    """The sidecar's settings with *credential* in place of the one they hold.
    Raises :class:`ConnectError` unless they hold exactly one."""
    lines = text.splitlines(keepends=True)
    found = [i for i, line in enumerate(lines) if line.startswith("COGNEXUS_API_KEY=")]
    if len(found) != 1:
        raise ConnectError("the sidecar's settings do not hold exactly one credential: run "
                           "`artzain connect openshell remove`, then `up` with a new token")
    lines[found[0]] = f'COGNEXUS_API_KEY="{credential}"\n'
    return "".join(lines)


def _with_settings(text: str, values: Mapping[str, str]) -> str:
    """The sidecar's settings with *values* added at their end."""
    if text and not text.endswith("\n"):
        text += "\n"
    return text + "".join(f'{name}="{value}"\n' for name, value in values.items())


def _bring_the_settings_up_to_date(paths: Layout, out: Callable[[str], None]) -> bool:
    """A gateway connected by artzain 0.6.40 or earlier: its sidecar has no
    token, so this one answers none of its routes but ``/healthz``, and does
    not know where gateway.toml is, so its heartbeat cannot say whether the
    registration is still there. Add what is missing. True when something
    was, and the sidecar must restart to take it (``up``'s step 4 does)."""
    saved = _saved(paths)
    missing: Dict[str, str] = {}
    if not saved.get("OPENSHELL_SIDECAR_TOKEN"):
        missing["OPENSHELL_SIDECAR_TOKEN"] = secrets.token_urlsafe(32)
    if not saved.get("OPENSHELL_GATEWAY_TOML"):
        missing["OPENSHELL_GATEWAY_TOML"] = paths.gateway_toml.as_posix()
    if not missing:
        return False
    for name, value in missing.items():
        if _UNSAFE.search(value):
            raise ConnectError(f"{name} holds a character a systemd environment file cannot "
                               "carry here")
    text = paths.sidecar_env.read_text(encoding="utf-8")
    _replace(paths.sidecar_env, _with_settings(text, missing).encode("utf-8"), private=True)
    said = {"OPENSHELL_SIDECAR_TOKEN": "a token for its loopback routes",
            "OPENSHELL_GATEWAY_TOML": "where gateway.toml is, for its heartbeat"}
    _say(out, "the sidecar's settings now hold " + " and ".join(said[name] for name in missing))
    return True


def _sidecar_takes_the_key(host: Host, port: int, token: str, *,
                           project: Optional[compose.Project] = None,
                           compose_file: Optional[Path] = None,
                           paths: Optional[Layout] = None) -> bool:
    """Restart the sidecar (the gateway, which requires it, restarts with it)
    and wait until it says whether the engine took its heartbeat. True when
    it did. Under Compose the sidecar's container is recreated, to read its
    settings again, and then the gateway's."""
    if project is None:
        _check(_ctl(host, paths, "restart", SIDECAR_UNIT, timeout=120),
               f"restarting {SIDECAR_UNIT}")
    else:
        for service in (compose.SERVICE, project.service):
            _check(compose.up(host, project, compose_file, service, recreate=True),
                   f"docker compose up -d {service}")
    seen: Dict[str, Any] = {}

    def heard() -> bool:
        seen["reports"] = reports = host.reports(port, token)
        return isinstance(reports, dict) and reports.get("heartbeat") in ("ok", "failed")

    _wait(host, ROTATE_WAIT_SECONDS, heard)
    reports = seen.get("reports")
    return isinstance(reports, dict) and reports.get("heartbeat") == "ok"


def rotate_key(host: Host, *, out: Callable[[str], None] = print) -> Dict[str, Any]:
    """Swap this gateway's credential for a new one.

    The live credential first retires any other key (one an earlier run
    minted and never put in use), then mints the next. The new one goes into
    the sidecar's settings, and the sidecar restarts with it. Once the
    engine has taken a heartbeat sent with it, the new credential retires
    the old. If the engine does not take it, the settings go back to the old
    credential, which then takes the new one back. Nothing here says a
    credential.
    """
    paths = layout(host)
    record = Record.load(paths.record)
    data = record.data
    if not data.get("connected") or not data.get("gateway_id"):
        raise ConnectError("this host's gateway is not connected: run "
                           "`artzain connect openshell up`")
    project = (compose.recorded(data.get("compose") or {})
               if data.get("shape") == SHAPE_COMPOSE else None)
    gateway = _snap_of(host, data)
    key: Optional[Path] = None
    if gateway is not None:
        paths = snap_layout(host, paths, gateway)
        _jwt, key = _snap_jwt(host, gateway,
                              (_read(host, paths, paths.gateway_toml) or b"").decode("utf-8"))
    saved = _saved(paths)
    before = paths.sidecar_env.read_bytes()
    _with_key(before.decode("utf-8"), CREDENTIAL_PREFIX + "0")  # one credential, or stop here
    unit = _unit(host, paths, gateway, key) if project is None else ""  # one systemd can run
    restart = {"project": project, "compose_file": paths.compose_file, "paths": paths}
    old = saved["COGNEXUS_API_KEY"]
    gateway_id = str(data["gateway_id"])
    route = (str(data.get("engine") or DEFAULT_ENGINE).rstrip("/")
             + f"/api/v1/openshell/gateways/{gateway_id}/keys")
    port = int(data.get("port") or DEFAULT_PORT)

    def call(tail: str, credential: str) -> Tuple[int, Any]:
        try:
            return host.post_json(route + tail, headers={"X-Api-Key": credential}, body={},
                                  proxy=saved.get("OPENSHELL_SIDECAR_PROXY", ""),
                                  ca_bundle=saved.get("OPENSHELL_SIDECAR_CA_BUNDLE", ""))
        except Exception as exc:  # noqa: BLE001 - said without the credential
            raise ConnectError(f"the engine could not be reached ({type(exc).__name__})") from None

    def refused(status: int) -> ConnectError:
        return ConnectError(_ROTATE_REFUSALS.get(status, f"the engine refused (HTTP {status})"))

    status, _answer = call("/retire-others", old)
    if status != 200:
        raise refused(status)
    status, answer = call("", old)
    if status != 200:
        raise refused(status)
    new = answer.get("credential") if isinstance(answer, dict) else None
    if (not isinstance(new, str) or not new.startswith(CREDENTIAL_PREFIX) or _UNSAFE.search(new)
            or len(new) > 256 or new == old):
        # Whatever was minted is taken back by the key that is still in use.
        call("/retire-others", old)
        raise ConnectError("the engine's answer holds no gateway credential")

    _replace(paths.sidecar_env, _with_key(before.decode("utf-8"), new).encode("utf-8"),
             private=True)
    # A sidecar connected before 0.6.37 runs as Type=simple, and the gateway
    # that restarts with it races its socket: its unit is brought up to date.
    if project is None and (_read(host, paths, paths.sidecar_unit) or b"") != unit.encode("utf-8"):
        _put(host, paths, paths.sidecar_unit, unit.encode("utf-8"))
        _reload(host, paths)
    token = saved.get("OPENSHELL_SIDECAR_TOKEN", "")
    if not _sidecar_takes_the_key(host, port, token, **restart):
        _replace(paths.sidecar_env, before, private=True)
        _sidecar_takes_the_key(host, port, token, **restart)
        call("/retire-others", old)
        raise ConnectError("the engine did not take the sidecar's heartbeat with the new "
                           "credential: the sidecar is back on the old credential, and the new "
                           "one is revoked. See `artzain connect openshell doctor`")
    status, _answer = call("/retire-others", new)
    retired = status == 200
    record.mark("rotated", key_rotated_at=int(host.wall()))
    # The gateway requires the sidecar, so it restarted with it.
    if project is not None:
        if not compose.stays_up(host, project.name, project.service):
            raise ConnectError("the credential is rotated, but the gateway's container did not "
                               f"come back up: see `docker compose -p {project.name} logs "
                               f"{project.service}`")
    elif not _gateway_stays_up(host, paths):
        raise ConnectError(f"the credential is rotated, but {paths.gateway_service} did not "
                           f"come back up: see {_journal(paths, paths.gateway_service)}")
    _say(out, f"gateway {gateway_id}: the credential is rotated; the sidecar uses the new one"
              + (", and the old one is revoked" if retired else
                 f". The engine did not revoke the old one (HTTP {status}): run "
                 "`artzain connect openshell rotate-key` again"))
    return {"gateway_id": gateway_id, "rotated": True, "old_key_retired": retired}


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


def status(host: Host) -> Dict[str, Any]:
    """What is installed, and whether it is up. Holds no credential."""
    paths = layout(host)
    try:
        record = Record.load(paths.record).data
    except ConnectError as exc:
        record = {"error": str(exc)}
    project = _recorded_project(record)
    gateway = _recorded_snap(host, record)
    if project is not None:
        paths = compose_layout(paths, project)
    elif gateway is not None:
        paths = snap_layout(host, paths, gateway)
    toml = _read(host, paths, paths.gateway_toml) or b""
    port = int(record.get("port") or DEFAULT_PORT)
    if project is not None:
        env = paths.gateway_env.read_bytes() if paths.gateway_env.is_file() else b""
        shape: Dict[str, Any] = {
            "shape": SHAPE_COMPOSE,
            "compose_project": project.name,
            "compose_file": paths.compose_file.exists(),
            "compose_env": strip_block(env) is not None,
            "sidecar": compose.status(host, project.name, compose.SERVICE),
            "gateway": compose.status(host, project.name, project.service),
        }
    elif gateway is not None:
        try:
            current: Optional[snap.Gateway] = snap.find(host)
        except ConnectError:
            current = None
        shape = {
            "shape": SHAPE_SNAP,
            "snap_mode": gateway.mode,
            "snap_revision": current.revision if current else None,
            "refresh_held": current.held if current else None,
            "drop_in": all(dropin.exists() for dropin in paths.dropins),
            "sidecar_unit": paths.sidecar_unit.exists(),
            "sidecar": (_ctl(host, paths, "is-active", SIDECAR_UNIT, timeout=10).stdout.strip()
                        or "unknown"),
            "gateway": (_ctl(host, paths, "is-active", gateway.unit, timeout=10).stdout.strip()
                        or "unknown"),
        }
    else:
        shape = {
            "shape": SHAPE_SYSTEMD_USER,
            "drop_in": paths.dropin.exists(),
            "sidecar_unit": paths.sidecar_unit.exists(),
            "sidecar": (_systemctl(host, "is-active", SIDECAR_UNIT, timeout=10).stdout.strip()
                        or "unknown"),
            "gateway": (_systemctl(host, "is-active", GATEWAY_UNIT, timeout=10).stdout.strip()
                        or "unknown"),
        }
    return {
        "gateway_id": record.get("gateway_id"),
        "steps": record.get("steps", []),
        "connected": bool(record.get("connected")),
        "self_test_decision_id": record.get("self_test_decision_id"),
        "self_test_receipt": receipt_url(record.get("engine"), record.get("self_test_decision_id"))
        or None,
        "credential_saved": paths.sidecar_env.exists(),
        "registration_in_gateway_toml": strip_block(toml) is not None,
        **shape,
        "sidecar_answers": host.healthy(port),
        "record_error": record.get("error"),
        # What the sidecar says the engine took: its last heartbeat and inventory.
        "reports": host.reports(port, _sidecar_token(paths)),
        "break_glass": host.break_glass(port, _sidecar_token(paths)),
    }


# ---------------------------------------------------------------------------
# upgrade
# ---------------------------------------------------------------------------


def upgrade(host: Host, *, to: Optional[str] = None, check: bool = False,
            current: Optional[str] = None,
            out: Callable[[str], None] = print) -> Dict[str, Any]:
    """Move this connected gateway to a newer artzain: only to one the
    signed compatibility manifest lists with the installed OpenShell release,
    and by running that release's connect script, checked against the
    SHA-256 the manifest names. *to* names the version (it must be listed,
    and newer); *check* says what would happen and changes nothing.
    Returns what it did."""
    from artzain import __version__

    current = current or __version__
    paths = layout(host)
    record = Record.load(paths.record)
    if not record.data.get("connected"):
        raise ConnectError("this host's gateway is not connected: run "
                           "`artzain connect openshell up` first")
    openshell = detect(host).openshell_version
    work = Path(tempfile.mkdtemp(prefix="artzain-upgrade-"))
    try:
        try:
            serial = signed.newest_serial(host, work)
            cosign = signed.cosign(host, paths.state_dir, lambda m: _say(out, m))
            manifest_path, bundle = work / signed.MANIFEST, work / signed.BUNDLE
            base = f"{signed.RELEASES}compat-v{serial}/"
            signed.fetch(host, base + signed.MANIFEST, manifest_path, what=signed.MANIFEST)
            signed.fetch(host, base + signed.BUNDLE, bundle, what=signed.BUNDLE)
            signed.verify(host, cosign, manifest_path, bundle)
            manifest = signed.read(manifest_path, serial)
        except signed.UpgradeError as exc:
            raise ConnectError(str(exc)) from None
        last = int(record.data.get("compat_serial") or 0)
        if serial < last:
            raise ConnectError(f"the newest signed manifest is serial {serial}, and this host "
                               f"has read serial {last}: refusing an older one")
        record.mark("compat", compat_serial=serial)
        pairs = signed.listed(manifest, openshell)
        if not pairs:
            raise ConnectError(f"the signed manifest (serial {serial}) lists no artzain for "
                               f"OpenShell {openshell}")
        if to is not None:
            chosen = [p for p in pairs if p["artzain"] == to]
            if not chosen:
                raise ConnectError(f"artzain {to} is not listed with OpenShell {openshell} "
                                   f"(manifest serial {serial})")
            if signed.key(to) <= signed.key(current):
                raise ConnectError(f"artzain {to} is not newer than this artzain, {current}")
            target = chosen[0]
        else:
            target = pairs[0]
        summary: Dict[str, Any] = {"upgraded": False, "from": current, "to": target["artzain"],
                                   "serial": serial, "openshell": openshell}
        if signed.key(target["artzain"]) <= signed.key(current):
            _say(out, f"artzain {current} is the newest listed with OpenShell {openshell} "
                      f"(manifest serial {serial}): nothing to do")
            return {**summary, "to": current}
        if check:
            _say(out, f"artzain {target['artzain']} is listed with OpenShell {openshell} "
                      f"(manifest serial {serial}); run `artzain connect openshell upgrade` "
                      "to move to it")
            return {**summary, "check": True}
        try:
            connect_script = signed.script(host, work, target)
        except signed.UpgradeError as exc:
            raise ConnectError(str(exc)) from None
        _say(out, f"moving to artzain {target['artzain']}, listed with OpenShell {openshell} "
                  f"in the signed manifest (serial {serial}): running "
                  f"{connect_script.name}, checked against its SHA-256")
        engine = str(record.data.get("engine") or DEFAULT_ENGINE)
        port = str(int(record.data.get("port") or DEFAULT_PORT))
        status_code = host.execute("sh", str(connect_script), "--engine", engine, "--port", port)
        if status_code != 0:
            raise ConnectError(f"{connect_script.name} stopped (exit {status_code}): see what it "
                               "said above; run `artzain connect openshell upgrade` again")
        Record.load(paths.record).mark("upgraded", upgraded_from=current,
                                       upgraded_to=target["artzain"])
        return {**summary, "upgraded": True}
    finally:
        shutil.rmtree(work, ignore_errors=True)


# ---------------------------------------------------------------------------
# break-glass
# ---------------------------------------------------------------------------

#: The longest window, as the sidecar holds it (``breakglass.MAX_MINUTES``).
BREAK_GLASS_MAX_MINUTES = 240


def _break_glass_state(port: int, token: str) -> Optional[Dict[str, Any]]:
    """The sidecar's break-glass window and what waits, or None when it
    does not say."""
    if not token:
        return None
    try:
        answer = _sidecar_get(port, "/artzain/break-glass", token)
    except Exception:  # noqa: BLE001 - it does not say
        return None
    return answer if isinstance(answer, dict) else None


def _break_glass_target(host: Host) -> Tuple[int, str]:
    """The sidecar's loopback port and its token, as ``up`` saved them."""
    paths = layout(host)
    record = Record.load(paths.record).data
    token = _sidecar_token(paths)
    if not token:
        raise ConnectError(f"{paths.sidecar_env} holds no OPENSHELL_SIDECAR_TOKEN: "
                           "run `artzain connect openshell up` again")
    return int(record.get("port") or DEFAULT_PORT), token


def break_glass(host: Host, *, minutes: Optional[int] = None, reason: str = "",
                close: bool = False) -> Dict[str, Any]:
    """Open a break-glass window of *minutes* for *reason*, or *close* the
    open one; with neither, say what is open.

    While a window is open, a governed write ArtzAIn cannot answer (no
    answer at all, or a 5xx) goes through, and the sidecar journals it. Its
    journal goes to the engine when it can be reached, and each write
    becomes a flagged receipt; the window goes to the Review Queue. Only
    this host's user opens one: the sidecar takes it on loopback, with its
    own token.
    """
    if close:
        port, token = _break_glass_target(host)
        return _sidecar_post(port, "/artzain/break-glass/close", {}, token)
    if minutes is None:
        port, token = _break_glass_target(host)
        state = host.break_glass(port, token)
        if state is None:
            raise ConnectError("the sidecar did not say: is it running?")
        return state
    if not (isinstance(minutes, int) and 1 <= minutes <= BREAK_GLASS_MAX_MINUTES):
        raise ConnectError(f"--minutes must be from 1 to {BREAK_GLASS_MAX_MINUTES}")
    if not (reason or "").strip():
        raise ConnectError("--reason is needed: why the window is open, in one line")
    port, token = _break_glass_target(host)
    return _sidecar_post(port, "/artzain/break-glass",
                         {"minutes": minutes, "reason": reason.strip(),
                          "opened_by": getpass.getuser()}, token)


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------

#: How far this host's clock may be from the engine's before doctor warns,
#: and before it fails.
CLOCK_WARN_SECONDS = 60.0
CLOCK_FAIL_SECONDS = 300.0


def _block_body(current: bytes) -> Optional[str]:
    """What is between the managed block's marker lines, or None when the
    file does not hold exactly one whole block."""
    if strip_block(current) is None:
        return None
    text = current.decode("utf-8")
    start = text.index(BLOCK_BEGIN + "\n") + len(BLOCK_BEGIN) + 1
    return text[start:text.index(BLOCK_END + "\n", start)]


def _plain_http_elsewhere(url: str) -> bool:
    """True for a plain ``http`` URL whose host is not this machine (a
    loopback address or ``localhost``). What goes there carries an enroll
    token or the gateway's credential. Other schemes are the transport's to
    refuse."""
    parts = urllib.parse.urlsplit(url.strip())
    if parts.scheme.lower() != "http":
        return False
    host = (parts.hostname or "").lower()
    if host == "localhost":
        return False
    try:
        return not ipaddress.ip_address(host).is_loopback
    except ValueError:
        return True


def _origin(url: str) -> str:
    """``scheme://host[:port]`` of *url*, with no user or password."""
    parts = urllib.parse.urlsplit(url)
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme}://{parts.hostname}{port}"


def _through(proxy: str) -> str:
    """How the engine is reached, for a sentence. Never a proxy password."""
    if not proxy:
        return ""
    if proxy == "env":
        return " through the environment's proxy"
    parts = urllib.parse.urlsplit(proxy)
    return f" through the proxy {parts.hostname}:{parts.port or 80}"


def _engine_time(date: str) -> Optional[float]:
    import email.utils

    try:
        return email.utils.parsedate_to_datetime(date).timestamp() if date else None
    except (TypeError, ValueError):
        return None


def _doctor_systemd(host: Host, paths: Layout, found: Callable[[str, str, str], None]) -> None:
    """doctor's checks of the socket and drop-in of the deb's gateway, or the
    snap's."""
    try:
        socket_stat = host.stat(paths.socket)
    except OSError:
        found("socket", "fail", f"{paths.socket} is missing: the sidecar is not serving the "
                                "gateway")
    else:
        problems = []
        if not stat.S_ISSOCK(socket_stat.st_mode):
            problems.append("it is not a socket")
        mode = stat.S_IMODE(socket_stat.st_mode)
        if mode & 0o077:
            problems.append(f"it is {mode:04o}, so other users can call the interceptor")
        if socket_stat.st_uid != host.uid:
            problems.append("it belongs to another user")
        try:
            folder = stat.S_IMODE(host.stat(paths.socket.parent).st_mode)
        except OSError:
            problems.append("its folder cannot be read")
        else:
            if folder & 0o077:
                problems.append(f"its folder is {folder:04o}")
        found("socket", "fail" if problems else "ok",
              f"{paths.socket}: " + ("; ".join(problems) if problems
                                     else "the owner's alone, in a folder of the owner's alone"))

    # The drop-in that makes the gateway wait for the sidecar.
    missing = [dropin for dropin in paths.dropins if not dropin.is_file()]
    found("drop_in", "fail" if missing else "ok",
          f"{missing[0]} is missing: the gateway does not wait for the sidecar" if missing else
          " and ".join(str(dropin) for dropin in paths.dropins)
          + (" is" if len(paths.dropins) == 1 else " are") + " in place")


def _doctor_snap(host: Host, data: Mapping[str, Any], gateway: snap.Gateway,
                 found: Callable[[str, str, str], None]) -> Optional[snap.Gateway]:
    """doctor's checks of the snap: its gateway in the mode ``up`` bound,
    its refreshes held, its revision. Returns the snap's gateway now."""
    try:
        current = snap.find(host)
    except ConnectError as exc:
        found("snap", "fail", str(exc))
        return None
    facts = data.get("snap") or {}
    if current is None:
        found("snap", "fail", f"the {snap.SNAP} snap is not installed")
    elif current.mode != gateway.mode:
        found("snap", "fail", f"the snap runs its {current.mode} gateway, and `up` bound its "
                              f"{gateway.mode} one: the gateway runs without ArtzAIn's "
                              f"registration. Run `sudo snap set {snap.SNAP} gateway-mode="
                              f"{gateway.mode}`, or `remove` and then `up` with a new token")
    elif not current.held:
        found("snap", "warn", f"the snap's refreshes are not held: a refresh can move OpenShell "
                              f"off the approved release (`sudo snap refresh --hold {snap.SNAP}`)")
    elif facts.get("revision") and current.revision != facts.get("revision"):
        found("snap", "warn", f"the snap was refreshed since `up`, from revision "
                              f"{facts.get('revision')} to {current.revision} (OpenShell "
                              f"{current.version})")
    else:
        found("snap", "ok", f"the snap runs its {current.mode} gateway (`{current.app}`, "
                            f"revision {current.revision}), and its refreshes are held")
    return current


def _doctor_services(host: Host, paths: Layout, project: Optional[compose.Project], port: int,
                     found: Callable[[str, str, str], None]) -> Dict[str, Dict[str, Any]]:
    """doctor's checks of the gateway and the sidecar, both up. Returns the
    project's containers, under Compose."""
    answers = host.healthy(port)
    if project is None:
        unit = paths.gateway_service
        state = _ctl(host, paths, "is-active", unit, timeout=10).stdout.strip() or "unknown"
        found("gateway", "ok" if state == "active" else "fail", f"{unit} is {state}")
        state = (_ctl(host, paths, "is-active", SIDECAR_UNIT, timeout=10).stdout.strip()
                 or "unknown")
        found("sidecar", "ok" if state == "active" and answers else "fail",
              f"{SIDECAR_UNIT} is {state}, and "
              + (f"answers on 127.0.0.1:{port}" if answers
                 else f"nothing answers on 127.0.0.1:{port}"))
        return {}
    running = compose.containers(host, project.name)
    state = compose.status(host, project.name, project.service)
    found("gateway", "ok" if state.startswith("running") else "fail",
          f"the gateway's container ({project.service} of project {project.name}) is {state}")
    state = compose.status(host, project.name, compose.SERVICE)
    found("sidecar", "ok" if state == "running (healthy)" and answers else "fail",
          f"the sidecar's container ({compose.SERVICE}) is {state}, and "
          + (f"answers on 127.0.0.1:{port}" if answers
             else f"nothing answers on 127.0.0.1:{port}"))
    return running


def _doctor_versions(host: Host, paths: Layout, project: Optional[compose.Project],
                     release: Optional[str], config: Optional[ConnectConfig],
                     found: Callable[[str, str, str], None]) -> None:
    """doctor's check of the gateway's OpenShell release against the approved
    one. *release* is the snap's, for the snap shape."""
    if release is not None:
        version = _VERSION.search(release)
    elif project is None:
        done = host.run("openshell-gateway", "--version", timeout=30)
        version = (_VERSION.search((done.stdout or "") + " " + (done.stderr or ""))
                   if done.returncode == 0 else None)
    else:
        version = _VERSION.fullmatch(_compose_release(host, paths))
    if not version:
        found("versions", "fail", "the snap did not say its OpenShell release"
              if release is not None else "openshell-gateway --version did not say its version")
    elif config is None:
        found("versions", "warn", f"the gateway is OpenShell {version.group(0)}; the record "
                                  "holds no approved release to compare with")
    elif not _same_line(version.group(0), config.openshell_version):
        found("versions", "fail", f"the gateway is OpenShell {version.group(0)}, and the "
                                  f"configuration was approved for {config.openshell_version}")
    else:
        found("versions", "ok", f"the gateway is OpenShell {version.group(0)}, as approved "
                                f"({config.openshell_version})")


def _compose_release(host: Host, paths: Layout) -> str:
    """The OpenShell release of the Compose gateway's image, or empty."""
    try:
        project = compose.find(host, paths.compose_file)
        return compose.version(host, project) if project is not None else ""
    except ConnectError:
        return ""


def _doctor_compose(host: Host, paths: Layout, project: compose.Project,
                    running: Mapping[str, Dict[str, Any]],
                    found: Callable[[str, str, str], None]) -> None:
    """doctor's checks of the socket, and of the project, under Compose."""
    sidecar = running.get(compose.SERVICE)
    said = compose.socket(host, str(sidecar.get("Id"))) if sidecar else None
    problems = []
    if said is None:
        problems.append("the sidecar's container did not say (is it running?)")
    elif not said.get("socket"):
        problems.append("it is missing: the sidecar is not serving the gateway")
    else:
        is_socket, mode, uid = said["socket"]
        if not is_socket:
            problems.append("it is not a socket")
        if mode & 0o077:
            problems.append(f"it is {mode:04o}, so other users can call the interceptor")
        if uid != compose.SIDECAR_UID:
            problems.append("it does not belong to the sidecar's user")
        folder = said.get("folder")
        if not folder or folder[1] & 0o077:
            problems.append(f"its folder is {folder[1]:04o}" if folder
                            else "its folder cannot be read")
    if not compose.mounts_socket(running.get(project.service)):
        problems.append("the gateway's container does not mount it")
    found("socket", "fail" if problems else "ok",
          f"{compose.SOCKET} (volume {compose.SOCKET_VOLUME}): "
          + ("; ".join(problems) if problems else
             "the sidecar's alone, and the gateway's container mounts it"))

    # docker compose up -d in the folder, as the operator runs it, keeps the
    # gateway bound: .env names up's file, and the gateway would come up as
    # it runs now.
    env = paths.gateway_env.read_bytes() if paths.gateway_env.is_file() else b""
    gateway = running.get(project.service) or {}
    label = ((gateway.get("Config") or {}).get("Labels") or {}).get(
        "com.docker.compose.config-hash", "")
    if strip_block(env) is None or not paths.compose_file.is_file():
        found("compose", "fail", f"{paths.gateway_env} does not add {paths.compose_file} to "
                                 f"COMPOSE_FILE: the next `docker compose up -d` in "
                                 f"{project.directory} recreates the gateway without the "
                                 "sidecar's socket. Run `artzain connect openshell remove`, "
                                 "then `up` with a new token")
    elif not label or compose.operator_hash(host, project) != label:
        found("compose", "fail", f"`docker compose up -d` in {project.directory} would "
                                 "recreate the gateway otherwise than it runs now: run "
                                 "`artzain connect openshell up` again")
    else:
        found("compose", "ok", f"`docker compose up -d` in {project.directory} keeps the "
                               "gateway bound")


def doctor(host: Host) -> Dict[str, Any]:
    """Check what binds this host's gateway: the record, both services, the
    credential file, the interceptor socket, the drop-in, the registration,
    the OpenShell release, the CLI, the engine through the sidecar's proxy,
    the clock against the engine's, and the sidecar's reports. Each check is
    ``ok``, ``warn`` or ``fail`` with what it found; ``ok`` is false when
    one fails. Changes nothing, and holds no credential."""
    paths = layout(host)
    checks: List[Dict[str, str]] = []

    def found(check: str, result: str, says: str) -> None:
        checks.append({"check": check, "result": result, "says": says})

    # The record.
    try:
        data = Record.load(paths.record).data
    except ConnectError as exc:
        data = {}
        found("record", "fail", str(exc))
    else:
        if data.get("connected"):
            receipt = receipt_url(data.get("engine"), data.get("self_test_decision_id"))
            found("record", "ok", f"gateway {data.get('gateway_id')} is connected (self-test "
                                  f"decision {data.get('self_test_decision_id')}"
                                  + (f", receipt {receipt})" if receipt else ")"))
        else:
            found("record", "fail", "this host's gateway is not connected: run "
                                    "`artzain connect openshell up`")
    try:
        config: Optional[ConnectConfig] = parse_config(data["config"]) if data.get("config") else None
    except ConnectError:
        config = None
    port = int(data.get("port") or DEFAULT_PORT)
    project, gateway, release = None, None, None
    if data.get("shape") == SHAPE_COMPOSE:
        try:
            project = compose.recorded(data.get("compose") or {})
        except ConnectError as exc:
            found("compose", "fail", str(exc))
        else:
            paths = compose_layout(paths, project)
    elif data.get("shape") == SHAPE_SNAP:
        try:
            gateway = _snap_of(host, data)
        except ConnectError as exc:
            found("snap", "fail", str(exc))
        else:
            paths = snap_layout(host, paths, gateway)
            now = _doctor_snap(host, data, gateway, found)
            release = now.version if now is not None else ""

    # The two services.
    running = _doctor_services(host, paths, project, port, found)

    # The credential file.
    saved: Dict[str, str] = {}
    try:
        saved = _saved(paths)
        mode = stat.S_IMODE(host.stat(paths.sidecar_env).st_mode)
    except (ConnectError, OSError) as exc:
        found("credential", "fail", str(exc) if isinstance(exc, ConnectError)
              else f"{paths.sidecar_env} cannot be read")
    else:
        if mode & 0o077:
            found("credential", "fail", f"{paths.sidecar_env} is {mode:04o}: other users can "
                                        "read the gateway's credential (chmod 600 it)")
        elif not saved.get("OPENSHELL_SIDECAR_TOKEN"):
            found("credential", "fail", f"{paths.sidecar_env} holds no OPENSHELL_SIDECAR_TOKEN, "
                                        "so the sidecar answers no local caller: run "
                                        "`artzain connect openshell up` again")
        else:
            found("credential", "ok", f"{paths.sidecar_env} holds a credential and is the "
                                      "owner's alone")

    # The socket the gateway calls the interceptor on.
    if project is not None:
        _doctor_compose(host, paths, project, running, found)
    else:
        _doctor_systemd(host, paths, found)

    # The registration: what gateway.toml holds, and what the sidecar was
    # installed with.
    current = _read(host, paths, paths.gateway_toml) or b""
    body = _block_body(current)
    if config is None:
        found("registration", "fail", "the record holds no approved configuration to check "
                                      "the registration against")
    elif body is None:
        found("registration", "fail", f"{paths.gateway_toml} holds no ArtzAIn registration")
    else:
        expected = sidecar_registration(paths, config)
        if expected.strip() not in body:
            found("registration", "fail", f"the registration in {paths.gateway_toml} is not "
                                          "the one `up` wrote: run `artzain connect openshell "
                                          "remove`, then `up` with a new token")
        elif saved.get("OPENSHELL_REGISTRATION_DIGEST") != registration.digest(expected):
            found("registration", "fail", "the sidecar was installed for another registration "
                                          f"than the one in {paths.gateway_toml}")
        else:
            found("registration", "ok", f"{paths.gateway_toml} registers this sidecar, as it "
                                        "was installed")

    # The OpenShell release against the approved one.
    _doctor_versions(host, paths, project, release, config, found)

    # The CLI that the sidecar lists sandboxes with.
    done = host.run("openshell", "settings", "get", "--global", timeout=60)
    register = (_SNAP_REGISTER[gateway.mode][1] if gateway is not None else
                "openshell gateway add https://127.0.0.1:17670 --local --name openshell")
    found("cli", "ok" if done.returncode == 0 else "fail",
          "the openshell CLI reaches the gateway" if done.returncode == 0 else
          f"the openshell CLI cannot reach the gateway: register it ({register}): "
          + _said(done)[-200:])

    # The engine, the way the sidecar reaches it, and the clock against it.
    url = saved.get("ARTZAIN_DECISION_URL") or (config.decision_url if config else "")
    proxy = saved.get("OPENSHELL_SIDECAR_PROXY", "")
    engine_time = None
    if not url:
        found("engine", "fail", "no engine URL is saved for the sidecar")
    else:
        origin = _origin(url)
        try:
            status, headers = host.get_engine(origin + "/health", proxy=proxy,
                                              ca_bundle=saved.get("OPENSHELL_SIDECAR_CA_BUNDLE", ""))
        except Exception as exc:  # noqa: BLE001 - the check says what failed, never a credential
            found("engine", "fail", f"{origin} cannot be reached{_through(proxy)} "
                                    f"({type(exc).__name__})")
        else:
            engine_time = _engine_time(str(headers.get("Date") or ""))
            found("engine", "ok" if status == 200 else "fail",
                  f"{origin} answers{_through(proxy)}" if status == 200 else
                  f"{origin} answered HTTP {status}{_through(proxy)}")
    if engine_time is None:
        found("clock", "warn", "the engine gave no time to compare this host's clock with")
    else:
        skew = abs(host.wall() - engine_time)
        result = ("ok" if skew <= CLOCK_WARN_SECONDS else
                  "warn" if skew <= CLOCK_FAIL_SECONDS else "fail")
        found("clock", result, f"this host's clock is {int(skew)} s off the engine's")

    # What the sidecar reported.
    reports = host.reports(port, saved.get("OPENSHELL_SIDECAR_TOKEN", ""))
    if not isinstance(reports, dict):
        found("reports", "fail", "the sidecar did not say what it reported")
    elif reports.get("reporting") is False:
        found("reports", "fail", "the sidecar sends no heartbeat or inventory: it holds no "
                                 "gateway credential")
    else:
        failed = [what for what in ("heartbeat", "inventory") if reports.get(what) == "failed"]
        waiting = [what for what in ("heartbeat", "inventory")
                   if reports.get(what) not in ("ok", "failed")]
        if failed:
            errors = [_word(reports[f"{what}_error"]) for what in failed
                      if reports.get(f"{what}_error")]
            found("reports", "fail", f"the engine did not take the last {' or '.join(failed)}"
                                     + (f" ({', '.join(errors)})" if errors else ""))
        elif waiting:
            found("reports", "warn", f"the {' and the '.join(waiting)} not yet taken by the "
                                     "engine")
        elif reports.get("partial") and project is not None and not reports.get("listing_error"):
            found("reports", "warn", "the last inventory is the sandboxes the sidecar has seen "
                                     "created: its settings name no openshell CLI to list them "
                                     "with. Run `artzain connect openshell up` again (no new "
                                     "token): it adds the image's")
        elif reports.get("partial"):
            error = _word(reports.get("listing_error") or "")
            found("reports", "warn", "the last inventory was not every sandbox"
                                     + (f" (the listing failed: {error})" if error else ""))
        else:
            count = int(reports.get("sandboxes") or 0)
            found("reports", "ok", "the engine took the last heartbeat and inventory "
                                   f"({count} sandbox{'' if count == 1 else 'es'})")

    return {"ok": all(check["result"] != "fail" for check in checks), "checks": checks}


__all__ = ["CONFIG_KIND", "CONFIG_VERSION", "ConnectConfig", "ConnectError", "Host", "Layout",
           "Record", "Redeemed", "Shape", "add_block", "config_digest", "detect", "layout",
           "doctor", "parse_config", "redeem", "remove", "revoke", "rotate_key", "self_test",
           "status", "strip_block", "up"]
