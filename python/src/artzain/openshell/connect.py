"""``artzain connect openshell``: bind an OpenShell gateway on this host to ArtzAIn.

This release handles one gateway shape: the deb or rpm package, which runs
the gateway as a systemd *user* service (``openshell-gateway.service``,
``~/.config/openshell/gateway.toml``). Homebrew, snap and Compose come later,
and are refused with a message that says so.

``up`` takes an enroll token (``ARTZAIN_ENROLL_TOKEN``) and the digest of the
configuration the operator approved, and then:

1. swaps the token for the gateway's credential and that configuration
   (``POST /api/v1/openshell/connect/redeem``), and checks the configuration
   against the digest. The credential goes straight into the sidecar's
   settings file (``0600``), so a run that stops later needs no new token;
2. sets the gateway's ``proposal_approval_mode`` to ``manual`` while nothing
   governs it yet;
3. writes the gateway's telemetry choice into ``gateway.env``;
4. installs the sidecar as a systemd user service, starts it and waits until
   it answers;
5. adds the two interceptor registrations to ``gateway.toml`` as one marked
   block, after ``openshell-gateway config preflight`` has passed on the
   result, and makes the gateway's unit require the sidecar;
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

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

from artzain._private_files import private_dir, write_private
from artzain.openshell import registration, transport

#: What the configuration a token carries says it is, and the one version
#: this release reads.
CONFIG_KIND = "artzain.openshell.connect"
CONFIG_VERSION = 1
_CONFIG_KEYS = frozenset({"kind", "version", "decision_url", "openshell_version",
                          "interceptor_timeout_ms", "decide_timeout_ms", "telemetry"})
#: The shape this release can bind.
SHAPE_SYSTEMD_USER = "systemd-user"

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

#: The lines a managed block starts and ends with. A file holds one block.
BLOCK_BEGIN = ("# >>> artzain connect openshell: added by `artzain connect openshell up`; "
               "`artzain connect openshell remove` takes it out. Do not edit.")
BLOCK_END = "# <<< artzain connect openshell"

_GATEWAY_ID = re.compile(r"^gw_[0-9A-HJKMNP-TV-Z]{26}$")
_DECISION_ID = re.compile(r"\(([0-9A-HJKMNP-TV-Z]{26})\)")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_VERSION = re.compile(r"(\d+)\.(\d+)\.(\d+)")
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
                 healthy: Optional[Callable[[int], bool]] = None,
                 post_json: Optional[Callable[..., Tuple[int, Any]]] = None,
                 which: Optional[Callable[[str], Optional[str]]] = None,
                 sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic,
                 platform: Optional[str] = None,
                 executable: Optional[str] = None,
                 uid: Optional[int] = None) -> None:
        self.environ = dict(os.environ if environ is None else environ)
        self.root = Path(root)
        self._runner = runner or _run
        self._healthy = healthy or _healthy
        self._post_json = post_json or _post_json
        self._which = which
        self.sleep = sleep
        self.clock = clock
        self.platform = platform or sys.platform
        self.executable = executable or sys.executable
        self.uid = uid if uid is not None else (os.getuid() if hasattr(os, "getuid") else 0)

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

    def healthy(self, port: int) -> bool:
        return self._healthy(port)

    def post_json(self, url: str, *, headers: Mapping[str, str], body: Mapping[str, Any],
                  proxy: str = "", ca_bundle: str = "") -> Tuple[int, Any]:
        return self._post_json(url, headers=headers, body=body, proxy=proxy, ca_bundle=ca_bundle)


def _run(argv: List[str], *, env: Mapping[str, str], timeout: float) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, env=dict(env), capture_output=True, text=True,
                              timeout=timeout, check=False)
    except FileNotFoundError:
        return subprocess.CompletedProcess(argv, 127, "", f"{argv[0]}: not found")
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(argv, 124, "", f"{argv[0]}: timed out")


def _healthy(port: int) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{int(port)}/healthz",  # noqa: S310
                                    timeout=2) as resp:
            return resp.status == 200 and json.loads(resp.read(4096) or b"{}").get("ok") is True
    except Exception:  # noqa: BLE001 - not up yet
        return False


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

    @property
    def toml_backup(self) -> Path:
        return self.artzain_dir / "gateway.toml.before"

    @property
    def env_backup(self) -> Path:
        return self.artzain_dir / "gateway.env.before"


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


@dataclass(frozen=True)
class Shape:
    kind: str
    openshell_version: str
    paths: Layout


def detect(host: Host) -> Shape:
    """The gateway on this host, when it is one this release can bind."""
    if not host.platform.startswith("linux"):
        raise ConnectError("this release binds the deb or rpm gateway on Linux only; "
                           "Homebrew, snap and Compose come later")
    if sys.version_info < (3, 11):
        raise ConnectError("artzain connect needs Python 3.11 or later (it reads TOML)")
    for tool in ("systemctl", "openshell-gateway", "openshell"):
        if not host.which(tool):
            raise ConnectError(f"{tool} is not on PATH: install OpenShell's deb or rpm package")
    paths = layout(host)
    if not paths.gateway_unit.is_file():
        raise ConnectError(f"no {GATEWAY_UNIT} user unit: this is not a deb or rpm gateway "
                           "(Homebrew, snap and Compose come later)")
    if not paths.gateway_toml.is_file():
        raise ConnectError(f"{paths.gateway_toml} is missing: start the gateway once so it is written")
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
    """Write *path* whole, by a rename, keeping the mode an existing file had."""
    mode = path.stat().st_mode & 0o777 if path.exists() else (0o600 if private else 0o644)
    temporary = path.with_name(path.name + ".artzain-new")
    if private:
        private_dir(path.parent)
        write_private(temporary, data)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary.write_bytes(data)
    if hasattr(os, "chmod"):
        os.chmod(temporary, mode)
    os.replace(temporary, path)


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


def _restore(path: Path, backup: Path, before_sha: str, created: bool) -> str:
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
    stripped = strip_block(path.read_bytes())
    if stripped is None:
        return "no-block"
    saved = backup.read_bytes() if backup.is_file() else None
    if saved is not None and _sha(saved) == before_sha and stripped == strip_block(
            add_block(saved, "")):
        if created and not saved:
            path.unlink()
            return "removed"
        _replace(path, saved)
        return "restored"
    _replace(path, stripped)
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


def _jwt_settings(toml_text: str) -> Dict[str, str]:
    """The gateway's own ``gateway_jwt`` public key and id, when its
    ``gateway.toml`` names them, so the sidecar can check the gateway's
    signed calls."""
    import tomllib

    try:
        jwt = tomllib.loads(toml_text).get("openshell", {}).get("gateway", {}).get("gateway_jwt", {})
    except tomllib.TOMLDecodeError:
        return {}
    key, gateway = jwt.get("public_key_path"), jwt.get("gateway_id")
    if isinstance(key, str) and isinstance(gateway, str) and key and gateway and not (
            _UNSAFE.search(key) or _UNSAFE.search(gateway)):
        return {"OPENSHELL_JWT_PUBLIC_KEY": key, "OPENSHELL_JWT_GATEWAY_ID": gateway}
    return {}


def sidecar_environment(host: Host, paths: Layout, redeemed_gateway: str, credential: str,
                        config: ConnectConfig, *, registration_digest: str, port: int,
                        proxy: str, ca_bundle: str, jwt: Mapping[str, str]) -> str:
    """The sidecar service's ``EnvironmentFile``. It holds the credential."""
    values = {
        "COGNEXUS_API_KEY": credential,
        "ARTZAIN_DECISION_URL": config.decision_url,
        "OPENSHELL_GATEWAY_ID": redeemed_gateway,
        "OPENSHELL_SIDECAR_GRPC": f"unix://{paths.socket.as_posix()}",
        "OPENSHELL_SIDECAR_HOST": "127.0.0.1",
        "OPENSHELL_SIDECAR_PORT": str(port),
        "OPENSHELL_SIDECAR_DECIDE_TIMEOUT_MS": str(config.decide_timeout_ms),
        "OPENSHELL_SIDECAR_STATE": (paths.state_dir / "state.json").as_posix(),
        "OPENSHELL_SIDECAR_JOURNAL": (paths.state_dir / "journal.json").as_posix(),
        "OPENSHELL_SIDECAR_BASE_POLICY": (paths.state_dir / "base-policy.json").as_posix(),
        "OPENSHELL_REGISTRATION_DIGEST": registration_digest,
    }
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
        "Type=simple\n"
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


def _gateway_stays_up(host: Host) -> bool:
    """Active, and still active a few seconds later: a gateway that cannot
    reach its interceptor exits at start and is restarted every 5 s."""
    def active() -> bool:
        return _systemctl(host, "is-active", GATEWAY_UNIT, timeout=10).stdout.strip() == "active"

    if not _wait(host, 30, active):
        return False
    host.sleep(6)
    return active()


def _same_line(found: str, wanted: str) -> bool:
    a, b = _VERSION.fullmatch(found), _VERSION.fullmatch(wanted)
    return bool(a and b and a.group(1, 2) == b.group(1, 2))


def self_test(host: Host) -> str:
    """Ask the gateway for a write ArtzAIn denies. Returns the decision id.
    Raises :class:`ConnectError` when the write was not refused, or not by
    ArtzAIn, or the setting moved anyway."""
    tried = host.run("openshell", "settings", "set", "--global", "--key", SELF_TEST_KEY,
                     "--value", "auto", timeout=60)
    said = (tried.stdout or "") + "\n" + (tried.stderr or "")
    if tried.returncode == 0:
        # Governance is not in force. Put the setting back before saying so.
        host.run("openshell", "settings", "set", "--global", "--key", SELF_TEST_KEY,
                 "--value", "manual", timeout=60)
        raise ConnectError("the self-test write was ALLOWED: the gateway is not governed. "
                           "Run `artzain connect openshell status`, then `up` again")
    found = _DECISION_ID.search(said)
    if not found:
        raise ConnectError("the self-test write was refused, but not by an ArtzAIn decision: "
                           + (said.strip().splitlines() or [""])[-1][:300])
    now = host.run("openshell", "settings", "get", "--global", timeout=60)
    value = re.search(SELF_TEST_KEY + r"\W+(\w+)", now.stdout or "")
    if now.returncode != 0 or not value or value.group(1) != "manual":
        raise ConnectError("after the self-test the gateway does not show "
                           f"{SELF_TEST_KEY} as manual: check it with `openshell settings get --global`")
    return found.group(1)


def up(host: Host, *, token: str = "", digest: str = "", engine: str = DEFAULT_ENGINE,
       proxy: str = "", ca_bundle: str = "", port: int = DEFAULT_PORT,
       out: Callable[[str], None] = print) -> Dict[str, Any]:
    """Bind this host's gateway. Returns the record. Raises
    :class:`ConnectError` at the first step that cannot be done; what was
    done before it stays recorded."""
    shape = detect(host)
    paths = shape.paths
    if "/.cache/uv/" in host.executable.replace("\\", "/"):
        raise ConnectError("artzain is running from a temporary uv environment, which the "
                           "sidecar service cannot keep using: install it first, "
                           "`uv tool install 'artzain[openshell]'`, and run that artzain")
    if not (1 <= int(port) <= 65535):
        raise ConnectError("--port must be 1..65535")
    record = Record.load(paths.record)
    toml_text = paths.gateway_toml.read_bytes().decode("utf-8")
    if strip_block(toml_text.encode("utf-8")) is None:
        # Before the token is spent: a file the block cannot go into stops here.
        check_gateway_toml(paths, toml_text)

    # 1. The credential, once. It is saved before anything else can fail.
    if record.done("redeemed"):
        _say(out, f"gateway {record.data['gateway_id']}: already redeemed; using the saved credential")
        _saved(paths)
        config = parse_config(record.data.get("config"))
        gateway_id = record.data["gateway_id"]
    else:
        if not token:
            raise ConnectError("set ARTZAIN_ENROLL_TOKEN to the enroll token you were given")
        # What this host puts into the sidecar's files, written once with
        # stand-ins for what the engine will send: a value systemd cannot
        # carry stops here, while the token is still unspent.
        sidecar_unit(host, paths)
        sidecar_environment(host, paths, "gw_" + "0" * 26, CREDENTIAL_PREFIX + "0",
                            ConnectConfig("https://engine.invalid", "0.0.0"),
                            registration_digest="0" * 64, port=port, proxy=proxy,
                            ca_bundle=ca_bundle, jwt=_jwt_settings(toml_text))
        got = redeem(host, engine=engine, token=token, digest=digest, proxy=proxy,
                     ca_bundle=ca_bundle)
        config, gateway_id = got.config, got.gateway_id
        jwt = _jwt_settings(toml_text)
        text = registration.render(f"unix://{paths.socket.as_posix()}",
                                   timeout_ms=config.interceptor_timeout_ms)
        _replace(paths.sidecar_env, sidecar_environment(
            host, paths, gateway_id, got.credential, config,
            registration_digest=registration.digest(text), port=port, proxy=proxy,
            ca_bundle=ca_bundle, jwt=jwt).encode("utf-8"), private=True)
        record.mark("redeemed", gateway_id=gateway_id, config=got.raw_config,
                    engine=engine.rstrip("/"), port=int(port))
        _say(out, f"gateway {gateway_id}: credential saved to {paths.sidecar_env}")
        if not jwt:
            _say(out, "note: gateway.toml names no gateway_jwt key, so the sidecar will not "
                      "check that calls come from the gateway (manual chapter 17)")
    if not _same_line(shape.openshell_version, config.openshell_version):
        raise ConnectError(f"this gateway is OpenShell {shape.openshell_version}, and the "
                           f"configuration was approved for {config.openshell_version}: "
                           "install that release, then run this again (no new token needed)")

    # 2. Nothing governs the gateway yet: no automatic approvals meanwhile.
    if not record.done("approval-manual"):
        done = host.run("openshell", "settings", "set", "--global", "--key", SELF_TEST_KEY,
                        "--value", "manual", timeout=60)
        if done.returncode != 0:
            _say(out, f"note: could not set {SELF_TEST_KEY} to manual (is the gateway running?)")
        record.mark("approval-manual")

    # 3. The gateway's telemetry choice, in the file its unit reads.
    if not record.done("gateway-env"):
        before = paths.gateway_env.read_bytes() if paths.gateway_env.exists() else b""
        created = not paths.gateway_env.exists()
        if strip_block(before) is None:
            _replace(paths.env_backup, before, private=True)
            line = f"OPENSHELL_TELEMETRY_ENABLED={'true' if config.telemetry else 'false'}"
            _replace(paths.gateway_env, add_block(before, line), private=created)
        record.mark("gateway-env", env_sha256=_sha(before), env_created=created)

    # 4. The sidecar, as a service, up and answering.
    if not record.done("sidecar"):
        _replace(paths.sidecar_unit, sidecar_unit(host, paths).encode("utf-8"))
        private_dir(paths.state_dir)
        _check(_systemctl(host, "daemon-reload"), "systemctl --user daemon-reload")
        _check(_systemctl(host, "enable", "--now", SIDECAR_UNIT), f"starting {SIDECAR_UNIT}")
        record.mark("sidecar")
    if not _wait(host, 30, lambda: host.healthy(int(record.data.get("port", port)))):
        raise ConnectError(f"the sidecar did not answer within 30 s: see "
                           f"`journalctl --user -u {SIDECAR_UNIT}`")

    # 5. The registration, checked by the gateway's own preflight first.
    if not record.done("registration"):
        current = paths.gateway_toml.read_bytes()
        if strip_block(current) is None:
            text = registration_text(paths, config, current.decode("utf-8"))
            candidate = add_block(current, text)
            trial = paths.artzain_dir / "gateway.toml.candidate"
            _replace(trial, candidate, private=True)
            try:
                _check(host.run("openshell-gateway", "config", "preflight", "--path",
                                trial.as_posix(), timeout=60),
                       "openshell-gateway config preflight")
            finally:
                if trial.exists():
                    trial.unlink()
            _replace(paths.toml_backup, current, private=True)
            record.mark("toml-saved", toml_sha256=_sha(current))
            _replace(paths.gateway_toml, candidate)
        record.mark("registration")
        _replace(paths.dropin, gateway_dropin().encode("utf-8"))
        _check(_systemctl(host, "daemon-reload"), "systemctl --user daemon-reload")

    # 6. The gateway, restarted bound.
    if not record.done("gateway-restarted"):
        _check(_systemctl(host, "restart", GATEWAY_UNIT, timeout=120), f"restarting {GATEWAY_UNIT}")
        if not _gateway_stays_up(host):
            raise ConnectError(f"{GATEWAY_UNIT} did not stay up: see "
                               f"`journalctl --user -u {GATEWAY_UNIT}`. "
                               "`artzain connect openshell remove` puts everything back")
        record.mark("gateway-restarted")

    # 7. The self-test.
    decision = self_test(host)
    record.mark("self-test", self_test_decision_id=decision, connected=True)
    _say(out, f"gateway {gateway_id} is governed: the self-test write was refused by "
              f"ArtzAIn decision {decision}. Its heartbeat and inventory reach the "
              "dashboard within a minute.")
    return dict(record.data)


def _saved(paths: Layout) -> Dict[str, str]:
    """The sidecar's settings as ``up`` wrote them. Raises
    :class:`ConnectError` when there is no credential in them."""
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
    result: Dict[str, Any] = {}

    if paths.gateway_toml.exists():
        result["gateway.toml"] = _restore(paths.gateway_toml, paths.toml_backup,
                                          data.get("toml_sha256", ""), False)
    if paths.dropin.exists():
        paths.dropin.unlink()
        result["drop-in"] = "removed"
    _systemctl(host, "daemon-reload")
    if _systemctl(host, "is-active", GATEWAY_UNIT, timeout=10).stdout.strip() in (
            "active", "activating", "failed") and result.get("gateway.toml") in (
            "restored", "kept-edits"):
        _check(_systemctl(host, "restart", GATEWAY_UNIT, timeout=120), f"restarting {GATEWAY_UNIT}")
        if not _gateway_stays_up(host):
            raise ConnectError(f"{GATEWAY_UNIT} did not come back up unbound: see "
                               f"`journalctl --user -u {GATEWAY_UNIT}`")
        result["gateway"] = "restarted unbound"

    _systemctl(host, "disable", "--now", SIDECAR_UNIT)
    if paths.sidecar_unit.exists():
        paths.sidecar_unit.unlink()
        result["sidecar"] = "removed"
    _systemctl(host, "daemon-reload")

    if paths.gateway_env.exists():
        result["gateway.env"] = _restore(paths.gateway_env, paths.env_backup,
                                         data.get("env_sha256", ""), bool(data.get("env_created")))

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

    for path in (paths.sidecar_env, paths.toml_backup, paths.env_backup):
        if path.exists():
            path.unlink()
    if paths.state_dir.exists():
        shutil.rmtree(paths.state_dir)
    record.delete()
    _say(out, "removed: " + ", ".join(f"{k} {v}" for k, v in result.items()) if result
         else "nothing to remove")
    return result


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
    toml = paths.gateway_toml.read_bytes() if paths.gateway_toml.exists() else b""
    port = int(record.get("port") or DEFAULT_PORT)
    return {
        "gateway_id": record.get("gateway_id"),
        "steps": record.get("steps", []),
        "connected": bool(record.get("connected")),
        "self_test_decision_id": record.get("self_test_decision_id"),
        "credential_saved": paths.sidecar_env.exists(),
        "registration_in_gateway_toml": strip_block(toml) is not None,
        "drop_in": paths.dropin.exists(),
        "sidecar_unit": paths.sidecar_unit.exists(),
        "sidecar": _systemctl(host, "is-active", SIDECAR_UNIT, timeout=10).stdout.strip() or "unknown",
        "sidecar_answers": host.healthy(port),
        "gateway": _systemctl(host, "is-active", GATEWAY_UNIT, timeout=10).stdout.strip() or "unknown",
        "record_error": record.get("error"),
    }


__all__ = ["CONFIG_KIND", "CONFIG_VERSION", "ConnectConfig", "ConnectError", "Host", "Layout",
           "Record", "Redeemed", "Shape", "add_block", "config_digest", "detect", "layout",
           "parse_config", "redeem", "remove", "revoke", "self_test", "status", "strip_block",
           "up"]
